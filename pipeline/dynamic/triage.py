"""Triage des crashes via CASR / ASan."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from typing import Optional

from pipeline.models import Confidence, Finding, VulnClass

# Frame ASan/CASR « #N 0x... in <fonction> <fichier>:<ligne> » (hors libasan/libc).
_FRAME_RE = re.compile(r"#\d+\s+0x[0-9a-f]+\s+in\s+(\S+)\s+(\S+?):(\d+)")
# Phrase de type après « AddressSanitizer: » jusqu'à « on »/« at »/fin de ligne.
_TYPE_RE = re.compile(r"AddressSanitizer:\s+([a-z0-9 -]+?)(?:\s+on\b|\s+at\b|\s*$)", re.M)


def _class_from_text(text: str) -> VulnClass:
    t = text.lower()
    if "double-free" in t or "double free" in t:
        return VulnClass.DOUBLE_FREE
    if "use-after-free" in t:
        return VulnClass.USE_AFTER_FREE
    if "stack-buffer-overflow" in t:
        return VulnClass.STACK_BOF
    if "heap-buffer-overflow" in t or "global-buffer-overflow" in t:
        return VulnClass.HEAP_BOF
    if "stack-use-after-return" in t:
        return VulnClass.USE_AFTER_FREE
    # ASan « negative-size-param » : une taille a débordé en négatif -> integer overflow.
    if "negative-size-param" in t:
        return VulnClass.INTEGER_OVERFLOW
    return VulnClass.UNKNOWN


def _first_source_frame(lines) -> tuple[str, Optional[str], Optional[int]]:
    for frame in lines:
        if "libasan" in frame or "libc.so" in frame:
            continue
        m = _FRAME_RE.search(frame)
        if m:
            return m.group(1), m.group(2), int(m.group(3))
    return "?", None, None


def _casr_bin(name: str) -> Optional[str]:
    found = shutil.which(name)
    if found:
        return found
    candidate = os.path.expanduser(f"~/.cargo/bin/{name}")
    return candidate if os.path.exists(candidate) else None


def triage_with_casr(asan_bin: str, input_path: str, file_input: bool = False) -> Optional[dict]:
    casr = _casr_bin("casr-san")
    if casr is None:
        return None
    with tempfile.TemporaryDirectory() as tmp:
        report = os.path.join(tmp, "crash.casrep")
        if file_input:
            cmd = [casr, "-o", report, "--", asan_bin, input_path]
        else:
            cmd = [casr, "-o", report, "--stdin", input_path, "--", asan_bin]
        try:
            subprocess.run(cmd, capture_output=True, timeout=90)
            with open(report, encoding="utf-8", errors="replace") as f:
                data = json.load(f)
        except (subprocess.SubprocessError, OSError, json.JSONDecodeError):
            return None
    severity = data.get("CrashSeverity", {})
    short = severity.get("ShortDescription", "") or severity.get("Description", "")
    func, src, line = _first_source_frame(data.get("Stacktrace", []))
    return {
        "description": short,
        "exploitability": severity.get("Type", "UNKNOWN"),
        "function": func, "file": src, "line": line,
        "tool": "casr-san",
    }


def triage_with_asan(asan_bin: str, input_path: str, file_input: bool = False) -> Optional[dict]:
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:abort_on_error=0")
    try:
        if file_input:
            proc = subprocess.run([asan_bin, input_path], capture_output=True, timeout=30, env=env)
        else:
            with open(input_path, "rb") as fichier:
                donnees = fichier.read()
            proc = subprocess.run([asan_bin], input=donnees, capture_output=True, timeout=30, env=env)
    except (subprocess.SubprocessError, OSError):
        return None
    err = proc.stderr.decode("utf-8", "replace")
    crashed = ("AddressSanitizer" in err) or (proc.returncode != 0)
    if not crashed:
        return None
    m = _TYPE_RE.search(err)
    description = m.group(1).strip() if m else ("SEGV" if "SEGV" in err else "crash")
    func, src, line = _first_source_frame(err.splitlines())
    return {"description": description, "exploitability": "UNKNOWN",
            "function": func, "file": src, "line": line, "tool": "asan"}


def triage_input(asan_bin: str, input_bytes: bytes, file_input: bool = False) -> Optional[Finding]:
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(input_bytes)
        input_path = tf.name
    try:
        result = (triage_with_casr(asan_bin, input_path, file_input)
                  or triage_with_asan(asan_bin, input_path, file_input))
    finally:
        os.unlink(input_path)
    if result is None:
        return None

    location = f"{result['file']}:{result['line']}" if result.get("line") else "?"
    return Finding(
        vuln_class=_class_from_text(result["description"]),
        function=result["function"],
        confidence=Confidence.CONFIRMED,
        source=f"dynamic:{result['tool']}",
        description=f"Crash reproductible ({result['description'] or 'SIGSEGV'}) à {location}.",
        remediation="corriger la vulnérabilité mémoire à l'origine du crash",
        evidence={
            "bug": result["description"],
            "exploitability": result["exploitability"],
            "crash_location": location,
            "tool": result["tool"],
        },
    )


def triage_crashes(asan_bin: str, crash_files: list[str], file_input: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for path in crash_files:
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            continue
        finding = triage_input(asan_bin, data, file_input)
        if finding is None:
            continue
        key = (finding.vuln_class.value, finding.function)
        if key in seen:
            continue
        seen.add(key)
        findings.append(finding)
    return findings
