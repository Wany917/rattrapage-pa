"""Compilation des cibles instrumentées (fuzzing AFL++ et triage ASan)."""

from __future__ import annotations

import os
import subprocess
from typing import Optional

from pipeline.dynamic.afl_env import afl_dir, afl_tool


def build_fuzz_target(source: str, out: str) -> Optional[str]:
    afl_cc = afl_tool("afl-cc")
    directory = afl_dir()
    if afl_cc is None or directory is None:
        return None
    env = dict(os.environ, AFL_PATH=directory, AFL_QUIET="1", AFL_USE_ASAN="1")
    try:
        proc = subprocess.run(
            [afl_cc, "-O2", "-g", "-fno-stack-protector", source, "-o", out, "-lm"],
            capture_output=True, timeout=180, env=env,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    return out if proc.returncode == 0 and os.path.exists(out) else None


def build_asan(source: str, out: str, cc: str = "cc") -> Optional[str]:
    try:
        proc = subprocess.run(
            [cc, "-O1", "-g", "-fsanitize=address", "-fno-omit-frame-pointer",
             "-fno-stack-protector", source, "-o", out, "-lm"],
            capture_output=True, timeout=180,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    return out if proc.returncode == 0 and os.path.exists(out) else None
