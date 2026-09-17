"""Build instrumenté, fuzzing AFL++ et triage des crashes."""

from __future__ import annotations

import os
import tempfile
from typing import Optional

from pipeline.dynamic import builder, fuzzer, triage
from pipeline.models import Finding


def analyze_source(source: str, workdir: Optional[str] = None, fuzz_timeout: int = 30,
                   seeds: Optional[str] = None, file_input: bool = False) -> list[Finding]:
    tmp = None
    if workdir is None:
        tmp = tempfile.TemporaryDirectory()
        workdir = tmp.name
    os.makedirs(workdir, exist_ok=True)
    try:
        base = os.path.splitext(os.path.basename(source))[0]
        fuzz_bin = os.path.join(workdir, f"{base}_afl")
        asan_bin = os.path.join(workdir, f"{base}_asan")

        if builder.build_fuzz_target(source, fuzz_bin) is None:
            return []
        if builder.build_asan(source, asan_bin) is None:
            asan_bin = fuzz_bin      # repli : la cible AFL est déjà instrumentée ASan

        crashes = fuzzer.fuzz(fuzz_bin, workdir, seeds=seeds,
                              timeout_s=fuzz_timeout, file_input=file_input)
        return triage.triage_crashes(asan_bin, crashes, file_input=file_input)
    finally:
        if tmp is not None:
            tmp.cleanup()
