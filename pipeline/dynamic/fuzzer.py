"""Pilotage d'AFL++ et collecte des crashes."""

from __future__ import annotations

import glob
import os
import shutil
import subprocess
from typing import Optional

from pipeline.dynamic.afl_env import afl_dir, afl_tool


def fuzz(target: str, work_dir: str, seeds: Optional[str] = None,
         timeout_s: int = 30, stop_on_crash: bool = True,
         file_input: bool = False) -> list[str]:
    afl_fuzz = afl_tool("afl-fuzz")
    directory = afl_dir()
    if afl_fuzz is None or directory is None:
        return []

    in_dir = os.path.join(work_dir, "in")
    afl_out = os.path.join(work_dir, "afl")
    shutil.rmtree(afl_out, ignore_errors=True)
    os.makedirs(in_dir, exist_ok=True)

    _prepare_seeds(in_dir, seeds)

    env = dict(
        os.environ,
        AFL_PATH=directory,
        AFL_SKIP_CPUFREQ="1",
        AFL_NO_AFFINITY="1",
        AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES="1",
        AFL_QUIET="1",
        ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:symbolize=0",
    )
    if stop_on_crash:
        env["AFL_BENCH_UNTIL_CRASH"] = "1"

    cmd = [afl_fuzz, "-i", in_dir, "-o", afl_out, "-m", "none",
           "-V", str(timeout_s), "--", target]
    if file_input:
        cmd.append("@@")
    try:
        subprocess.run(cmd, capture_output=True, timeout=timeout_s + 60, env=env)
    except subprocess.TimeoutExpired:
        pass
    except (subprocess.SubprocessError, OSError):
        return []

    return sorted(glob.glob(os.path.join(afl_out, "default", "crashes", "id:*")))


def _prepare_seeds(in_dir: str, seeds: Optional[str]) -> None:
    if seeds and os.path.isdir(seeds):
        for name in os.listdir(seeds):
            path = os.path.join(seeds, name)
            if os.path.isfile(path):
                shutil.copy(path, in_dir)
    if not os.listdir(in_dir):
        with open(os.path.join(in_dir, "seed"), "wb") as f:
            f.write(b"hello\n")
