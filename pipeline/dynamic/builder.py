"""Compilation des cibles instrumentées du moteur dynamique.

  - cible de fuzzing : afl-cc + AddressSanitizer (AFL_USE_ASAN=1). Instrumentée
    pour la couverture (guidage d'AFL) ET détectant précisément les corruptions
    mémoire (ASan) pendant le fuzzing ;
  - cible de triage  : ASan simple (gcc -fsanitize=address), pour rejouer un
    crash et obtenir un rapport ASan propre (analysé par CASR).

Nécessite les sources. C'est le point « binaire vs sources » du sujet : le
moteur statique reste black-box (binaire seul), mais le moteur dynamique
recompile le corpus, ce qui est légitime puisque l'étudiant en écrit les sources.
Sans sources, le moteur dynamique est simplement sauté (le fuzzing black-box en
mode QEMU est un bonus séparé).
"""

from __future__ import annotations

import os
import subprocess
from typing import Optional

from pipeline.dynamic.afl_env import afl_dir, afl_tool


def build_fuzz_target(source: str, out: str) -> Optional[str]:
    """Compile `source` en cible AFL++ instrumentée + ASan. Renvoie `out` ou None."""
    afl_cc = afl_tool("afl-cc")
    directory = afl_dir()
    if afl_cc is None or directory is None:
        return None
    env = dict(os.environ, AFL_PATH=directory, AFL_QUIET="1", AFL_USE_ASAN="1")
    try:
        # -O2 : AFL recommande d'optimiser la cible (exécutions bien plus rapides
        # que -O0, crucial pour fuzzer du vrai code). -lm : beaucoup de programmes
        # réels (parseurs d'images...) utilisent libm.
        proc = subprocess.run(
            [afl_cc, "-O2", "-g", "-fno-stack-protector", source, "-o", out, "-lm"],
            capture_output=True, timeout=180, env=env,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    return out if proc.returncode == 0 and os.path.exists(out) else None


def build_asan(source: str, out: str, cc: str = "cc") -> Optional[str]:
    """Compile `source` en binaire ASan simple (pour le triage). Renvoie `out` ou None."""
    try:
        proc = subprocess.run(
            [cc, "-O1", "-g", "-fsanitize=address", "-fno-omit-frame-pointer",
             "-fno-stack-protector", source, "-o", out, "-lm"],
            capture_output=True, timeout=180,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    return out if proc.returncode == 0 and os.path.exists(out) else None
