"""Pilotage d'AFL++ : fuzzing coverage-guided et collecte des crashes.

Lance afl-fuzz sur une cible instrumentée, entrée fournie sur stdin, pour une
durée bornée (`-V`). Par défaut on s'arrête au premier crash
(`AFL_BENCH_UNTIL_CRASH`) pour une démonstration rapide ; on peut le désactiver
pour explorer plus longtemps.

Variables d'environnement utilisées (pour éviter les blocages classiques d'AFL) :
  - AFL_SKIP_CPUFREQ, AFL_NO_AFFINITY : pas de réglage CPU requis ;
  - AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES : tolère un core_pattern « piped »
    (sinon AFL refuse de démarrer sans droits root) ;
  - ASAN_OPTIONS=abort_on_error=1 : une erreur ASan devient un crash visible.
"""

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
    """Fuzze `target` pendant au plus `timeout_s` s. Renvoie les fichiers de crash.

    file_input=False : entrée sur stdin ; True : en argument fichier (AFL remplace
    `@@` par le chemin du cas de test), pour les programmes qui lisent un fichier.
    """
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
        cmd.append("@@")   # AFL remplace @@ par le chemin du fichier de test
    try:
        subprocess.run(cmd, capture_output=True, timeout=timeout_s + 60, env=env)
    except subprocess.TimeoutExpired:
        pass  # -V borne déjà la durée ; le wrapper est une sécurité
    except (subprocess.SubprocessError, OSError):
        return []

    # Les crashes sont dans <out>/default/crashes/id:* (on ignore README.txt).
    return sorted(glob.glob(os.path.join(afl_out, "default", "crashes", "id:*")))


def _prepare_seeds(in_dir: str, seeds: Optional[str]) -> None:
    """Remplit `in_dir` avec les seeds fournis, ou une graine par défaut."""
    if seeds and os.path.isdir(seeds):
        for name in os.listdir(seeds):
            path = os.path.join(seeds, name)
            if os.path.isfile(path):
                shutil.copy(path, in_dir)
    if not os.listdir(in_dir):
        with open(os.path.join(in_dir, "seed"), "wb") as f:
            f.write(b"hello\n")
