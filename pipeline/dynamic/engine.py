"""Pilote du moteur dynamique : build instrumenté -> fuzzing -> triage.

Enchaîne les trois briques sur une source C :
  1. compile une cible de fuzzing (AFL + ASan) et une cible de triage (ASan) ;
  2. fuzze la cible pour découvrir des entrées qui font crasher ;
  3. triage chaque crash (type + exploitabilité) -> findings CONFIRMED.

`file_input` : les programmes qui lisent un fichier (et non stdin) sont fuzzés
en mode fichier (AFL `@@`) et triagés avec l'entrée passée en argument.

Renvoie une liste vide (sans échouer) si AFL++ ou la compilation manquent : le
pipeline reste utilisable en mode statique seul.
"""

from __future__ import annotations

import os
import tempfile
from typing import Optional

from pipeline.dynamic import builder, fuzzer, triage
from pipeline.models import Finding


def analyze_source(source: str, workdir: Optional[str] = None, fuzz_timeout: int = 30,
                   seeds: Optional[str] = None, file_input: bool = False) -> list[Finding]:
    """Construit, fuzze puis triage `source`. Renvoie des findings CONFIRMED."""
    tmp = None
    if workdir is None:
        tmp = tempfile.TemporaryDirectory()
        workdir = tmp.name
    os.makedirs(workdir, exist_ok=True)   # robustesse : créer le dossier de travail s'il manque
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
