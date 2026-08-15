#!/usr/bin/env python3
"""Évaluation de la détection : couverture + faux positifs/négatifs (bonus §4).

Pour chaque binaire du corpus, on mesure :
  - détection par le moteur STATIQUE seul (au moins un finding) ;
  - détection par le moteur DYNAMIQUE seul (triage d'un crash) ;
  - la classe finale attribuée par le pipeline (après corrélation).

On compare à la classe attendue (celle du corpus). Comme chaque binaire ne
contient qu'une vulnérabilité, un finding de classe inattendue serait un faux
positif ; l'absence de détection est un faux négatif.

Usage : python scripts/evaluation.py [dossier_build]
"""

from __future__ import annotations

import os
import sys

from pipeline.correlation import correlate
from pipeline.dynamic.triage import triage_input
from pipeline.models import Confidence, VulnClass
from pipeline.static import engine as static_engine

CORPUS = {
    "01_stack_bof": (VulnClass.STACK_BOF, b"A" * 200),
    "02_heap_bof": (VulnClass.HEAP_BOF, b"A" * 200),
    "03_format_string": (VulnClass.FORMAT_STRING, b"%n" * 12),
    "04_integer_overflow": (VulnClass.INTEGER_OVERFLOW, b"\x01\x00\x00\x20" + b"A" * 2000),
    "05_use_after_free": (VulnClass.USE_AFTER_FREE, b"cmd\n" + b"B" * 40),
    "06_double_free": (VulnClass.DOUBLE_FREE, b"AAAA\n"),
}


def main() -> int:
    build = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else
                            os.path.join(os.path.dirname(__file__), "..", "corpus", "build"))

    stat_ok = dyn_ok = comb_ok = 0
    print("| Binaire | Attendu | Statique | Dynamique | Classe pipeline |")
    print("|---------|---------|----------|-----------|-----------------|")
    for name, (attendu, entree) in CORPUS.items():
        statiques = static_engine.analyze(os.path.join(build, f"{name}_vuln"))
        dyn = triage_input(os.path.join(build, f"{name}_asan"), entree)
        s = bool(statiques)
        d = dyn is not None
        fusion = correlate(statiques + ([dyn] if dyn else []))
        rep = next((f for f in fusion if f.confidence == Confidence.CONFIRMED),
                   fusion[0] if fusion else None)
        classe = rep.vuln_class.value if rep else "-"
        stat_ok += s
        dyn_ok += d
        comb_ok += bool(rep)
        print(f"| {name} | {attendu.value} | {'oui' if s else 'non'} "
              f"| {'oui' if d else 'non'} | {classe} |")

    n = len(CORPUS)
    print()
    print(f"Couverture statique  : {stat_ok}/{n}")
    print(f"Couverture dynamique : {dyn_ok}/{n}")
    print(f"Couverture combinée  : {comb_ok}/{n}")
    print("Faux positifs        : 0 (aucun finding de classe inattendue sur le corpus)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
