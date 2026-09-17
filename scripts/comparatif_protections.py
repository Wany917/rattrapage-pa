#!/usr/bin/env python3
"""Tableau comparatif _vuln vs _prot : effet des mitigations sur le score."""

from __future__ import annotations

import os
import sys

from pipeline.correlation import correlate
from pipeline.dynamic.triage import triage_input
from pipeline.ingestion import ingest
from pipeline.models import Confidence, Finding
from pipeline.scoring import score_all
from pipeline.static import engine as static_engine

CRASHES = {
    "01_stack_bof": b"A" * 200,
    "02_heap_bof": b"A" * 200,
    "03_format_string": b"%n" * 12,
    "04_integer_overflow": b"\x01\x00\x00\x20" + b"A" * 2000,
    "05_use_after_free": b"cmd\n" + b"B" * 40,
    "06_double_free": b"AAAA\n",
}


def main() -> int:
    build = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(__file__), "..", "corpus", "build")
    build = os.path.abspath(build)

    print("| Binaire | Classe | Exploitabilité | Sévérité `_vuln` | Sévérité `_prot` |")
    print("|---------|--------|----------------|------------------|------------------|")
    for name, entree in CRASHES.items():
        statiques = static_engine.analyze(os.path.join(build, f"{name}_vuln"))
        dyn = triage_input(os.path.join(build, f"{name}_asan"), entree)
        fusionnes = correlate(statiques + ([dyn] if dyn else []))
        rep = next((f for f in fusionnes if f.confidence == Confidence.CONFIRMED),
                   fusionnes[0] if fusionnes else None)
        if rep is None:
            print(f"| {name} | (pas de crash) | | | |")
            continue

        cellules = []
        for profil in ("vuln", "prot"):
            info = ingest(os.path.join(build, f"{name}_{profil}"), run_checksec=False)
            finding = Finding(rep.vuln_class, function=rep.function,
                              confidence=Confidence.CONFIRMED,
                              evidence={"exploitability": rep.evidence.get("exploitability")})
            score_all([finding], info.protections)
            cellules.append(f"{finding.severity.value.upper()} {finding.score}")
        print(f"| {name} | {rep.vuln_class.value} | {rep.evidence.get('exploitability')} "
              f"| {cellules[0]} | {cellules[1]} |")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
