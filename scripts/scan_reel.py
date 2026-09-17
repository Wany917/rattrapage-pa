#!/usr/bin/env python3
"""Scan statique argus sur des binaires système réels."""

from __future__ import annotations

import sys
import time
from collections import Counter

from pipeline.ingestion import ingest
from pipeline.scoring import score_all
from pipeline.static import engine


def main() -> int:
    for path in sys.argv[1:]:
        try:
            t0 = time.perf_counter()
            info = ingest(path, run_checksec=False)
            findings = engine.analyze(path)
            score_all(findings, info.protections)
            dt = (time.perf_counter() - t0) * 1000
        except Exception as exc:  # noqa: BLE001 - on veut voir toute robustesse en échec
            print(f"### {path}  ECHEC: {type(exc).__name__}: {exc}")
            continue

        prot = {k: v for k, v in info.protections.items() if k != "checksec"}
        par_classe = Counter(f.vuln_class.value for f in findings)
        print(f"### {path}  ({dt:.0f} ms)")
        print(f"  arch={info.arch} pie={info.is_pie} symbols={info.has_symbols} "
              f"fonctions={len(info.functions)} imports={len(info.imports)}")
        print(f"  protections={prot}")
        print(f"  findings={len(findings)} {dict(par_classe)}")
        for f in findings[:6]:
            off = hex(f.static_offset) if f.static_offset is not None else "?"
            print(f"   [{f.severity.value}] {f.vuln_class.value} {f.function} @ {off}"
                  f" :: {f.description[:64]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
