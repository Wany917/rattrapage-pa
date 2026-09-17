"""Rapport JSON."""

from __future__ import annotations

import json

from pipeline.models import Report


def write_json(report: Report, path: str) -> str:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)
        f.write("\n")
    return path
