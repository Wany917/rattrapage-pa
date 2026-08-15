"""Rapport JSON (lisible par une machine), au schéma stable.

Sérialise l'objet `Report` (cible + ELFInfo + findings + stats) via son
`to_dict()`, qui convertit proprement les enums en valeurs.
"""

from __future__ import annotations

import json

from pipeline.models import Report


def write_json(report: Report, path: str) -> str:
    """Écrit le rapport JSON dans `path` et renvoie ce chemin."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)
        f.write("\n")
    return path
