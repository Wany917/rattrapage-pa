"""Génération des rapports : JSON (machine) et HTML/Markdown (humain).

`build_report` assemble un objet `Report` (cible + ELFInfo + findings + stats) ;
`write_all` produit les trois formats dans un dossier de sortie.
"""

from __future__ import annotations

import os
from collections import Counter
from typing import Optional

from pipeline.models import ELFInfo, Finding, Report
from pipeline.report import html_report, json_report, markdown_report


def build_report(target: str, elf: Optional[ELFInfo], findings: list[Finding]) -> Report:
    """Assemble un `Report` complet avec ses statistiques."""
    return Report(target=target, elf=elf, findings=findings, stats=_stats(findings))


def _stats(findings: list[Finding]) -> dict:
    par_severite = Counter(f.severity.value for f in findings)
    par_confiance = Counter(f.confidence.value for f in findings)
    # Ordonner les sévérités de la plus grave à la moins grave.
    ordre = ["critical", "high", "medium", "low", "info"]
    return {
        "total": len(findings),
        "par_severite": {s: par_severite[s] for s in ordre if par_severite[s]},
        "par_confiance": dict(par_confiance),
        "score_max": max((f.score for f in findings), default=0.0),
    }


def write_all(report: Report, out_dir: str) -> dict[str, str]:
    """Écrit les rapports JSON, HTML et Markdown dans `out_dir`. Renvoie leurs chemins."""
    os.makedirs(out_dir, exist_ok=True)
    base = os.path.splitext(os.path.basename(report.target))[0] or "rapport"
    return {
        "json": json_report.write_json(report, os.path.join(out_dir, f"{base}.json")),
        "html": html_report.write_html(report, os.path.join(out_dir, f"{base}.html")),
        "md": markdown_report.write_md(report, os.path.join(out_dir, f"{base}.md")),
    }
