"""Tests de la génération des rapports (JSON / HTML / Markdown)."""

import json
import os

from pipeline import report as report_mod
from pipeline.models import (Confidence, ELFInfo, Finding, Severity, VulnClass)


def _exemple():
    elf = ELFInfo(
        path="/bin/exemple", arch="x64", bits=64, is_pie=False, entrypoint=0x401000,
        protections={"nx": False, "canary": False, "pie": False, "relro": "none", "fortify": False},
        imports=["strcpy", "fgets"], functions={"main": 0x401000, "vuln": 0x401150},
        has_symbols=True,
    )
    finding = Finding(
        vuln_class=VulnClass.STACK_BOF, function="vuln", static_offset=0x401178,
        severity=Severity.CRITICAL, score=90.0, confidence=Confidence.CONFIRMED,
        source="static:taint+dynamic:casr-san",
        description="Débordement de pile confirmé.",
        remediation="utiliser fgets borné.",
        evidence={"exploitability": "EXPLOITABLE", "bug": "stack-buffer-overflow"},
    )
    return report_mod.build_report("/bin/exemple", elf, [finding])


def test_statistiques():
    rep = _exemple()
    assert rep.stats["total"] == 1
    assert rep.stats["par_severite"]["critical"] == 1
    assert rep.stats["score_max"] == 90.0


def test_ecriture_des_trois_formats(tmp_path):
    paths = report_mod.write_all(_exemple(), str(tmp_path))
    for genre in ("json", "html", "md"):
        assert os.path.exists(paths[genre])

    data = json.load(open(paths["json"], encoding="utf-8"))
    assert data["findings"][0]["vuln_class"] == "stack_buffer_overflow"
    assert data["findings"][0]["severity"] == "critical"

    html = open(paths["html"], encoding="utf-8").read()
    assert "CRITICAL" in html and "stack_buffer_overflow" in html

    md = open(paths["md"], encoding="utf-8").read()
    assert "CRITICAL" in md and "vuln" in md
