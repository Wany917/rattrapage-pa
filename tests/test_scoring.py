"""Tests du scoring (règles -> niveau + score)."""

from pipeline.models import Confidence, Finding, Severity, VulnClass
from pipeline.scoring import score_finding

PROT_OFF = {"nx": False, "canary": False, "pie": False, "relro": "none", "fortify": False}
PROT_ON = {"nx": True, "canary": True, "pie": True, "relro": "full", "fortify": True}


def _stack_bof():
    return Finding(VulnClass.STACK_BOF, function="vuln", confidence=Confidence.CONFIRMED,
                   evidence={"exploitability": "EXPLOITABLE"})


def test_stack_bof_vuln_est_critique():
    f = _stack_bof()
    score_finding(f, PROT_OFF)
    assert f.severity == Severity.CRITICAL
    assert f.score >= 85


def test_protections_font_baisser_le_score():
    off, on = _stack_bof(), _stack_bof()
    score_finding(off, PROT_OFF)
    score_finding(on, PROT_ON)
    assert on.score < off.score              # les mitigations réduisent l'exploitabilité
    assert on.severity != Severity.CRITICAL


def test_exploitabilite_influe():
    exploitable = _stack_bof()
    non_exploitable = Finding(VulnClass.STACK_BOF, function="vuln",
                              confidence=Confidence.CONFIRMED,
                              evidence={"exploitability": "NOT_EXPLOITABLE"})
    score_finding(exploitable, PROT_OFF)
    score_finding(non_exploitable, PROT_OFF)
    assert exploitable.score > non_exploitable.score


def test_contexte_protections_rempli():
    f = Finding(VulnClass.HEAP_BOF, function="main", confidence=Confidence.CONFIRMED,
                evidence={"exploitability": "EXPLOITABLE"})
    score_finding(f, PROT_ON)
    assert "nx" in f.protections_context
    assert any(p.startswith("relro") for p in f.protections_context)
