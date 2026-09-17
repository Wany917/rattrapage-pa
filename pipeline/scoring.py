"""Scoring : score = impact × confiance × exploitabilité × mitigations."""

from __future__ import annotations

from pipeline.models import Confidence, Finding, Severity, VulnClass

_IMPACT = {
    VulnClass.STACK_BOF: 90,
    VulnClass.FORMAT_STRING: 85,
    VulnClass.HEAP_BOF: 80,
    VulnClass.USE_AFTER_FREE: 80,
    VulnClass.DOUBLE_FREE: 70,
    VulnClass.INTEGER_OVERFLOW: 60,
    VulnClass.UNKNOWN: 40,
}

_CONFIANCE = {Confidence.POSSIBLE: 0.6, Confidence.PROBABLE: 0.8, Confidence.CONFIRMED: 1.0}

_EXPLOITABILITE = {
    "EXPLOITABLE": 1.0,
    "PROBABLY_EXPLOITABLE": 0.85,
    "NOT_EXPLOITABLE": 0.6,
    "UNKNOWN": 0.8,
}

_MITIGATIONS = {
    VulnClass.STACK_BOF: {"canary": 0.35, "fortify": 0.25, "pie": 0.10, "nx": 0.10},
    VulnClass.FORMAT_STRING: {"fortify": 0.40, "relro": 0.15, "pie": 0.10},
    VulnClass.HEAP_BOF: {"nx": 0.10, "fortify": 0.10},
    VulnClass.USE_AFTER_FREE: {"nx": 0.10, "pie": 0.10},
    VulnClass.DOUBLE_FREE: {"nx": 0.05},
    VulnClass.INTEGER_OVERFLOW: {"canary": 0.15, "fortify": 0.15},
    VulnClass.UNKNOWN: {},
}


def _protection_active(protections: dict, name: str) -> bool:
    if name == "relro":
        return protections.get("relro", "none") != "none"
    return bool(protections.get(name))


def _mitigation_factor(vuln_class: VulnClass, protections: dict) -> float:
    reduction = sum(
        poids for prot, poids in _MITIGATIONS.get(vuln_class, {}).items()
        if _protection_active(protections, prot)
    )
    return max(0.3, 1.0 - reduction)


def _niveau(score: float) -> Severity:
    if score >= 85:
        return Severity.CRITICAL
    if score >= 65:
        return Severity.HIGH
    if score >= 40:
        return Severity.MEDIUM
    if score >= 20:
        return Severity.LOW
    return Severity.INFO


def score_finding(finding: Finding, protections: dict) -> None:
    impact = _IMPACT.get(finding.vuln_class, 40)
    confiance = _CONFIANCE.get(finding.confidence, 0.6)
    exploitabilite = _EXPLOITABILITE.get(finding.evidence.get("exploitability", "UNKNOWN"), 0.8)
    mitigation = _mitigation_factor(finding.vuln_class, protections)

    score = impact * confiance * exploitabilite * mitigation
    finding.score = round(min(100.0, max(0.0, score)), 1)
    finding.severity = _niveau(finding.score)

    actives = [p for p in ("nx", "canary", "pie", "fortify") if _protection_active(protections, p)]
    if _protection_active(protections, "relro"):
        actives.append("relro:" + protections.get("relro", "none"))
    finding.protections_context = actives


def score_all(findings: list[Finding], protections: dict) -> list[Finding]:
    for finding in findings:
        score_finding(finding, protections)
    findings.sort(key=lambda f: f.score, reverse=True)
    return findings
