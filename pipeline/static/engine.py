"""Agrégation et déduplication des analyses statiques."""

from __future__ import annotations

from pipeline.models import Confidence, Finding
from pipeline.static import buffer_sizing, dangerous_funcs, taint

_RANG = {Confidence.POSSIBLE: 0, Confidence.PROBABLE: 1, Confidence.CONFIRMED: 2}


def analyze(path: str) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(dangerous_funcs.scan(path))
    findings.extend(buffer_sizing.scan(path))
    findings.extend(taint.scan(path))
    return _dedupe(findings)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    fusionnes: dict[tuple, Finding] = {}
    ordre: list[tuple] = []
    for finding in findings:
        cle = (finding.function, finding.static_offset, finding.vuln_class.value)
        if cle not in fusionnes:
            fusionnes[cle] = finding
            ordre.append(cle)
            continue
        garde = fusionnes[cle]
        if _RANG[finding.confidence] > _RANG[garde.confidence]:
            finding.source = f"{garde.source}+{finding.source}"
            finding.evidence = {**garde.evidence, **finding.evidence}
            fusionnes[cle] = finding
        else:
            garde.source = f"{garde.source}+{finding.source}"
            garde.evidence = {**finding.evidence, **garde.evidence}
    return [fusionnes[cle] for cle in ordre]
