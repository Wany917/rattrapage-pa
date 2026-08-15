"""Pilote du moteur statique : agrège les analyses statiques en une liste de findings.

Phase 3 : fonctions dangereuses + taille de buffer + taint tracking, avec une
déduplication intra-statique. Si plusieurs analyses pointent le même site
(fonction, offset, classe), on garde une seule entrée à la confiance la plus
haute et on combine leurs sources. Exemple : dangerous_funcs signale un strcpy
(POSSIBLE) et le taint confirme que la donnée vient de fgets (PROBABLE) -> une
seule entrée PROBABLE, source « dangerous_funcs+taint ».

La corrélation complète (Phase 5) étendra cette logique aux findings dynamiques.
"""

from __future__ import annotations

from pipeline.models import Confidence, Finding
from pipeline.static import buffer_sizing, dangerous_funcs, taint

_RANG = {Confidence.POSSIBLE: 0, Confidence.PROBABLE: 1, Confidence.CONFIRMED: 2}


def analyze(path: str) -> list[Finding]:
    """Lance toutes les analyses statiques sur `path` et déduplique les findings."""
    findings: list[Finding] = []
    findings.extend(dangerous_funcs.scan(path))
    findings.extend(buffer_sizing.scan(path))
    findings.extend(taint.scan(path))
    return _dedupe(findings)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Fusionne les findings du même site en gardant la confiance la plus haute."""
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
