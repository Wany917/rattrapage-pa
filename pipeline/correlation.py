"""Corrélation : fusion des findings statiques et dynamiques.

Un même défaut est souvent vu par plusieurs analyses (ex : buffer_sizing en
PROBABLE et le crash CASR en CONFIRMED). On les fusionne par fonction, en
réconciliant les classes : deux findings d'une même fonction fusionnent si leur
classe est identique, ou si l'un est UNKNOWN. Ce dernier cas est typique du
format string, que le dynamique voit comme un simple SEGV non typé alors que le
statique lui donne sa classe.

Le finding fusionné conserve la confiance la plus haute, l'offset statique connu,
l'exploitabilité dynamique, et combine sources et preuves.
"""

from __future__ import annotations

from pipeline.models import Confidence, Finding, VulnClass

_RANG = {Confidence.POSSIBLE: 0, Confidence.PROBABLE: 1, Confidence.CONFIRMED: 2}


def _compatibles(a: VulnClass, b: VulnClass) -> bool:
    """Deux classes fusionnables : identiques, ou l'une non typée (UNKNOWN)."""
    return a == b or a == VulnClass.UNKNOWN or b == VulnClass.UNKNOWN


def correlate(findings: list[Finding]) -> list[Finding]:
    """Fusionne les findings d'une même vulnérabilité. Renvoie la liste réduite."""
    groupes: list[Finding] = []
    for finding in findings:
        cible = next(
            (g for g in groupes
             if g.function == finding.function and _compatibles(g.vuln_class, finding.vuln_class)),
            None,
        )
        if cible is None:
            groupes.append(_copie(finding))
        else:
            _fusionner(cible, finding)
    return groupes


def _copie(f: Finding) -> Finding:
    return Finding(
        vuln_class=f.vuln_class, function=f.function,
        static_offset=f.static_offset, exploit_offset=f.exploit_offset,
        severity=f.severity, score=f.score, confidence=f.confidence,
        source=f.source, description=f.description, remediation=f.remediation,
        evidence=dict(f.evidence), protections_context=list(f.protections_context),
    )


def _fusionner(base: Finding, autre: Finding) -> None:
    # Classe : préférer une classe spécifique à UNKNOWN.
    if base.vuln_class == VulnClass.UNKNOWN and autre.vuln_class != VulnClass.UNKNOWN:
        base.vuln_class = autre.vuln_class
    # Offsets : récupérer ceux qui sont connus.
    if base.static_offset is None:
        base.static_offset = autre.static_offset
    if base.exploit_offset is None:
        base.exploit_offset = autre.exploit_offset
    # Preuves et sources combinées.
    base.evidence = {**base.evidence, **autre.evidence}
    base.source = "+".join(sorted(set(base.source.split("+")) | set(autre.source.split("+"))))
    # Confiance : la plus forte l'emporte (et impose sa description).
    if _RANG[autre.confidence] > _RANG[base.confidence]:
        base.confidence = autre.confidence
        base.description = autre.description
        base.remediation = autre.remediation
