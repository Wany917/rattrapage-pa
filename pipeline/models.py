"""Structures de données partagées par tout le pipeline.

Ce module définit le « contrat » entre les étapes : chaque moteur (statique,
dynamique) produit des `Finding`, la corrélation les fusionne, le scoring les
note, et le reporting les sérialise. Centraliser ces types au même endroit
évite les incohérences entre modules et rend chaque étape testable isolément.

Choix de conception :
  - Des `Enum` (et non des chaînes libres) pour les valeurs fermées (classe de
    vuln, sévérité, confiance) : on interdit les fautes de frappe et on obtient
    une liste de valeurs auto-documentée, défendable à l'oral.
  - Des `dataclass` pour la lisibilité et la sérialisation quasi gratuite.
  - Une conversion JSON explicite (`_to_jsonable`) pour garder la main sur le
    format de sortie machine, indépendamment des détails d'implémentation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Optional


class VulnClass(str, Enum):
    """Classe de vulnérabilité (les six imposées par le sujet, plus `UNKNOWN`)."""

    STACK_BOF = "stack_buffer_overflow"
    HEAP_BOF = "heap_buffer_overflow"
    FORMAT_STRING = "format_string"
    INTEGER_OVERFLOW = "integer_overflow"
    USE_AFTER_FREE = "use_after_free"
    DOUBLE_FREE = "double_free"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    """Niveau de sévérité qualitatif. La règle de calcul vit dans `scoring.py`."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    """Degré de confiance dans un finding.

    POSSIBLE  : indice statique isolé (ex. présence d'une fonction dangereuse).
    PROBABLE  : indices concordants (ex. taint reliant une source à un sink).
    CONFIRMED : preuve dynamique (crash reproductible identifié par ASan).
    """

    POSSIBLE = "possible"
    PROBABLE = "probable"
    CONFIRMED = "confirmed"


@dataclass
class ELFInfo:
    """Métadonnées produites par l'étape d'ingestion (§3.4.1)."""

    path: str
    arch: str = ""
    bits: int = 64
    endianness: str = "little"
    is_pie: bool = False
    entrypoint: int = 0
    # Protections détectées : {"nx": True, "canary": False, "relro": "full", ...}
    protections: dict[str, Any] = field(default_factory=dict)
    imports: list[str] = field(default_factory=list)          # fonctions importées (PLT / dynsym)
    functions: dict[str, int] = field(default_factory=dict)   # nom de fonction -> adresse
    has_symbols: bool = False


@dataclass
class Finding:
    """Une vulnérabilité candidate ou confirmée remontée par le pipeline.

    Les deux sens d'« offset » du sujet cohabitent volontairement :
      - `static_offset`  : adresse de l'instruction ou de la fonction visée
                           (résultat de l'analyse statique) ;
      - `exploit_offset` : distance buffer -> RIP obtenue lors de la génération
                           de PoC (cyclic pattern), quand elle est connue.
    """

    vuln_class: VulnClass
    function: str = "?"
    static_offset: Optional[int] = None
    exploit_offset: Optional[int] = None
    severity: Severity = Severity.INFO
    score: float = 0.0                                        # score numérique 0-100
    confidence: Confidence = Confidence.POSSIBLE
    source: str = ""                                          # ex. "static:dangerous_funcs"
    description: str = ""
    remediation: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)    # trace ASan, extrait désassemblé...
    protections_context: list[str] = field(default_factory=list)

    def key(self) -> tuple[str, str]:
        """Clé de déduplication : même classe dans la même fonction = même vuln."""
        return (self.vuln_class.value, self.function)


@dataclass
class Report:
    """Rapport complet pour un binaire analysé."""

    target: str
    elf: Optional[ELFInfo] = None
    findings: list[Finding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Représentation JSON-compatible (les `Enum` deviennent leurs valeurs)."""
        return _to_jsonable(asdict(self))


def _to_jsonable(obj: Any) -> Any:
    """Convertit récursivement `Enum` et conteneurs en types JSON de base."""
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, dict):
        return {key: _to_jsonable(value) for key, value in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_jsonable(value) for value in obj]
    return obj
