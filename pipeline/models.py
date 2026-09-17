"""Structures de données partagées par tout le pipeline."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Optional


class VulnClass(str, Enum):

    STACK_BOF = "stack_buffer_overflow"
    HEAP_BOF = "heap_buffer_overflow"
    FORMAT_STRING = "format_string"
    INTEGER_OVERFLOW = "integer_overflow"
    USE_AFTER_FREE = "use_after_free"
    DOUBLE_FREE = "double_free"
    UNKNOWN = "unknown"


class Severity(str, Enum):

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):

    POSSIBLE = "possible"
    PROBABLE = "probable"
    CONFIRMED = "confirmed"


@dataclass
class ELFInfo:

    path: str
    arch: str = ""
    bits: int = 64
    endianness: str = "little"
    is_pie: bool = False
    entrypoint: int = 0
    # Protections détectées : {"nx": True, "canary": False, "relro": "full", ...}
    protections: dict[str, Any] = field(default_factory=dict)
    imports: list[str] = field(default_factory=list)
    functions: dict[str, int] = field(default_factory=dict)
    has_symbols: bool = False


@dataclass
class Finding:

    vuln_class: VulnClass
    function: str = "?"
    static_offset: Optional[int] = None
    exploit_offset: Optional[int] = None
    severity: Severity = Severity.INFO
    score: float = 0.0
    confidence: Confidence = Confidence.POSSIBLE
    source: str = ""
    description: str = ""
    remediation: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    protections_context: list[str] = field(default_factory=list)

    def key(self) -> tuple[str, str]:
        return (self.vuln_class.value, self.function)


@dataclass
class Report:

    target: str
    elf: Optional[ELFInfo] = None
    findings: list[Finding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return _to_jsonable(asdict(self))


def _to_jsonable(obj: Any) -> Any:
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, dict):
        return {key: _to_jsonable(value) for key, value in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_jsonable(value) for value in obj]
    return obj
