"""Tests de la corrélation (fusion statique/dynamique)."""

from pipeline.correlation import correlate
from pipeline.models import Confidence, Finding, VulnClass


def test_fusion_statique_dynamique():
    static = Finding(VulnClass.HEAP_BOF, function="main", static_offset=0x1000,
                     confidence=Confidence.PROBABLE, source="static:buffer_sizing")
    dyn = Finding(VulnClass.HEAP_BOF, function="main", confidence=Confidence.CONFIRMED,
                  source="dynamic:casr-san", evidence={"exploitability": "EXPLOITABLE"})
    merged = correlate([static, dyn])
    assert len(merged) == 1
    m = merged[0]
    assert m.confidence == Confidence.CONFIRMED          # le crash l'emporte
    assert m.static_offset == 0x1000                      # offset statique conservé
    assert "static:buffer_sizing" in m.source and "dynamic:casr-san" in m.source
    assert m.evidence.get("exploitability") == "EXPLOITABLE"


def test_reconciliation_unknown_format_string():
    static = Finding(VulnClass.FORMAT_STRING, function="main", static_offset=0x2000,
                     confidence=Confidence.PROBABLE, source="static:taint")
    dyn = Finding(VulnClass.UNKNOWN, function="main", confidence=Confidence.CONFIRMED,
                  source="dynamic:casr-san")
    merged = correlate([static, dyn])
    assert len(merged) == 1
    assert merged[0].vuln_class == VulnClass.FORMAT_STRING   # la classe spécifique gagne
    assert merged[0].confidence == Confidence.CONFIRMED


def test_pas_de_fusion_classes_differentes():
    a = Finding(VulnClass.STACK_BOF, function="f", source="static:x")
    b = Finding(VulnClass.HEAP_BOF, function="f", source="static:y")
    assert len(correlate([a, b])) == 2


def test_pas_de_fusion_fonctions_differentes():
    a = Finding(VulnClass.HEAP_BOF, function="f", source="static:x")
    b = Finding(VulnClass.HEAP_BOF, function="g", source="dynamic:y")
    assert len(correlate([a, b])) == 2
