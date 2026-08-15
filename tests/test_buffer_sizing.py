"""Tests de l'analyse « taille de buffer vs taille de copie »."""

from pipeline.models import Confidence, VulnClass
from pipeline.static.buffer_sizing import scan


def test_heap_overflow_detecte(corpus_build):
    """read(4096) dans un malloc(64) doit être vu comme un heap-buffer-overflow."""
    findings = scan(str(corpus_build / "02_heap_bof_vuln"))
    heap = [f for f in findings if f.vuln_class == VulnClass.HEAP_BOF]
    assert heap, "le débordement de tas devrait être détecté statiquement"
    finding = heap[0]
    assert finding.function == "main"
    assert finding.static_offset is not None
    assert finding.evidence.get("copy_size") == 4096
    assert finding.evidence.get("buffer_capacity") == 64
    assert finding.confidence == Confidence.PROBABLE


def test_pas_de_faux_positif_sur_copies_bornees(corpus_build):
    """fgets bornés (256/256, 32/32, 64/64) : aucun finding buffer_sizing."""
    for nom in ("03_format_string_vuln", "05_use_after_free_vuln", "06_double_free_vuln"):
        findings = scan(str(corpus_build / nom))
        assert not findings, f"{nom} ne devrait produire aucun finding buffer_sizing"
