"""Tests du triage dynamique (ASan / CASR)."""

from pipeline.dynamic.triage import _class_from_text, triage_input
from pipeline.models import Confidence, VulnClass

# Entrées connues qui font crasher chaque binaire _asan (cf. docs/corpus.md).
CRASHES = {
    "02_heap_bof": b"A" * 200,
    "05_use_after_free": b"cmd\n" + b"B" * 40,
    "06_double_free": b"AAAA\n",
    "04_integer_overflow": b"\x01\x00\x00\x20" + b"A" * 2000,
}


def test_mapping_des_types():
    assert _class_from_text("heap-buffer-overflow(write)") == VulnClass.HEAP_BOF
    assert _class_from_text("attempting double-free") == VulnClass.DOUBLE_FREE
    assert _class_from_text("heap-use-after-free") == VulnClass.USE_AFTER_FREE
    assert _class_from_text("stack-buffer-overflow") == VulnClass.STACK_BOF
    assert _class_from_text("negative-size-param") == VulnClass.INTEGER_OVERFLOW
    assert _class_from_text("SEGV on unknown address") == VulnClass.UNKNOWN


def test_triage_heap_overflow(corpus_build):
    finding = triage_input(str(corpus_build / "02_heap_bof_asan"), CRASHES["02_heap_bof"])
    assert finding is not None
    assert finding.vuln_class == VulnClass.HEAP_BOF
    assert finding.confidence == Confidence.CONFIRMED
    assert finding.function == "main"


def test_triage_use_after_free(corpus_build):
    finding = triage_input(str(corpus_build / "05_use_after_free_asan"), CRASHES["05_use_after_free"])
    assert finding is not None
    assert finding.vuln_class == VulnClass.USE_AFTER_FREE
    assert finding.confidence == Confidence.CONFIRMED


def test_triage_double_free(corpus_build):
    finding = triage_input(str(corpus_build / "06_double_free_asan"), CRASHES["06_double_free"])
    assert finding is not None
    assert finding.vuln_class == VulnClass.DOUBLE_FREE


def test_triage_integer_overflow_donne_heap(corpus_build):
    """L'integer overflow se manifeste dynamiquement comme un heap-buffer-overflow."""
    finding = triage_input(str(corpus_build / "04_integer_overflow_asan"), CRASHES["04_integer_overflow"])
    assert finding is not None
    assert finding.vuln_class == VulnClass.HEAP_BOF


def test_triage_exploitabilite_presente(corpus_build):
    finding = triage_input(str(corpus_build / "02_heap_bof_asan"), CRASHES["02_heap_bof"])
    assert finding.evidence.get("exploitability") in (
        "EXPLOITABLE", "PROBABLY_EXPLOITABLE", "NOT_EXPLOITABLE", "UNKNOWN")
