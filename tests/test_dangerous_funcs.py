"""Tests de la détection des fonctions dangereuses (moteur statique)."""

from pipeline.models import VulnClass
from pipeline.static.dangerous_funcs import scan


def test_strcpy_detecte_dans_stack_bof(corpus_build):
    findings = scan(str(corpus_build / "01_stack_bof_vuln"))
    strcpy = [f for f in findings if f.evidence.get("sink") == "strcpy"]
    assert strcpy, "strcpy devrait être détecté"
    assert strcpy[0].vuln_class == VulnClass.STACK_BOF
    assert strcpy[0].function == "vuln"          # appelant correctement identifié
    assert strcpy[0].static_offset is not None    # offset du call renseigné


def test_format_string_detecte(corpus_build):
    findings = scan(str(corpus_build / "03_format_string_vuln"))
    fmt = [f for f in findings if f.vuln_class == VulnClass.FORMAT_STRING]
    assert fmt, "printf à format non constant devrait être détecté"
    assert fmt[0].function == "main"


def test_pas_de_faux_positif_format_constant(corpus_build):
    """Seul 03 utilise un format non constant : aucun autre ne doit être flagué."""
    for nom in ("01_stack_bof_vuln", "02_heap_bof_vuln", "04_integer_overflow_vuln",
                "05_use_after_free_vuln", "06_double_free_vuln"):
        findings = scan(str(corpus_build / nom))
        fmt = [f for f in findings if f.vuln_class == VulnClass.FORMAT_STRING]
        assert not fmt, f"{nom} ne devrait pas déclencher de faux positif format string"


def test_fortify_neutralise_strcpy(corpus_build):
    """Dans _prot, strcpy devient __strcpy_chk : plus de finding strcpy nu."""
    findings = scan(str(corpus_build / "01_stack_bof_prot"))
    strcpy = [f for f in findings if f.evidence.get("sink") == "strcpy"]
    assert not strcpy
