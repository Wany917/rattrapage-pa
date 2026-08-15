"""Tests du taint tracking et de la déduplication du moteur statique."""

from pipeline.models import Confidence, VulnClass
from pipeline.static.engine import analyze
from pipeline.static.taint import scan


def test_taint_fgets_vers_strcpy(corpus_build):
    findings = scan(str(corpus_build / "01_stack_bof_vuln"))
    flux = [f for f in findings
            if f.evidence.get("source") == "fgets" and f.evidence.get("sink") == "strcpy"]
    assert flux, "le flux fgets -> strcpy devrait être détecté"
    assert flux[0].confidence == Confidence.PROBABLE
    assert flux[0].vuln_class == VulnClass.STACK_BOF


def test_taint_fgets_vers_printf(corpus_build):
    findings = scan(str(corpus_build / "03_format_string_vuln"))
    flux = [f for f in findings if f.evidence.get("sink") == "printf"]
    assert flux, "le flux fgets -> printf devrait être détecté"
    assert flux[0].vuln_class == VulnClass.FORMAT_STRING


def test_taint_absent_sans_flux(corpus_build):
    """06 (double free) : aucune source ne rejoint un sink suivi -> pas de finding taint."""
    assert not scan(str(corpus_build / "06_double_free_vuln"))


def test_engine_fusionne_et_eleve_la_confiance(corpus_build):
    """dangerous_funcs (POSSIBLE) + taint (PROBABLE) sur strcpy -> une entrée PROBABLE."""
    findings = analyze(str(corpus_build / "01_stack_bof_vuln"))
    strcpy = [f for f in findings if f.evidence.get("sink") == "strcpy"]
    assert len(strcpy) == 1, "les deux findings du même site doivent être fusionnés"
    assert strcpy[0].confidence == Confidence.PROBABLE
    assert "taint" in strcpy[0].source and "dangerous_funcs" in strcpy[0].source
