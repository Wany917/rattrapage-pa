"""Tests de l'étape d'ingestion sur le corpus (profils _vuln vs _prot).

On vérifie que la détection maison des protections colle aux flags de
compilation connus, que l'inventaire des fonctions est correct, et que le
recoupement avec checksec concorde.
"""

import shutil

from pipeline.ingestion import ingest


def test_arch_et_type(corpus_build):
    info = ingest(str(corpus_build / "01_stack_bof_vuln"), run_checksec=False)
    assert info.arch == "x64"
    assert info.bits == 64
    assert info.is_pie is False          # profil _vuln : -no-pie -> ET_EXEC


def test_protections_vuln_toutes_off(corpus_build):
    prot = ingest(str(corpus_build / "01_stack_bof_vuln"), run_checksec=False).protections
    assert prot["nx"] is False
    assert prot["canary"] is False
    assert prot["pie"] is False
    assert prot["relro"] == "none"
    assert prot["fortify"] is False


def test_protections_prot_toutes_on(corpus_build):
    prot = ingest(str(corpus_build / "01_stack_bof_prot"), run_checksec=False).protections
    assert prot["nx"] is True
    assert prot["canary"] is True
    assert prot["pie"] is True
    assert prot["relro"] == "full"
    assert prot["fortify"] is True


def test_inventaire_fonctions(corpus_build):
    info = ingest(str(corpus_build / "01_stack_bof_vuln"), run_checksec=False)
    # Fonctions définies : main et vuln (profil -O0, pas d'inlining).
    assert "main" in info.functions
    assert "vuln" in info.functions
    assert info.has_symbols is True
    # Imports : la source fgets et le sink strcpy doivent apparaître.
    assert "strcpy" in info.imports
    assert "fgets" in info.imports


def test_fortify_remplace_strcpy_dans_prot(corpus_build):
    """Dans le profil _prot, FORTIFY remplace strcpy par __strcpy_chk."""
    info = ingest(str(corpus_build / "01_stack_bof_prot"), run_checksec=False)
    assert "__strcpy_chk" in info.imports


def test_checksec_concordant(corpus_build):
    """Le recoupement checksec doit concorder avec notre détection maison."""
    if shutil.which("checksec") is None:
        import pytest
        pytest.skip("checksec non installé")
    prot = ingest(str(corpus_build / "01_stack_bof_prot"), run_checksec=True).protections
    checksec = prot.get("checksec")
    assert checksec is not None
    for cle in ("nx", "canary", "pie", "relro", "fortify"):
        assert prot[cle] == checksec[cle], f"divergence sur {cle}"
