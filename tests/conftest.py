"""Fixtures partagées par les tests.

`corpus_build` garantit que le corpus est compilé avant les tests qui en ont
besoin (compilation unique par session, sautée si gcc ou le Makefile manque).
"""

import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus"
BUILD = CORPUS / "build"


@pytest.fixture(scope="session")
def corpus_build() -> Path:
    """Renvoie le dossier des binaires compilés, en lançant `make` si besoin."""
    if not (BUILD / "01_stack_bof_vuln").exists():
        if not (CORPUS / "Makefile").exists():
            pytest.skip("corpus/Makefile absent")
        proc = subprocess.run(
            ["make", "-C", str(CORPUS), "all"],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            pytest.skip(f"échec de compilation du corpus : {proc.stderr[-300:]}")
    return BUILD
