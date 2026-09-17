"""Fixtures partagées par les tests."""

import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus"
BUILD = CORPUS / "build"


@pytest.fixture(scope="session")
def corpus_build() -> Path:
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
