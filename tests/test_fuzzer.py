"""Test de bout en bout du moteur dynamique : build + fuzzing + triage."""

from pathlib import Path

import pytest

from pipeline.dynamic import engine
from pipeline.dynamic.afl_env import afl_dir
from pipeline.models import Confidence, VulnClass

pytestmark = pytest.mark.skipif(afl_dir() is None, reason="AFL++ non installé")

SRC = Path(__file__).resolve().parent.parent / "corpus" / "src" / "02_heap_bof.c"


def test_pipeline_dynamique_decouvre_heap_overflow(tmp_path):
    """Le fuzzing doit découvrir seul une entrée qui déclenche le heap overflow."""
    findings = engine.analyze_source(str(SRC), workdir=str(tmp_path), fuzz_timeout=40)
    heap = [f for f in findings if f.vuln_class == VulnClass.HEAP_BOF]
    assert heap, "le fuzzing aurait dû découvrir le débordement de tas"
    assert heap[0].confidence == Confidence.CONFIRMED
    assert heap[0].source.startswith("dynamic:")


# Cible réaliste qui lit un FICHIER (et non stdin), comme la plupart des vrais
# programmes : déborde buf[32] si le fichier dépasse 32 octets.
_FILE_VULN_SRC = r"""
#include <stdio.h>
int main(int argc, char **argv) {
    char buf[32];
    if (argc < 2) return 0;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 0;
    size_t n = fread(buf, 1, 4096, f);   /* déborde buf[32] si le fichier > 32 octets */
    fclose(f);
    printf("%zu\n", n);
    return 0;
}
"""


def test_pipeline_dynamique_mode_fichier(tmp_path):
    """Cible lisant un FICHIER : le pipeline fuzze en @@ et découvre l'overflow."""
    src = tmp_path / "fvuln.c"
    src.write_text(_FILE_VULN_SRC)
    findings = engine.analyze_source(str(src), workdir=str(tmp_path),
                                     fuzz_timeout=40, file_input=True)
    assert findings, "le fuzzing en mode fichier aurait dû trouver un crash"
    assert any(f.vuln_class == VulnClass.STACK_BOF for f in findings)
    assert findings[0].confidence == Confidence.CONFIRMED
