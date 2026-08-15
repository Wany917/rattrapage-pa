"""Test fumigène : le paquet s'importe et le contrat de données fonctionne.

Ce test ne dépend d'aucune bibliothèque externe (ni Capstone, ni pyelftools) :
il valide uniquement que le squelette du projet est cohérent.
"""

from pipeline import __version__
from pipeline.models import Confidence, Finding, Report, Severity, VulnClass


def test_version_presente():
    assert __version__


def test_finding_serialisation():
    """Un Finding sérialisé doit exposer les valeurs des enums, pas les objets."""
    finding = Finding(
        vuln_class=VulnClass.STACK_BOF,
        function="main",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
    )
    rapport = Report(target="/bin/true", findings=[finding])
    donnees = rapport.to_dict()

    finding_json = donnees["findings"][0]
    assert finding_json["vuln_class"] == "stack_buffer_overflow"
    assert finding_json["severity"] == "critical"
    assert finding_json["confidence"] == "confirmed"


def test_cle_deduplication():
    """Deux findings de même classe et même fonction partagent la même clé."""
    a = Finding(vuln_class=VulnClass.HEAP_BOF, function="parse")
    b = Finding(vuln_class=VulnClass.HEAP_BOF, function="parse")
    assert a.key() == b.key()
