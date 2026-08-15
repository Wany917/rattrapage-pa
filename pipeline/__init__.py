"""Pipeline d'analyse de vulnérabilités bas niveau sur binaire ELF x86-64.

Chaque étape du pipeline correspond à un (sous-)module :

    ingestion              -> parse ELF, protections, inventaire des fonctions
    static/                -> fonctions dangereuses, buffer sizing, taint
    dynamic/               -> build instrumenté, fuzzing AFL++, triage ASan/CASR
    correlation + scoring  -> fusion, déduplication, sévérité
    report/                -> sérialisation JSON + HTML/Markdown

Le module `models` définit le contrat de données partagé entre ces étapes.
"""

__version__ = "0.1.0"
