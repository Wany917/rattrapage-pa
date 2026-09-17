"""CLI argus : orchestration du pipeline d'analyse."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from pipeline import __version__, colors
from pipeline.ingestion import ingest
from pipeline.models import ELFInfo, _to_jsonable


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="argus",
        description="argus : détection automatisée de vulnérabilités bas niveau sur binaire ELF.",
    )
    parser.add_argument("binaire", help="chemin du binaire ELF à analyser")
    parser.add_argument("--json", action="store_true",
                        help="sortie JSON (machine) au lieu du résumé lisible")
    parser.add_argument("--no-checksec", action="store_true",
                        help="ne pas recouper la détection avec l'outil checksec")
    parser.add_argument("--static", action="store_true",
                        help="lancer l'analyse statique (fonctions dangereuses, ...)")
    parser.add_argument("--dynamic", action="store_true",
                        help="lancer l'analyse dynamique (build instrumenté, fuzzing AFL++, triage)")
    parser.add_argument("--sources", metavar="FICHIER.c",
                        help="source C de la cible (requis pour --dynamic)")
    parser.add_argument("--fuzz-timeout", type=int, default=30, metavar="S",
                        help="durée max du fuzzing par cible en secondes (défaut : 30)")
    parser.add_argument("--report", metavar="DOSSIER",
                        help="générer les rapports JSON/HTML/Markdown dans ce dossier (implique --static)")
    parser.add_argument("--version", action="version", version=f"argus {__version__}")
    return parser


def _oui_non(valeur: bool) -> str:
    return colors.flag("oui" if valeur else "non", valeur)


def _relro(valeur: str) -> str:
    return colors.flag(valeur, valeur == "full")


def _format_summary(info: ELFInfo) -> str:
    prot = info.protections
    lignes = [
        f"Cible        : {info.path}",
        f"Architecture : {info.arch} ({info.bits} bits, {info.endianness}-endian)",
        f"Type         : {'PIE' if info.is_pie else 'exécutable non-PIE'}"
        f"  (entry = 0x{info.entrypoint:x})",
        "Protections  :",
        f"    NX      : {_oui_non(prot['nx'])}",
        f"    Canary  : {_oui_non(prot['canary'])}",
        f"    PIE     : {_oui_non(prot['pie'])}",
        f"    RELRO   : {_relro(prot['relro'])}",
        f"    FORTIFY : {_oui_non(prot['fortify'])}",
    ]

    checksec = prot.get("checksec")
    if checksec is not None:
        cles = ("nx", "canary", "pie", "relro", "fortify")
        accord = all(prot[c] == checksec[c] for c in cles)
        etat = colors.flag("concordant", True) if accord else colors.flag("DIVERGENT", False)
        lignes.append(f"    checksec: {etat}")

    lignes += [
        f"Fonctions    : {len(info.functions)} définies, {len(info.imports)} importées",
        f"Symboles     : {'présents' if info.has_symbols else 'absents (binaire strippé)'}",
    ]
    return "\n".join(lignes)


def _format_findings(findings: list) -> str:
    if not findings:
        return "Findings : aucun."
    lignes = [f"Findings : {len(findings)}"]
    for finding in findings:
        offset = f"0x{finding.static_offset:x}" if finding.static_offset is not None else "?"
        sev = finding.severity.value
        tag = colors.severity(f"[{sev.upper()} {finding.score}]", sev)
        classe = colors.paint(f"[{finding.vuln_class.value}]", "magenta")
        conf = colors.confidence(finding.confidence.value, finding.confidence.value)
        lignes.append(
            f"    {tag}"
            f" {classe} {finding.function} @ {offset}"
            f" : {finding.description}"
            f" (confiance : {conf}, source : {finding.source})"
        )
    return "\n".join(lignes)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        info = ingest(args.binaire, run_checksec=not args.no_checksec)
    except FileNotFoundError:
        print(f"argus : fichier introuvable : {args.binaire}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - on veut un message propre en CLI
        print(f"argus : échec de l'ingestion : {exc}", file=sys.stderr)
        return 1

    run_static = args.static or bool(args.report)
    run_dynamic = args.dynamic
    if run_dynamic and not args.sources:
        print("argus : --dynamic requiert --sources <fichier.c>", file=sys.stderr)
        return 2

    findings = []
    if run_static:
        from pipeline.static import engine as static_engine
        findings += static_engine.analyze(args.binaire)
    if run_dynamic:
        from pipeline.dynamic import engine as dynamic_engine
        findings += dynamic_engine.analyze_source(args.sources, fuzz_timeout=args.fuzz_timeout)

    show_findings = run_static or run_dynamic
    if show_findings:
        from pipeline import correlation, scoring
        findings = correlation.correlate(findings)
        scoring.score_all(findings, info.protections)

    if args.json:
        sortie = {"elf": asdict(info)}
        if show_findings:
            sortie["findings"] = [asdict(f) for f in findings]
        print(json.dumps(_to_jsonable(sortie), indent=2, ensure_ascii=False))
    else:
        print(_format_summary(info))
        if show_findings:
            print(_format_findings(findings))

    if args.report:
        from pipeline import report as report_mod
        rapport = report_mod.build_report(args.binaire, info, findings)
        chemins = report_mod.write_all(rapport, args.report)
        print("\nRapports générés :")
        for genre, chemin in chemins.items():
            print(f"  {genre:5}: {chemin}")
    return 0
