"""Rapport Markdown (lisible par un humain, versionnable, convertible PDF/Word)."""

from __future__ import annotations

from pipeline.models import Finding, Report


def _oui_non(valeur) -> str:
    return "oui" if valeur else "non"


def _offset(value) -> str:
    return f"0x{value:x}" if value is not None else "-"


def render_markdown(report: Report) -> str:
    elf = report.elf
    prot = elf.protections if elf else {}
    lignes: list[str] = []
    lignes.append(f"# Rapport argus : `{report.target}`")
    lignes.append("")
    if elf:
        lignes.append("## Cible")
        lignes.append("")
        lignes.append(f"- Architecture : {elf.arch} ({elf.bits} bits, {elf.endianness}-endian)")
        lignes.append(f"- Type : {'PIE' if elf.is_pie else 'exécutable non-PIE'} (entry 0x{elf.entrypoint:x})")
        lignes.append(f"- Symboles : {'présents' if elf.has_symbols else 'absents (strippé)'}")
        lignes.append(f"- Fonctions : {len(elf.functions)} définies, {len(elf.imports)} importées")
        lignes.append("")
        lignes.append("## Protections")
        lignes.append("")
        lignes.append("| Protection | État |")
        lignes.append("|------------|------|")
        lignes.append(f"| NX | {_oui_non(prot.get('nx'))} |")
        lignes.append(f"| Stack canary | {_oui_non(prot.get('canary'))} |")
        lignes.append(f"| PIE | {_oui_non(prot.get('pie'))} |")
        lignes.append(f"| RELRO | {prot.get('relro', 'none')} |")
        lignes.append(f"| FORTIFY | {_oui_non(prot.get('fortify'))} |")
        lignes.append("")

    stats = report.stats or {}
    lignes.append("## Synthèse")
    lignes.append("")
    lignes.append(f"- {stats.get('total', len(report.findings))} vulnérabilité(s) détectée(s).")
    par_sev = stats.get("par_severite", {})
    if par_sev:
        detail = ", ".join(f"{n} {sev}" for sev, n in par_sev.items())
        lignes.append(f"- Répartition : {detail}.")
    lignes.append("")

    lignes.append("## Vulnérabilités")
    lignes.append("")
    if not report.findings:
        lignes.append("Aucune vulnérabilité détectée.")
    for finding in report.findings:
        lignes.extend(_finding_md(finding))
    lignes.append("")
    return "\n".join(lignes)


def _finding_md(f: Finding) -> list[str]:
    out = [
        f"### [{f.severity.value.upper()} {f.score}] {f.vuln_class.value} — "
        f"`{f.function}` @ {_offset(f.static_offset)}",
        "",
        f"- Confiance : {f.confidence.value}",
        f"- Exploitabilité : {f.evidence.get('exploitability', 'inconnue')}",
        f"- Offset statique : {_offset(f.static_offset)} | offset exploit : {_offset(f.exploit_offset)}",
        f"- Sources : {f.source}",
        f"- Description : {f.description}",
        f"- Remédiation : {f.remediation}",
    ]
    if f.protections_context:
        out.append(f"- Protections en place : {', '.join(f.protections_context)}")
    if f.evidence:
        preuves = ", ".join(f"{k} = {v}" for k, v in f.evidence.items())
        out.append(f"- Preuves : {preuves}")
    out.append("")
    return out


def write_md(report: Report, path: str) -> str:
    """Écrit le rapport Markdown dans `path` et renvoie ce chemin."""
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_markdown(report))
    return path
