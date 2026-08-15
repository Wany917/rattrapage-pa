"""Étape 1 du pipeline : ingestion du binaire ELF.

Rôle : à partir du seul binaire (vrai black-box), extraire les métadonnées
nécessaires aux étapes suivantes :
  - architecture, type (exécutable / PIE), point d'entrée ;
  - protections en place (NX, canary, PIE, RELRO, FORTIFY), détectées « à la
    main » en lisant l'ELF, puis recoupées avec l'outil checksec ;
  - inventaire des fonctions : fonctions importées (candidates aux sinks
    dangereux) et fonctions définies (nom -> adresse).

On implémente la détection nous-mêmes plutôt que de seulement appeler checksec,
pour deux raisons : ne dépendre d'aucun outil externe pour le résultat
principal, et pouvoir expliquer précisément, à la soutenance, où chaque
protection se lit dans le format ELF.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Optional

from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from pipeline.models import ELFInfo

# Constantes ELF utiles (valeurs standard du format).
PF_X = 0x1              # program header : segment exécutable
DF_BIND_NOW = 0x8      # DT_FLAGS    : liaison immédiate (contribue au RELRO complet)
DF_1_NOW = 0x1        # DT_FLAGS_1  : idem, variante moderne
DF_1_PIE = 0x08000000  # DT_FLAGS_1  : binaire PIE


def ingest(path: str, run_checksec: bool = True) -> ELFInfo:
    """Analyse le binaire `path` et renvoie un `ELFInfo` complet.

    `run_checksec` : si vrai et si checksec est installé, ajoute son verdict sous
    protections["checksec"] (recoupement, n'altère jamais notre détection).
    """
    with open(path, "rb") as f:
        elf = ELFFile(f)

        info = ELFInfo(path=path)
        info.arch = elf.get_machine_arch()
        info.bits = elf.elfclass
        info.endianness = "little" if elf.little_endian else "big"
        info.entrypoint = elf.header["e_entry"]
        info.is_pie = elf.header["e_type"] == "ET_DYN"

        importes, definies, has_symtab = _collect_symbols(elf)
        info.imports = sorted(importes)
        info.functions = definies
        info.has_symbols = has_symtab

        info.protections = _detect_protections(elf, importes, info.is_pie)

    if run_checksec:
        cross = _checksec_crosscheck(path)
        if cross is not None:
            info.protections["checksec"] = cross

    return info


def _clean_symbol_name(name: str) -> str:
    """Retire le suffixe de version GNU (« fgets@GLIBC_2.2.5 » -> « fgets »)."""
    return name.split("@", 1)[0] if name else name


def _collect_symbols(elf) -> tuple[set[str], dict[str, int], bool]:
    """Renvoie (noms importés, {nom_défini: adresse}, présence d'une .symtab).

    - Importés : symboles FUNC/NOTYPE non définis (SHN_UNDEF) de la .dynsym,
                 résolus via la PLT / l'édition de liens dynamique. C'est là que
                 se trouvent gets, strcpy, printf, __stack_chk_fail, __strcpy_chk.
    - Définis  : symboles FUNC définis (de la .symtab, ou de la .dynsym si le
                 binaire est strippé), avec leur adresse (pour cibler le
                 désassemblage du moteur statique).

    Les suffixes de version (« @GLIBC_... ») sont normalisés pour éviter les
    doublons et fiabiliser la comparaison à la liste noire de la Phase 3.
    """
    importes: set[str] = set()
    definies: dict[str, int] = {}

    dynsym = elf.get_section_by_name(".dynsym")
    if isinstance(dynsym, SymbolTableSection):
        for sym in dynsym.iter_symbols():
            name = _clean_symbol_name(sym.name)
            if name and sym["st_shndx"] == "SHN_UNDEF" \
                    and sym["st_info"]["type"] in ("STT_FUNC", "STT_NOTYPE"):
                importes.add(name)

    symtab = elf.get_section_by_name(".symtab")
    has_symtab = isinstance(symtab, SymbolTableSection)
    source = symtab if has_symtab else dynsym
    if isinstance(source, SymbolTableSection):
        for sym in source.iter_symbols():
            name = _clean_symbol_name(sym.name)
            if name and sym["st_info"]["type"] == "STT_FUNC" \
                    and sym["st_shndx"] != "SHN_UNDEF" and sym["st_value"]:
                definies.setdefault(name, sym["st_value"])

    return importes, definies, has_symtab


def _detect_protections(elf, importes: set[str], is_pie: bool) -> dict:
    """Détecte NX, canary, PIE, RELRO et FORTIFY en lisant l'ELF."""
    canary = "__stack_chk_fail" in importes or "__stack_chk_guard" in importes
    fortify = any(n.startswith("__") and n.endswith("_chk") for n in importes)
    return {
        "nx": _detect_nx(elf),
        "canary": canary,
        "pie": is_pie,
        "relro": _detect_relro(elf),
        "fortify": fortify,
    }


def _detect_nx(elf) -> bool:
    """NX activé si le segment PT_GNU_STACK n'est pas exécutable.

    Convention (comme checksec) : en l'absence de PT_GNU_STACK, on considère la
    pile exécutable (NX désactivé).
    """
    for seg in elf.iter_segments():
        if seg["p_type"] == "PT_GNU_STACK":
            return not bool(seg["p_flags"] & PF_X)
    return False


def _detect_relro(elf) -> str:
    """RELRO : 'none' (pas de segment), 'partial' (segment seul), 'full' (+ BIND_NOW)."""
    has_relro = any(seg["p_type"] == "PT_GNU_RELRO" for seg in elf.iter_segments())
    if not has_relro:
        return "none"
    return "full" if _has_bind_now(elf) else "partial"


def _has_bind_now(elf) -> bool:
    """Vrai si la table dynamique impose la résolution immédiate des symboles."""
    dyn = elf.get_section_by_name(".dynamic")
    if dyn is None or not isinstance(dyn, DynamicSection):
        return False
    for tag in dyn.iter_tags():
        t = tag.entry.d_tag
        if t == "DT_BIND_NOW":
            return True
        if t == "DT_FLAGS" and (tag.entry.d_val & DF_BIND_NOW):
            return True
        if t == "DT_FLAGS_1" and (tag.entry.d_val & DF_1_NOW):
            return True
    return False


def _checksec_crosscheck(path: str) -> Optional[dict]:
    """Verdict de checksec (format JSON) pour recoupement, ou None si indisponible."""
    if shutil.which("checksec") is None:
        return None
    try:
        proc = subprocess.run(
            ["checksec", "--no-banner", "-o", "json", "file", path],
            capture_output=True, text=True, timeout=30,
        )
        data = json.loads(proc.stdout)
    except (subprocess.SubprocessError, json.JSONDecodeError, OSError):
        return None
    if not isinstance(data, list) or not data:
        return None
    checks = data[0].get("checks", {})
    relro_map = {"Full RELRO": "full", "Partial RELRO": "partial", "No RELRO": "none"}
    return {
        "nx": checks.get("nx") == "NX enabled",
        "canary": checks.get("canary") == "Canary Found",
        "pie": checks.get("pie") == "PIE Enabled",
        "relro": relro_map.get(checks.get("relro"), "none"),
        "fortify": checks.get("fortify_source") == "Yes",
        "raw": checks,
    }
