"""Ingestion ELF : métadonnées, protections, fonctions."""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Optional

from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from pipeline.models import ELFInfo

PF_X = 0x1
DF_BIND_NOW = 0x8
DF_1_NOW = 0x1
DF_1_PIE = 0x08000000


def ingest(path: str, run_checksec: bool = True) -> ELFInfo:
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
    return name.split("@", 1)[0] if name else name


def _collect_symbols(elf) -> tuple[set[str], dict[str, int], bool]:
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
    # Sans PT_GNU_STACK, on considère la pile exécutable (convention checksec).
    for seg in elf.iter_segments():
        if seg["p_type"] == "PT_GNU_STACK":
            return not bool(seg["p_flags"] & PF_X)
    return False


def _detect_relro(elf) -> str:
    has_relro = any(seg["p_type"] == "PT_GNU_RELRO" for seg in elf.iter_segments())
    if not has_relro:
        return "none"
    return "full" if _has_bind_now(elf) else "partial"


def _has_bind_now(elf) -> bool:
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
