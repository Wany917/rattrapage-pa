"""Taint tracking intra-procédural source -> sink."""

from __future__ import annotations

from typing import Optional

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP
from elftools.elf.elffile import ELFFile

from pipeline.models import Confidence, Finding, VulnClass
from pipeline.static.disasm import Disassembler

# Source -> registre pointant le buffer rempli (ABI SysV x86-64).
SOURCES = {
    "fgets": "rdi", "gets": "rdi", "fread": "rdi",
    "read": "rsi", "recv": "rsi",
}
# Sink -> (registre consommant la donnée, classe si le flux est confirmé).
SINKS = {
    "strcpy": ("rsi", VulnClass.STACK_BOF),
    "strcat": ("rsi", VulnClass.STACK_BOF),
    "printf": ("rdi", VulnClass.FORMAT_STRING),
    "fprintf": ("rsi", VulnClass.FORMAT_STRING),
    "system": ("rdi", VulnClass.UNKNOWN),
}


def scan(path: str) -> list[Finding]:
    findings: list[Finding] = []
    with open(path, "rb") as f:
        elf = ELFFile(f)
        dis = Disassembler(elf)
        for fname, start, size in dis.iter_functions():
            findings.extend(_scan_function(dis, fname, start, size))
    return findings


def _scan_function(dis, fname, start, size) -> list[Finding]:
    out: list[Finding] = []
    reg: dict[str, Optional[tuple]] = {}     # canon -> clé de buffer | None
    slots: dict[int, Optional[tuple]] = {}
    tainted: set = set()                       # clés de buffers contaminés
    origin: dict[tuple, str] = {}             # clé -> nom de la source contaminante

    for insn in dis.disasm_function(start, size):
        if not insn.mnemonic.endswith("call"):
            _track(dis, insn, reg, slots)
            continue

        target = dis.resolve_call(insn)
        if target in SOURCES:
            key = reg.get(SOURCES[target])
            if key is not None:
                tainted.add(key)
                origin[key] = target
        elif target in SINKS:
            arg_reg, vuln_class = SINKS[target]
            key = reg.get(arg_reg)
            if key is not None and key in tainted:
                out.append(Finding(
                    vuln_class=vuln_class, function=fname, static_offset=insn.address,
                    confidence=Confidence.PROBABLE, source="static:taint",
                    description=f"Donnée issue de {origin.get(key)} atteint {target} (flux source vers sink confirmé).",
                    remediation="valider et borner la donnée entre la source et le sink",
                    evidence={"source": origin.get(key), "sink": target, "call_site": hex(insn.address)},
                ))
        reg.clear()   # l'appel écrase les registres (les buffers contaminés, eux, persistent)

    return out


def _track(dis, insn, reg, slots) -> None:
    ops = insn.operands
    mnem = insn.mnemonic
    if not ops:
        return

    # Sauvegarde d'un pointeur local : mov [rbp+disp], reg.
    if mnem in ("mov", "movabs") and ops[0].type == X86_OP_MEM and len(ops) >= 2:
        slot = _rbp_slot(dis, ops[0].mem)
        if slot is not None and ops[1].type == X86_OP_REG:
            slots[slot] = reg.get(dis.canon(ops[1].reg))
        return

    if ops[0].type != X86_OP_REG:
        return
    dst = dis.canon(ops[0].reg)
    if dst is None:
        return

    if mnem == "lea" and len(ops) >= 2 and ops[1].type == X86_OP_MEM:
        reg[dst] = _buffer_key(dis, insn, ops[1].mem)
    elif mnem in ("mov", "movabs") and len(ops) >= 2:
        src = ops[1]
        if src.type == X86_OP_REG:
            reg[dst] = reg.get(dis.canon(src.reg))
        elif src.type == X86_OP_IMM:
            # no-PIE : l'adresse d'un buffer global est chargée en immédiat.
            reg[dst] = ("global", src.imm) if dis.is_writable_data(src.imm) else None
        elif src.type == X86_OP_MEM:
            slot = _rbp_slot(dis, src.mem)
            reg[dst] = slots.get(slot) if slot is not None else None
        else:
            reg[dst] = None
    else:
        reg[dst] = None


def _rbp_slot(dis, mem) -> Optional[int]:
    if mem.base and dis.md.reg_name(mem.base) == "rbp" and mem.index == 0:
        return mem.disp
    return None


def _buffer_key(dis, insn, mem) -> Optional[tuple]:
    if mem.index != 0:
        return None
    if mem.base and dis.md.reg_name(mem.base) == "rbp" and mem.disp < 0:
        return ("stack", -mem.disp)
    if mem.base == X86_REG_RIP:
        return ("global", insn.address + insn.size + mem.disp)
    return None
