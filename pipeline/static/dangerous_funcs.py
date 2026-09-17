"""Détection des appels à fonctions dangereuses et des format strings non constants."""

from __future__ import annotations

from typing import Optional

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP
from elftools.elf.elffile import ELFFile

from pipeline.models import Confidence, Finding, VulnClass
from pipeline.static.disasm import Disassembler

# Sinks : nom -> (classe probable, raison, remédiation).
SINKS: dict[str, tuple[VulnClass, str, str]] = {
    "gets": (VulnClass.STACK_BOF, "gets ne borne pas la lecture (débordement garanti sur entrée longue)", "remplacer par fgets(buf, sizeof(buf), stdin)"),
    "strcpy": (VulnClass.STACK_BOF, "strcpy copie sans vérifier la taille de destination", "utiliser strncpy/strlcpy ou contrôler la longueur"),
    "strcat": (VulnClass.STACK_BOF, "strcat concatène sans borne", "utiliser strncat/strlcat"),
    "sprintf": (VulnClass.STACK_BOF, "sprintf écrit sans borne dans le tampon", "utiliser snprintf"),
    "vsprintf": (VulnClass.STACK_BOF, "vsprintf écrit sans borne", "utiliser vsnprintf"),
    "scanf": (VulnClass.STACK_BOF, "scanf avec %s lit sans borne", "borner (%Ns) ou utiliser fgets"),
    "sscanf": (VulnClass.STACK_BOF, "sscanf avec %s lit sans borne", "borner les conversions"),
    "fscanf": (VulnClass.STACK_BOF, "fscanf avec %s lit sans borne", "borner les conversions"),
    "alloca": (VulnClass.STACK_BOF, "alloca alloue sur la pile selon une taille non contrôlée", "éviter alloca, borner la taille"),
    "system": (VulnClass.UNKNOWN, "system exécute une commande shell (injection possible)", "éviter system, préférer execve avec des arguments"),
    "popen": (VulnClass.UNKNOWN, "popen lance un shell (injection possible)", "éviter popen, valider strictement l'entrée"),
}

# Fonctions de format -> registre (canonique) portant la chaîne de format.
FORMAT_ARG: dict[str, str] = {
    "printf": "rdi", "vprintf": "rdi",
    "fprintf": "rsi", "dprintf": "rsi", "vfprintf": "rsi",
    "syslog": "rsi", "vsyslog": "rsi",
}



def scan(path: str) -> list[Finding]:
    findings: list[Finding] = []
    with open(path, "rb") as f:
        elf = ELFFile(f)
        dis = Disassembler(elf)
        for fname, start, size in dis.iter_functions():
            findings.extend(_scan_function(dis, fname, start, size))
    return findings


def _scan_function(dis: Disassembler, fname: str, start: int, size: int) -> list[Finding]:
    out: list[Finding] = []
    # Constance des pointeurs par registre : None inconnu, True constant, False variable.
    reg_const: dict[str, Optional[bool]] = {}

    for insn in dis.disasm_function(start, size):
        if not insn.mnemonic.endswith("call"):
            _track_registers(dis, insn, reg_const)
            continue

        target = dis.resolve_call(insn)
        if target in SINKS:
            vuln_class, raison, remede = SINKS[target]
            out.append(Finding(
                vuln_class=vuln_class,
                function=fname,
                static_offset=insn.address,
                confidence=Confidence.POSSIBLE,
                source="static:dangerous_funcs",
                description=f"Appel à {target} : {raison}.",
                remediation=remede,
                evidence={"sink": target, "call_site": hex(insn.address)},
            ))
        elif target in FORMAT_ARG and reg_const.get(FORMAT_ARG[target]) is False:
            out.append(Finding(
                vuln_class=VulnClass.FORMAT_STRING,
                function=fname,
                static_offset=insn.address,
                confidence=Confidence.POSSIBLE,
                source="static:dangerous_funcs",
                description=f"Appel à {target} avec une chaîne de format non constante (format contrôlable).",
                remediation=f'utiliser {target}("%s", donnee) avec un format constant',
                evidence={"sink": target, "call_site": hex(insn.address), "format": "non constant"},
            ))

        # Un appel écrase les registres caller-saved (dont rax/rdi/rsi).
        reg_const.clear()

    return out


def _track_registers(dis: Disassembler, insn, reg_const: dict) -> None:
    ops = insn.operands
    if not ops or ops[0].type != X86_OP_REG:
        return
    dst = dis.canon(ops[0].reg)
    if dst is None:
        return

    mnem = insn.mnemonic
    if mnem == "lea" and len(ops) >= 2 and ops[1].type == X86_OP_MEM:
        if ops[1].mem.base == X86_REG_RIP:
            target = insn.address + insn.size + ops[1].mem.disp
            reg_const[dst] = dis.is_const_ptr(target)   # lea rip vers .rodata = constant
        else:
            reg_const[dst] = False                       # adresse de pile/tas = variable
    elif mnem in ("mov", "movabs") and len(ops) >= 2:
        src = ops[1]
        if src.type == X86_OP_REG:
            reg_const[dst] = reg_const.get(dis.canon(src.reg))
        elif src.type == X86_OP_IMM:
            reg_const[dst] = dis.is_const_ptr(src.imm)    # immédiat pointant en .rodata (non-PIE)
        else:
            reg_const[dst] = False                        # chargement mémoire = variable
    else:
        reg_const[dst] = False                            # toute autre écriture = variable
