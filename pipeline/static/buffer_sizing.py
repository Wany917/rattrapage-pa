"""Analyse « taille de buffer vs taille de copie » (moteur statique).

Objectif (cf. sujet) : retrouver l'allocation d'un buffer, sur la pile
(sub rsp / lea [rbp-D]) ou sur le tas (malloc), et la comparer à la taille de la
copie qui le remplit (read, memcpy, fgets...). On signale une copie trop grande
ou de taille non bornée.

Dataflow léger, suffisant pour du code -O0 :
  - registres    : lea [rbp-D] -> pointeur de pile de D octets ; retour de
                   malloc(K) -> pointeur de tas de K octets ; mov propage ;
                   immédiat -> constante ;
  - emplacements : les pointeurs sauvés dans une variable locale ([rbp+disp])
                   sont suivis à travers store/reload. C'est indispensable : à
                   -O0 les variables vivent en mémoire, pas en registre, donc
                   un pointeur malloc est écrit sur la pile puis relu avant usage ;
  - un appel écrase les registres (caller-saved) mais pas les emplacements.

Registres de destination et de taille selon l'ABI SysV x86-64.
"""

from __future__ import annotations

from typing import Optional

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
from elftools.elf.elffile import ELFFile

from pipeline.models import Confidence, Finding, VulnClass
from pipeline.static.disasm import Disassembler

# Fonction de copie -> (registre destination, registre taille) canoniques.
COPY_FUNCS: dict[str, tuple[str, str]] = {
    "read": ("rsi", "rdx"),
    "recv": ("rsi", "rdx"),
    "memcpy": ("rdi", "rdx"),
    "memmove": ("rdi", "rdx"),
    "strncpy": ("rdi", "rdx"),
    "strncat": ("rdi", "rdx"),
    "fgets": ("rdi", "rsi"),
    "snprintf": ("rdi", "rsi"),
}
ALLOC_FUNCS = {"malloc", "calloc", "realloc"}


def scan(path: str) -> list[Finding]:
    """Analyse le binaire et renvoie les findings de taille de buffer."""
    findings: list[Finding] = []
    with open(path, "rb") as f:
        elf = ELFFile(f)
        dis = Disassembler(elf)
        for fname, start, size in dis.iter_functions():
            findings.extend(_scan_function(dis, fname, start, size))
    return findings


def _scan_function(dis, fname, start, size) -> list[Finding]:
    out: list[Finding] = []
    reg: dict[str, Optional[tuple]] = {}    # canon -> ('stackbuf',D)|('heapbuf',K)|('const',N)|None
    slots: dict[int, Optional[tuple]] = {}  # emplacement [rbp+disp] -> info
    frame = {"size": None}                   # taille du cadre de pile (sub rsp, imm)

    for insn in dis.disasm_function(start, size):
        if not insn.mnemonic.endswith("call"):
            _track(dis, insn, reg, slots, frame)
            continue

        target = dis.resolve_call(insn)
        if target in COPY_FUNCS:
            finding = _check_copy(target, fname, insn, reg)
            if finding is not None:
                out.append(finding)

        alloc = _alloc_result(target, reg) if target in ALLOC_FUNCS else None
        reg.clear()                          # l'appel écrase les registres caller-saved
        if alloc is not None:
            reg["rax"] = alloc               # ... sauf le retour, qu'on modélise

    return out


def _track(dis, insn, reg, slots, frame) -> None:
    ops = insn.operands
    mnem = insn.mnemonic

    # Taille du cadre : sub rsp, imm (prologue).
    if (mnem == "sub" and len(ops) >= 2 and ops[0].type == X86_OP_REG
            and dis.md.reg_name(ops[0].reg) == "rsp" and ops[1].type == X86_OP_IMM):
        if frame["size"] is None:
            frame["size"] = ops[1].imm
        return

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
        reg[dst] = _stack_ptr(dis, ops[1].mem, frame)
    elif mnem in ("mov", "movabs") and len(ops) >= 2:
        src = ops[1]
        if src.type == X86_OP_IMM:
            reg[dst] = ("const", src.imm)
        elif src.type == X86_OP_REG:
            reg[dst] = reg.get(dis.canon(src.reg))
        elif src.type == X86_OP_MEM:
            slot = _rbp_slot(dis, src.mem)
            reg[dst] = slots.get(slot) if slot is not None else None
        else:
            reg[dst] = None
    elif mnem == "xor" and len(ops) >= 2 and ops[1].type == X86_OP_REG \
            and dis.canon(ops[1].reg) == dst:
        reg[dst] = ("const", 0)
    else:
        reg[dst] = None


def _rbp_slot(dis, mem) -> Optional[int]:
    """Clé d'emplacement local si `mem` est [rbp+disp] simple, sinon None."""
    if mem.base and dis.md.reg_name(mem.base) == "rbp" and mem.index == 0:
        return mem.disp
    return None


def _stack_ptr(dis, mem, frame) -> Optional[tuple]:
    """Pointeur de pile pour un lea : ('stackbuf', capacité) ou None."""
    if not mem.base or mem.index != 0:
        return None
    base = dis.md.reg_name(mem.base)
    if base == "rbp" and mem.disp < 0:
        return ("stackbuf", -mem.disp)          # D octets jusqu'au RBP sauvé
    if base == "rsp" and frame["size"] is not None and mem.disp >= 0:
        capacity = frame["size"] - mem.disp
        if capacity > 0:
            return ("stackbuf", capacity)
    return None


def _alloc_result(target, reg) -> tuple:
    """Modélise le retour de malloc/calloc/realloc : ('heapbuf', taille|None)."""
    if target == "malloc":
        arg = reg.get("rdi")
    elif target == "realloc":
        arg = reg.get("rsi")
    elif target == "calloc":
        nmemb, size = reg.get("rdi"), reg.get("rsi")
        if nmemb and size and nmemb[0] == "const" and size[0] == "const":
            return ("heapbuf", nmemb[1] * size[1])
        return ("heapbuf", None)
    else:
        arg = None
    return ("heapbuf", arg[1] if arg and arg[0] == "const" else None)


def _check_copy(target, fname, insn, reg) -> Optional[Finding]:
    dst_reg, size_reg = COPY_FUNCS[target]
    dst = reg.get(dst_reg)
    if not dst or dst[0] not in ("stackbuf", "heapbuf"):
        return None

    kind, capacity = dst
    if capacity is None:
        return None      # allocation de taille inconnue : comparaison impossible
    vuln_class = VulnClass.STACK_BOF if kind == "stackbuf" else VulnClass.HEAP_BOF
    lieu = "pile" if kind == "stackbuf" else "tas"
    evidence = {"sink": target, "call_site": hex(insn.address),
                "buffer_capacity": capacity, "buffer": lieu}

    size = reg.get(size_reg)
    if size and size[0] == "const":
        n = size[1]
        if n <= capacity:
            return None      # copie bornée correctement
        evidence["copy_size"] = n
        return Finding(
            vuln_class=vuln_class, function=fname, static_offset=insn.address,
            confidence=Confidence.PROBABLE, source="static:buffer_sizing",
            description=f"{target} copie {n} octets vers un buffer de {lieu} de {capacity} octets (débordement).",
            remediation="borner la copie à la taille réelle du buffer",
            evidence=evidence,
        )

    # Taille non constante (registre non résolu) : potentiellement contrôlée.
    evidence["copy_size"] = "non constante"
    return Finding(
        vuln_class=vuln_class, function=fname, static_offset=insn.address,
        confidence=Confidence.POSSIBLE, source="static:buffer_sizing",
        description=f"{target} copie une taille non constante (potentiellement contrôlée) vers un buffer de {lieu} de {capacity} octets.",
        remediation="borner la copie à la taille réelle du buffer",
        evidence=evidence,
    )
