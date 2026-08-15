"""Désassemblage et résolution des appels (socle commun du moteur statique).

La classe `Disassembler`, pour un ELF x86-64 :
  - itère les fonctions définies (nom, adresse, taille) ;
  - désassemble une fonction avec Capstone (mode détaillé, opérandes accessibles) ;
  - résout la cible d'un `call` vers le nom de la fonction importée, que l'appel
    passe par la PLT (`call <stub>`) ou par la GOT (`call [rip+x]`, binaires
    compilés en -fno-plt) ;
  - indique si une adresse pointe dans une section en lecture seule (.rodata),
    pour distinguer une chaîne de format constante d'une variable.

La résolution PLT lit réellement la cible du saut du stub (`jmp [rip+got]`)
plutôt que de supposer une disposition figée : cela fonctionne pour la PLT
classique comme pour `.plt.sec` (stubs précédés d'un `endbr64`, CET).
"""

from __future__ import annotations

from typing import Iterator, Optional

from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

# Drapeaux de section ELF (champ sh_flags).
SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4


def _clean(name: str) -> str:
    """Retire le suffixe de version GNU (« strcpy@GLIBC_2.2.5 » -> « strcpy »)."""
    return name.split("@", 1)[0] if name else name


# Sous-registres -> registre 64 bits canonique (pour la propagation de dataflow).
CANON = {
    "rax": "rax", "eax": "rax", "ax": "rax", "al": "rax",
    "rcx": "rcx", "ecx": "rcx", "cx": "rcx", "cl": "rcx",
    "rdx": "rdx", "edx": "rdx", "dx": "rdx", "dl": "rdx",
    "rsi": "rsi", "esi": "rsi", "si": "rsi", "sil": "rsi",
    "rdi": "rdi", "edi": "rdi", "di": "rdi", "dil": "rdi",
    "r8": "r8", "r8d": "r8", "r9": "r9", "r9d": "r9",
}


class Disassembler:
    """Fournit désassemblage et résolution d'appels pour un ELFFile ouvert."""

    def __init__(self, elf):
        self.elf = elf
        mode = CS_MODE_64 if elf.elfclass == 64 else CS_MODE_32
        self.md = Cs(CS_ARCH_X86, mode)
        self.md.detail = True
        self._sections: list[tuple[int, int, bytes]] = []
        self._load_sections()
        self.ro_ranges = self._compute_ro_ranges()
        self.writable_ranges = self._compute_writable_ranges()
        self.got_map = self._build_got_map()
        self._plt_cache: dict[int, Optional[str]] = {}

    # ------------------------------------------------------------------ mémoire
    def _load_sections(self) -> None:
        for sec in self.elf.iter_sections():
            addr = sec["sh_addr"]
            if addr and sec["sh_type"] != "SHT_NOBITS":
                self._sections.append((addr, sec["sh_size"], sec.data()))

    def read_vaddr(self, addr: int, size: int) -> Optional[bytes]:
        """Renvoie `size` octets à l'adresse virtuelle de link `addr`, ou None."""
        for base, sz, data in self._sections:
            if base <= addr < base + sz:
                off = addr - base
                return data[off:off + size]
        return None

    def _compute_ro_ranges(self) -> list[tuple[int, int]]:
        ranges = []
        for sec in self.elf.iter_sections():
            flags = sec["sh_flags"]
            if (flags & SHF_ALLOC) and not (flags & SHF_WRITE) and not (flags & SHF_EXECINSTR):
                addr = sec["sh_addr"]
                if addr:
                    ranges.append((addr, addr + sec["sh_size"]))
        return ranges

    def _compute_writable_ranges(self) -> list[tuple[int, int]]:
        # Sections de données inscriptibles (.data, .bss) : y compris NOBITS (.bss).
        ranges = []
        for sec in self.elf.iter_sections():
            flags = sec["sh_flags"]
            if (flags & SHF_ALLOC) and (flags & SHF_WRITE):
                addr = sec["sh_addr"]
                if addr:
                    ranges.append((addr, addr + sec["sh_size"]))
        return ranges

    def is_const_ptr(self, addr: int) -> bool:
        """Vrai si `addr` tombe dans une section allouée en lecture seule."""
        return any(start <= addr < end for start, end in self.ro_ranges)

    def is_writable_data(self, addr: int) -> bool:
        """Vrai si `addr` tombe dans une section de données inscriptible (.data/.bss)."""
        return any(start <= addr < end for start, end in self.writable_ranges)

    def canon(self, reg_id: int) -> Optional[str]:
        """Registre 64 bits canonique (rdi pour edi/di/dil...), ou None si non suivi."""
        return CANON.get(self.md.reg_name(reg_id))

    # ------------------------------------------------------------------ imports
    def _build_got_map(self) -> dict[int, str]:
        """Table {adresse d'entrée GOT -> nom de la fonction importée}."""
        mapping: dict[int, str] = {}
        for secname in (".rela.plt", ".rela.dyn"):
            sec = self.elf.get_section_by_name(secname)
            if not isinstance(sec, RelocationSection):
                continue
            symtab = self.elf.get_section(sec["sh_link"])
            if not isinstance(symtab, SymbolTableSection):
                continue
            for reloc in sec.iter_relocations():
                symidx = reloc["r_info_sym"]
                if not symidx:
                    continue
                name = _clean(symtab.get_symbol(symidx).name)
                if name:
                    mapping[reloc["r_offset"]] = name
        return mapping

    def _resolve_plt_stub(self, addr: int) -> Optional[str]:
        """Nom résolu si `addr` est un stub PLT (`... jmp [rip+got]`)."""
        if addr in self._plt_cache:
            return self._plt_cache[addr]
        result = None
        code = self.read_vaddr(addr, 32)
        if code:
            for i, insn in enumerate(self.md.disasm(code, addr)):
                if i > 3:
                    break
                if insn.mnemonic in ("endbr64", "endbr32", "nop"):
                    continue
                if insn.mnemonic.endswith("jmp"):
                    for op in insn.operands:
                        if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                            got = insn.address + insn.size + op.mem.disp
                            result = self.got_map.get(got)
                    break
                break  # premier vrai insn non-jmp : ce n'est pas un stub simple
        self._plt_cache[addr] = result
        return result

    def resolve_call(self, insn) -> Optional[str]:
        """Nom de la fonction importée appelée par `insn`, ou None."""
        if not insn.mnemonic.endswith("call"):
            return None
        for op in insn.operands:
            if op.type == X86_OP_IMM:
                return self._resolve_plt_stub(op.imm)
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                got = insn.address + insn.size + op.mem.disp
                return self.got_map.get(got)
        return None

    # ---------------------------------------------------------------- fonctions
    def iter_functions(self) -> Iterator[tuple[str, int, int]]:
        """Itère (nom, adresse, taille) des fonctions définies.

        Si le binaire est strippé (pas de .symtab), renvoie une pseudo-fonction
        couvrant toute la section .text.
        """
        symtab = self.elf.get_section_by_name(".symtab")
        if isinstance(symtab, SymbolTableSection):
            for sym in symtab.iter_symbols():
                if (sym["st_info"]["type"] == "STT_FUNC"
                        and sym["st_shndx"] != "SHN_UNDEF"
                        and sym["st_value"] and sym["st_size"]):
                    yield _clean(sym.name), sym["st_value"], sym["st_size"]
        else:
            text = self.elf.get_section_by_name(".text")
            if text is not None:
                yield "(.text)", text["sh_addr"], text["sh_size"]

    def disasm_function(self, start: int, size: int):
        """Itère les instructions Capstone de la fonction [start, start+size)."""
        code = self.read_vaddr(start, size)
        if code:
            yield from self.md.disasm(code, start)
