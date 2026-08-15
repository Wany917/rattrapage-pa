"""Localisation de l'installation AFL++.

AFL++ a été compilé depuis les sources (mode GCC plugin, LLVM désactivé car
LLVM 22 casse l'instrumentation LLVM d'AFL++) dans ~/.local/opt/AFLplusplus.
On le localise via la variable d'environnement AFL_DIR/AFL_PATH, puis cet
emplacement par défaut, puis le PATH.
"""

from __future__ import annotations

import os
import shutil
from typing import Optional

_DEFAULT = os.path.expanduser("~/.local/opt/AFLplusplus")


def afl_dir() -> Optional[str]:
    """Répertoire d'AFL++ (contenant afl-fuzz), ou None si introuvable."""
    for env in ("AFL_DIR", "AFL_PATH"):
        candidate = os.environ.get(env)
        if candidate and os.path.isfile(os.path.join(candidate, "afl-fuzz")):
            return candidate
    if os.path.isfile(os.path.join(_DEFAULT, "afl-fuzz")):
        return _DEFAULT
    found = shutil.which("afl-fuzz")
    return os.path.dirname(found) if found else None


def afl_tool(name: str) -> Optional[str]:
    """Chemin complet d'un outil AFL++ (afl-cc, afl-fuzz...), ou None."""
    directory = afl_dir()
    if directory and os.path.isfile(os.path.join(directory, name)):
        return os.path.join(directory, name)
    return shutil.which(name)
