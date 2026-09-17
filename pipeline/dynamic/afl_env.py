"""Localisation de l'installation AFL++."""

from __future__ import annotations

import os
import shutil
from typing import Optional

_DEFAULT = os.path.expanduser("~/.local/opt/AFLplusplus")


def afl_dir() -> Optional[str]:
    for env in ("AFL_DIR", "AFL_PATH"):
        candidate = os.environ.get(env)
        if candidate and os.path.isfile(os.path.join(candidate, "afl-fuzz")):
            return candidate
    if os.path.isfile(os.path.join(_DEFAULT, "afl-fuzz")):
        return _DEFAULT
    found = shutil.which("afl-fuzz")
    return os.path.dirname(found) if found else None


def afl_tool(name: str) -> Optional[str]:
    directory = afl_dir()
    if directory and os.path.isfile(os.path.join(directory, name)):
        return os.path.join(directory, name)
    return shutil.which(name)
