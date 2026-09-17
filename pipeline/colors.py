"""Coloration ANSI de la sortie terminal (sans dépendance).

Désactivée hors TTY, si NO_COLOR est défini ou si TERM=dumb, pour ne jamais
polluer une sortie redirigée (pipe, fichier, CI).
"""

from __future__ import annotations

import os
import sys

_CODES = {
    "reset": "0", "bold": "1", "dim": "2",
    "red": "31", "green": "32", "yellow": "33", "blue": "34", "magenta": "35",
}


def _enabled() -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return sys.stdout.isatty()


ENABLED = _enabled()


def paint(text: str, *styles: str) -> str:
    if not ENABLED or not styles:
        return text
    prefix = "".join(f"\033[{_CODES[s]}m" for s in styles if s in _CODES)
    return f"{prefix}{text}\033[0m"


_SEVERITY_STYLE = {
    "critical": ("red", "bold"),
    "high": ("red",),
    "medium": ("yellow",),
    "low": ("blue",),
    "info": ("dim",),
}

_CONFIDENCE_STYLE = {
    "confirmed": ("green", "bold"),
    "probable": ("yellow",),
    "possible": ("dim",),
}


def severity(text: str, name: str) -> str:
    return paint(text, *_SEVERITY_STYLE.get(name, ()))


def confidence(text: str, name: str) -> str:
    return paint(text, *_CONFIDENCE_STYLE.get(name, ()))


def flag(text: str, ok: bool) -> str:
    """Vert si la protection est active, rouge sinon."""
    return paint(text, "green" if ok else "red")
