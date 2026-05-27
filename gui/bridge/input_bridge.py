"""Replace builtins.input when running scans from the PyQt6 GUI."""

from __future__ import annotations

import builtins
from typing import Callable

_original_input = builtins.input
_handler: Callable[[str], str] | None = None
_installed = False


def set_gui_input_handler(handler: Callable[[str], str] | None) -> None:
    global _handler
    _handler = handler


def _default_gui_input(prompt: str = "") -> str:
    pl = (prompt or "").lower()
    if "pivot" in pl or "subnet" in pl or "discover and attack other" in pl:
        return "n"
    if "quit" in pl and "pivot" in pl:
        return "q"
    if "press enter" in pl:
        return ""
    if "proceed" in pl or "full attack" in pl:
        return "y"
    if "exploit" in pl and "(y/n)" in pl:
        return "n"
    if "credentials to log in" in pl:
        return "y"
    if "choose tool id" in pl or "choose:" in pl:
        return "0"
    return ""


def gui_input(prompt: str = "") -> str:
    if _handler is not None:
        try:
            return _handler(prompt)
        except Exception:
            pass
    return _default_gui_input(prompt)


def install_gui_bridge() -> None:
    global _installed
    if _installed:
        return
    builtins.input = gui_input
    _installed = True


def uninstall_gui_bridge() -> None:
    global _installed
    builtins.input = _original_input
    _installed = False
