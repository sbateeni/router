"""AUTO-PWN orchestrator — prep → port attacks → finalize."""

from __future__ import annotations

from engines.auto_pwn.finalize import finalize_attack
from engines.auto_pwn.port_attack import attack_all_ports
from engines.auto_pwn.prep import build_session


def main(target_input, manual_mode=False, known_open_ports=None):
    import os

    if os.environ.get("AUTOPWN_GUI") == "1":
        from gui.bridge.input_bridge import install_gui_bridge

        install_gui_bridge()

    session = build_session(target_input, manual_mode=manual_mode, known_open_ports=known_open_ports)
    if not session:
        return
    attack_all_ports(session)
    finalize_attack(session)
