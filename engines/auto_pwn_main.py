"""
Device Engine entry point — backward-compatible facade.

Modules:
  engines/auto_pwn/prep.py        — history, OSINT, port discovery
  engines/auto_pwn/port_attack.py — per-port fingerprint + exploits
  engines/auto_pwn/finalize.py    — RTSP, SSH, pivot, loot
  engines/auto_pwn/cli.py         — interactive menu
  engines/auto_pwn/runner.py      — main() orchestrator
"""

import sys

from core.paths import project_root

_ROOT = project_root()
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from engines.auto_pwn.runner import main  # noqa: E402

__all__ = ["main"]

if __name__ == "__main__":
    from engines.auto_pwn.cli import run_cli
    run_cli()
