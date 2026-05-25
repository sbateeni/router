#!/usr/bin/env python3
"""Diagnose .env Telegram settings on this machine (run on Kali after git pull)."""

import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from core.paths import setup_project_env, project_root
from core.notify import explain_telegram_config, load_telegram_env, telegram_configured, telegram_placeholder_keys_present

setup_project_env()


def main():
    base = project_root()
    print(explain_telegram_config(base))
    load_telegram_env(base)
    if telegram_configured() and not telegram_placeholder_keys_present():
        print("\n[+] Telegram env OK — run: bash run.sh")
        return 0
    print("\n[!] Fix .env then: bash run.sh")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
