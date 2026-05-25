#!/usr/bin/env python3
"""Telegram bot only — no git update, no tool install (for run.sh background)."""

import sys

import _bootstrap

_bootstrap.install()

from core.paths import setup_project_env, project_root
from core.notify import load_dotenv
from core.telegram_bot import run_telegram_bot

setup_project_env()


def main():
    base = project_root()
    load_dotenv(base)
    print("[*] Telegram daemon starting...", flush=True)
    return run_telegram_bot(base)


if __name__ == "__main__":
    raise SystemExit(main())
