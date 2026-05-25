#!/usr/bin/env python3
"""Shortcut — same as: python bin/telegram_daemon.py"""

import os
import sys

import _bootstrap

_bootstrap.install()

from core.paths import setup_project_env, project_root

setup_project_env()

if __name__ == "__main__":
    daemon = os.path.join(project_root(), "bin", "telegram_daemon.py")
    os.execv(sys.executable, [sys.executable, daemon])
