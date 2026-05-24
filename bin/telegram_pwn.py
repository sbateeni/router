#!/usr/bin/env python3
"""Shortcut — same as: python bin/master_pwn.py --telegram"""

import os
import sys

from core.paths import setup_project_env, project_root

setup_project_env()

if __name__ == "__main__":
    master = os.path.join(project_root(), "bin", "master_pwn.py")
    os.execv(sys.executable, [sys.executable, master, "--telegram"])
