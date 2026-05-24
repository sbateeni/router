#!/usr/bin/env python3
"""Pull latest changes from GitHub for the project and external tools."""

import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
os.chdir(ROOT)

from core.paths import setup_project_env, project_root

if __name__ == "__main__":
    setup_project_env()
    from engines.updater import run_startup_update

    os.chdir(project_root())
    run_startup_update()
