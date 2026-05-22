#!/usr/bin/env python3
"""Pull latest changes from GitHub for the project and external tools."""

import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from engines.updater import run_startup_update

if __name__ == "__main__":
    os.chdir(ROOT)
    run_startup_update()
