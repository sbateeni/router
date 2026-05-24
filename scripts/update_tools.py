#!/usr/bin/env python3
"""Pull latest changes from GitHub for the project and external tools."""

import os

from core.paths import setup_project_env, project_root

if __name__ == "__main__":
    setup_project_env()
    from engines.updater import run_startup_update

    os.chdir(project_root())
    run_startup_update()
