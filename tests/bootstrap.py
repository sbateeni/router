"""Bootstrap sys.path and cwd when running tests as scripts."""

import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from core.paths import setup_project_env

setup_project_env()
