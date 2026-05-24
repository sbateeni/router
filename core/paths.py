"""Project root resolution — all entry scripts should call setup_project_env()."""

import os
import sys

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def project_root() -> str:
    return _PROJECT_ROOT


def setup_project_env() -> str:
    """Add repo root to sys.path and chdir so relative paths (tools/, targets/) work."""
    root = project_root()
    if root not in sys.path:
        sys.path.insert(0, root)
    os.chdir(root)
    os.makedirs(os.path.join(root, "logs"), exist_ok=True)
    return root


def logs_dir() -> str:
    path = os.path.join(project_root(), "logs")
    os.makedirs(path, exist_ok=True)
    return path
