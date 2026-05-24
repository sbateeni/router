"""Add repo root to sys.path — import this before core/engines (bin/*.py)."""

import os
import sys


def install() -> str:
    root = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    if root not in sys.path:
        sys.path.insert(0, root)
    os.chdir(root)
    return root
