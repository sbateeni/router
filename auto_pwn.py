#!/usr/bin/env python3
"""Standalone device AUTO-PWN (cameras + routers) — run from project root."""

import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from engines.auto_pwn_main import main  # noqa: E402

if __name__ == "__main__":
    main()
