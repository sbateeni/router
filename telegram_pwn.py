#!/usr/bin/env python3
"""Shortcut — same as: python3 master_pwn.py --telegram"""

import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)

if __name__ == "__main__":
    os.execv(sys.executable, [sys.executable, os.path.join(BASE, "master_pwn.py"), "--telegram"])
