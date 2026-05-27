#!/usr/bin/env python3
"""Apply RouterSploit wordlists patch (setuptools 82+ compat)."""
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from core.routersploit_patch import patch_routersploit_wordlists, wordlists_path


def main():
    path = wordlists_path()
    if not os.path.isfile(path):
        print(f"[i] RouterSploit wordlists not found: {path}")
        print("[i] Run: bash scripts/install_tools.sh")
        return 1
    if patch_routersploit_wordlists():
        print("[+] RouterSploit wordlists patched (importlib.resources)")
        return 0
    print(f"[!] Failed to patch: {path}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
