#!/usr/bin/env python3
"""
Open VLC for each configured camera (one window per IP).

RTSP passwords with @ must be URL-encoded: @ -> %40

Usage:
  python open_vlc_cameras.py
  python open_vlc_cameras.py --sub
  python open_vlc_cameras.py --print-only
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from urllib.parse import quote

import _bootstrap

_bootstrap.install()

from core.paths import setup_project_env

setup_project_env()

# Edit this list with your own cameras (host, user, password, label)
CAMERAS: list[tuple[str, str, str, str]] = [
    # ("192.168.1.100", "admin", "your_password", "Camera-1"),
]


def rtsp_url(host: str, user: str, password: str, stream_suffix: str) -> str:
    pw = quote(password, safe="")
    return f"rtsp://{user}:{pw}@{host}:554/Streaming/Channels/1{stream_suffix}"


def find_vlc() -> str | None:
    from engines.vlc_utils import find_vlc as _find_vlc

    return _find_vlc()


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    p = argparse.ArgumentParser(description="Open one VLC window per camera")
    p.add_argument("--sub", action="store_true", help="Use sub-stream (102) instead of main (101)")
    p.add_argument("--print-only", action="store_true", help="Print URLs only, do not launch VLC")
    args = p.parse_args()

    if not CAMERAS:
        print("[!] No cameras configured. Edit CAMERAS in open_vlc_cameras.py", file=sys.stderr)
        return 1

    suffix = "02" if args.sub else "01"
    vlc = find_vlc()

    print(f"[*] {len(CAMERAS)} camera(s) — stream 1{suffix} each\n")

    for host, user, password, label in CAMERAS:
        url = rtsp_url(host, user, password, suffix)
        print(f"[{label}]")
        print(f"  {url}\n")
        if args.print_only:
            continue
        if not vlc:
            print("  [!] VLC not found — copy URL into VLC manually\n", file=sys.stderr)
            continue
        subprocess.Popen([vlc, url])
        print("  [+] VLC started\n")

    if not args.print_only and not vlc:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
