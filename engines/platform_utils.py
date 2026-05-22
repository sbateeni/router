"""Cross-platform helpers (develop on Windows, run on Linux/Kali)."""

from __future__ import annotations

import os
import subprocess


def is_windows() -> bool:
    return os.name == "nt"


def is_linux() -> bool:
    return os.name == "posix" and not is_windows()


def ping_host(ip: str, timeout_ms: int = 200) -> bool:
    """Return True when the host responds to a single ping."""
    if is_windows():
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
        timeout_s = max(2, timeout_ms / 1000 + 1)
    else:
        timeout_s = max(1, (timeout_ms + 999) // 1000)
        cmd = ["ping", "-c", "1", "-W", str(timeout_s), ip]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s + 2,
            check=False,
        )
        return "ttl=" in (result.stdout or "").lower()
    except (subprocess.TimeoutExpired, OSError):
        return False


def find_chromium_binary() -> str | None:
    """Locate Chrome/Chromium for Selenium on Windows or Linux."""
    if is_windows():
        candidates = (
            os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
            os.path.expandvars(r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
            os.path.expandvars(r"%LocalAppData%\Google\Chrome\Application\chrome.exe"),
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        )
    else:
        candidates = (
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            "/usr/bin/google-chrome",
            "/snap/bin/chromium",
        )

    for path in candidates:
        if path and os.path.exists(path):
            return path
    return None
