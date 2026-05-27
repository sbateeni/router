"""Install/check dependencies for changeme + Default-Hunter in project .venv."""

from __future__ import annotations

import os
import subprocess
import sys

from core.utils import PYTHON, TOOLS_DIR

# changeme (ztgrace) — https://github.com/ztgrace/changeme
CHANGEME_PIP = (
    "cerberus>=1.3.0",
    "PyYAML>=6.0",
    "pymysql>=1.0.0",
    "psycopg2-binary>=2.9.0",
    "shodan>=1.0.0",
    "python-nmap>=0.7.0",
)

_FAIL_MARKERS = (
    "traceback (most recent call last)",
    "modulenotfounderror",
    "importerror",
    "no module named",
    "command timed out",
)


def output_failed(output: str | None) -> bool:
    if not output:
        return False
    lower = output.lower()
    return any(m in lower for m in _FAIL_MARKERS)


def _pip_install(*args: str, editable: str | None = None) -> bool:
    cmd = [PYTHON, "-m", "pip", "install", "-q"]
    if editable:
        cmd.extend(["-e", editable])
    cmd.extend(args)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if r.returncode != 0:
            err = (r.stderr or r.stdout or "").strip()
            print(f"[!] pip failed: {' '.join(cmd)}\n{err[:500]}")
            return False
        return True
    except (subprocess.TimeoutExpired, OSError) as exc:
        print(f"[!] pip install error: {exc}")
        return False


def ensure_changeme_deps() -> bool:
    try:
        import cerberus  # noqa: F401
        return True
    except ImportError:
        pass
    print("[*] Installing changeme dependencies (cerberus, pymysql, …)...")
    if not _pip_install(*CHANGEME_PIP):
        return False
    try:
        import cerberus  # noqa: F401
        print("[+] changeme dependencies OK")
        return True
    except ImportError:
        print("[!] changeme deps still missing after pip install")
        return False


def ensure_default_hunter() -> bool:
    cli_ok = False
    try:
        import default_hunter  # noqa: F401
        cli_ok = True
    except ImportError:
        pass

    dh_dir = os.path.join(TOOLS_DIR, "default-hunter")
    if not os.path.isdir(dh_dir):
        print("[*] Default-Hunter not cloned — run: bash scripts/install_tools.sh")
        return False

    if not cli_ok:
        print("[*] Installing Default-Hunter (editable from tools/default-hunter)...")
        if not _pip_install(editable=dh_dir):
            return False
        try:
            import default_hunter  # noqa: F401
        except ImportError:
            print("[!] default_hunter module still missing — check tools/default-hunter/")
            return False
    print("[+] Default-Hunter OK")
    return True


def ensure_cred_scanner_deps() -> bool:
    """Call once before changeme / Default-Hunter jobs."""
    ok_cm = ensure_changeme_deps()
    ok_dh = ensure_default_hunter()
    return ok_cm and ok_dh
