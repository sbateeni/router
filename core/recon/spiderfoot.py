"""SpiderFoot OSINT — passive modules with timeout (tools/spiderfoot or system sf)."""

from __future__ import annotations

import json
import os
import shutil
import sys

from core.paths import project_root
from core.utils import ensure_parent_dir, run_cmd

PYTHON = sys.executable

# Passive / light modules (avoid aggressive port scan modules that duplicate Nmap/Masscan)
_PASSIVE_MODULES = (
    "sfp_dnsresolve,sfp_whois,sfp_crt,sfp_subdomain,sfp_hackertarget,"
    "sfp_email,sfp_bingsearch,sfp_crossref"
)
_IP_MODULES = "sfp_dnsresolve,sfp_whois,sfp_shodan,sfp_ipwhois"


def _spiderfoot_cmd() -> list[str] | None:
    root = project_root()
    sf_py = os.path.join(root, "tools", "spiderfoot", "sf.py")
    if os.path.isfile(sf_py):
        return [PYTHON, sf_py]
    for name in ("spiderfoot", "sfcli"):
        path = shutil.which(name)
        if path:
            return [path]
    return None


def run_spiderfoot_passive(target: str, target_dir: str, *, is_ip: bool = False) -> dict:
    """Run SpiderFoot CLI; write SPIDERFOOT.json + spiderfoot_scan.txt."""
    cmd_base = _spiderfoot_cmd()
    out: dict = {"target": target, "ok": False, "modules": _IP_MODULES if is_ip else _PASSIVE_MODULES}

    if not cmd_base:
        print("[!] SpiderFoot not found — clone via scripts/install_tools.sh or: sudo apt install spiderfoot")
        out["error"] = "not_installed"
        _save(out, target_dir)
        return out

    log_path = os.path.join(target_dir, "spiderfoot_scan.txt")
    json_path = os.path.join(target_dir, "SPIDERFOOT.json")
    ensure_parent_dir(log_path)

    modules = out["modules"]
    timeout = 300 if is_ip else 420
    print(f"\n[*] SpiderFoot passive OSINT on {target} (timeout={timeout}s)...")

    cmd = cmd_base + [
        "-t", target,
        "-m", modules,
        "-o", "tab",
        "-q",
    ]
    ok, output = run_cmd(cmd, capture=True, log_file=log_path, timeout=timeout)
    out["ok"] = ok
    out["output_lines"] = len((output or "").splitlines())
    if output:
        out["preview"] = (output[:2000] + "...") if len(output) > 2000 else output

    _save(out, target_dir, log_path=log_path if os.path.isfile(log_path) else None)
    print(f"[{'+'if ok else '!'}] SpiderFoot finished → {json_path}")
    return out


def _save(data: dict, target_dir: str, log_path: str | None = None) -> None:
    json_path = os.path.join(target_dir, "SPIDERFOOT.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    if log_path and os.path.isfile(log_path) and not data.get("preview"):
        try:
            with open(log_path, encoding="utf-8", errors="replace") as fh:
                data["preview"] = fh.read()[:2000]
            with open(json_path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, ensure_ascii=False)
        except OSError:
            pass
