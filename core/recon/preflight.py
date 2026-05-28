"""Lightweight connectivity checks (curl) before heavy scanning."""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
from typing import Any
from core.utils import ensure_parent_dir, run_cmd


def _curl(args: list[str], timeout: int = 25) -> dict[str, Any]:
    if not shutil.which("curl"):
        return {"ok": False, "error": "curl not in PATH", "stdout": "", "exit": -1}
    cmd = ["curl", "-sS", "--max-time", str(timeout), *args]
    ok, out = run_cmd(cmd, capture=True, timeout=timeout + 5)
    return {"ok": ok, "stdout": (out or "").strip(), "exit": 0 if ok else 1}


def _probe_url(url: str) -> dict[str, Any]:
    null_out = "NUL" if sys.platform == "win32" else "/dev/null"
    head = _curl(["-skI", "-o", null_out, "-w", "%{http_code}", url], timeout=20)
    body = _curl(["-sk", "--max-redirs", "3", url], timeout=25)
    code = head.get("stdout") or ""
    http_code = code if code.isdigit() else None
    return {
        "url": url,
        "http_code": http_code,
        "head_ok": bool(head.get("ok")),
        "body_ok": bool(body.get("ok")),
        "reachable": bool(head.get("ok") or body.get("ok")),
        "snippet": (body.get("stdout") or "")[:400],
    }


def run_connectivity_preflight(
    ip: str,
    target_dir: str,
    hints: dict | None = None,
) -> dict[str, Any]:
    """Run curl checks; save CONNECTIVITY.json + connectivity_preflight.txt."""
    hints = hints or {}
    host = (hints.get("host") or hints.get("domain") or ip or "").strip()
    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))

    report: dict[str, Any] = {
        "target": ip,
        "host": host,
        "checks": [],
        "external_ip": None,
        "reachable": False,
    }

    print("\n[*] Connectivity preflight (curl)...")

    for label, url in (
        ("external_ip", "https://api.ipify.org"),
        ("external_ip_alt", "https://ifconfig.me/ip"),
    ):
        r = _curl([url], timeout=15)
        if r.get("ok") and r.get("stdout"):
            report["external_ip"] = r["stdout"].splitlines()[0].strip()
            report["checks"].append({"label": label, "ok": True, "value": report["external_ip"]})
            break
        report["checks"].append({"label": label, "ok": False, "error": r.get("error") or "no response"})

    urls: list[str] = []
    seed = hints.get("seed_url") or hints.get("raw") or ""
    if seed and str(seed).startswith("http"):
        urls.append(str(seed).split()[0])
    if host:
        if not is_ip:
            urls.extend([f"https://{host}/", f"http://{host}/"])
        else:
            urls.extend([f"http://{host}/", f"https://{host}/"])

    seen: set[str] = set()
    for url in urls:
        if url in seen:
            continue
        seen.add(url)
        probe = _probe_url(url)
        report["checks"].append({"label": "target_probe", **probe})
        if probe.get("reachable"):
            report["reachable"] = True

    log_path = os.path.join(target_dir, "connectivity_preflight.txt")
    json_path = os.path.join(target_dir, "CONNECTIVITY.json")
    ensure_parent_dir(log_path)
    lines = [
        f"Target: {ip}",
        f"Host: {host}",
        f"External IP (this machine): {report.get('external_ip') or 'unknown'}",
        f"Target reachable (curl): {report['reachable']}",
        "",
    ]
    for chk in report["checks"]:
        if chk.get("label") == "target_probe":
            lines.append(f"URL: {chk.get('url')} → HTTP {chk.get('http_code')} reachable={chk.get('reachable')}")
        else:
            lines.append(f"{chk.get('label')}: ok={chk.get('ok')} {chk.get('value') or chk.get('error') or ''}")

    with open(log_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)

    status = "reachable" if report["reachable"] else "no HTTP response (firewall/down?)"
    print(f"[+] Preflight: {status} — {json_path}")
    return report
