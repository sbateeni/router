"""Fast port discovery — feeds focused Nmap in deep profile (does not bypass firewalls)."""

from __future__ import annotations

import json
import os
import re
import shutil

from core.scan_config import get_scan_profile
from core.utils import ensure_parent_dir, run_cmd


def parse_masscan_output(text: str) -> list[int]:
    ports: list[int] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("open"):
            parts = line.split()
            if len(parts) >= 3 and parts[1] == "tcp":
                try:
                    ports.append(int(parts[2]))
                except ValueError:
                    pass
            continue
        m = re.match(r"^(\d+)/tcp\s+open", line)
        if m:
            ports.append(int(m.group(1)))
    return sorted(set(ports))


def run_masscan_discovery(ip: str, target_dir: str) -> list[int]:
    """Run masscan when enabled in profile; return open TCP ports (may be empty)."""
    profile = get_scan_profile()
    if not profile.get("masscan_enabled"):
        return []

    if not shutil.which("masscan"):
        print("[!] masscan not in PATH — skip (install: sudo apt install masscan)")
        return []

    port_spec = str(profile.get("masscan_ports", "1-1000"))
    rate = int(profile.get("masscan_rate", 800))
    timeout = int(profile.get("masscan_timeout", 180))

    log_path = os.path.join(target_dir, "masscan_scan.txt")
    json_path = os.path.join(target_dir, "MASSCAN_PORTS.json")
    ensure_parent_dir(log_path)

    print(f"\n[*] Masscan quick discovery on {ip} (ports={port_spec}, rate={rate})...")
    cmd = [
        "masscan",
        ip,
        "-p", port_spec,
        "--rate", str(rate),
        "--wait", "3",
        "-oL", log_path,
    ]
    ok, output = run_cmd(cmd, capture=True, log_file=log_path, timeout=timeout)

    text = output or ""
    if os.path.isfile(log_path):
        try:
            with open(log_path, encoding="utf-8", errors="replace") as fh:
                text = fh.read() + "\n" + text
        except OSError:
            pass

    ports = parse_masscan_output(text)
    payload = {
        "target": ip,
        "ports": ports,
        "port_spec": port_spec,
        "rate": rate,
        "ok": ok,
        "count": len(ports),
    }
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)

    if ports:
        print(f"[+] Masscan: {len(ports)} open TCP port(s) → Nmap will focus on these")
    else:
        print("[*] Masscan: no extra ports logged (Nmap will use profile defaults)")
    return ports
