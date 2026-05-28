"""Fast port discovery — feeds focused Nmap in deep profile (does not bypass firewalls)."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

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


def _permission_denied(output: str) -> bool:
    low = (output or "").lower()
    return "permission denied" in low or "need to sudo" in low or "cap_net_raw" in low


def _default_interface() -> str | None:
    try:
        out = subprocess.check_output(
            ["ip", "-4", "route", "show", "default"],
            text=True,
            timeout=5,
            stderr=subprocess.DEVNULL,
        )
        for line in out.splitlines():
            parts = line.split()
            if "dev" in parts:
                idx = parts.index("dev")
                if idx + 1 < len(parts):
                    return parts[idx + 1]
    except (subprocess.SubprocessError, FileNotFoundError, ValueError):
        pass
    return None


def _masscan_base_cmd(ip: str, port_spec: str, rate: int, log_path: str) -> list[str]:
    cmd = [
        "masscan",
        ip,
        "-p",
        port_spec,
        "--rate",
        str(rate),
        "--wait",
        "3",
        "-oL",
        log_path,
    ]
    iface = get_scan_profile().get("masscan_interface") or _default_interface()
    if iface:
        cmd.extend(["-e", str(iface)])
    return cmd


def _run_masscan_cmd(cmd: list[str], timeout: int) -> tuple[bool, str]:
    ok, output = run_cmd(cmd, capture=True, timeout=timeout)
    if ok:
        return True, output or ""
    if not _permission_denied(output or ""):
        return False, output or ""

    if os.geteuid() == 0:
        return False, output or ""

    if not get_scan_profile().get("masscan_try_sudo", True) or not shutil.which("sudo"):
        return False, output or ""

    print("[*] Masscan needs raw sockets — retrying with sudo -n ...")
    sudo_cmd = ["sudo", "-n", *cmd]
    ok2, output2 = run_cmd(sudo_cmd, capture=True, timeout=timeout)
    if ok2:
        return True, output2 or ""
    combined = f"{output}\n{output2}".strip()
    return False, combined


def _print_masscan_setup_hint() -> None:
    masscan_bin = shutil.which("masscan") or "masscan"
    print(
        "[!] Masscan skipped (raw sockets). On Kali run once:\n"
        f"    sudo setcap cap_net_raw+ep $(which masscan)\n"
        f"    # or: sudo {masscan_bin} ...\n"
        "    Nmap will continue with the normal deep profile."
    )


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
    cmd = _masscan_base_cmd(ip, port_spec, rate, log_path)
    ok, output = _run_masscan_cmd(cmd, timeout)

    text = output or ""
    if os.path.isfile(log_path):
        try:
            with open(log_path, encoding="utf-8", errors="replace") as fh:
                text = fh.read() + "\n" + text
        except OSError:
            pass

    if not ok and _permission_denied(text):
        _print_masscan_setup_hint()

    ports = parse_masscan_output(text)
    payload = {
        "target": ip,
        "ports": ports,
        "port_spec": port_spec,
        "rate": rate,
        "ok": ok,
        "permission_denied": _permission_denied(text),
        "count": len(ports),
    }
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)

    if ports:
        print(f"[+] Masscan: {len(ports)} open TCP port(s) → Nmap will focus on these")
    elif not ok:
        print("[*] Masscan: no ports (permission or interface issue) — Nmap uses profile defaults")
    else:
        print("[*] Masscan: no extra ports logged (Nmap will use profile defaults)")
    return ports
