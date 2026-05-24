import sys

from core.paths import setup_project_env

setup_project_env()

from engines.lan_scanner import LANScanner
from engines.auto_pwn_main import main as start_pwn


def run_lan_mode():
    scanner = LANScanner()
    print(f"[*] Your Local IP: {scanner.local_ip}")
    print("[*] Scanning your local network for cameras and routers... Please wait.")

    devices = scanner.run_scan()
    selected = scanner.display_results()

    if selected:
        target_url = f"http://{selected['ip']}:{selected['port']}"
        print(f"\n[!] Target Selected: {target_url}")
        print("[!] Redirecting to AUTO-PWN Engine...\n")
        start_pwn(target_url)
    else:
        print("\n[!] LAN Scan ended without selection.")


if __name__ == "__main__":
    run_lan_mode()
