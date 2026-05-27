"""Interactive CLI menu for Device Engine (GEMINI edition)."""

from __future__ import annotations

import json
import os
import sys

from core.paths import setup_project_env
from engines.auto_pwn.runner import main as run_auto_pwn
from engines.lan_scanner import LANScanner
from engines.utils import clear_logs, log
from engines.updater import run_startup_update


def run_cli() -> None:
    setup_project_env()

    if os.environ.get("NUCLEI_SKIP_UPDATE") != "1":
        run_startup_update()
    clear_logs()
    print("\n==================================================")
    print("      NUCLEI AUTO-PWN SYSTEM - GEMINI EDITION")
    print("==================================================\n")

    while True:
        target = ""
        lan_known_ports = None
        while True:
            print("\n  [1] Enter Target URL manually")
            print("  [2] Scan Local Network (LAN) to find targets")
            print("  [3] Show Previous Targets (History)")
            print("  [4] Update Exploit Arsenal (GitHub Zero-Day Scraper)")
            print("  [5] Social OSINT (Email / Phone / Username Lookup)")
            print("  [6] Decepticon Mode (Autonomous Kill-Chain)")
            print("  [7] Update Framework & Tools (GitHub Pull)")
            print("  [0] Exit")
            start_choice = input("\n[?] Select option: ").strip()

            if start_choice == "0":
                print("Exiting...")
                sys.exit(0)
            if start_choice == "1":
                target = input("[?] Enter Target URL: ").strip()
                if target:
                    break
            elif start_choice == "2":
                target, lan_known_ports = _lan_device_picker()
                if target:
                    break
            elif start_choice == "3":
                target = _history_picker()
                if target:
                    break
            elif start_choice == "4":
                _run_zero_day_scraper()
            elif start_choice == "5":
                from engines.social_osint import run_social_osint_menu
                run_social_osint_menu()
            elif start_choice == "6":
                t = input("[?] Enter Target URL or IP for Decepticon Mode: ").strip()
                if t:
                    from engines.decepticon_core import DecepticonCore
                    DecepticonCore(t).run_autonomous_mode()
            elif start_choice == "7":
                log("Checking for Framework and Tools Updates from GitHub...", "INFO")
                run_startup_update(update_project=True, update_tools=True, update_templates=True)
                input("\nPress Enter to return to the main menu...")
            else:
                log("Invalid option. Please choose 1, 2, 3, 4, 5, 6, 7, or 0.", "ERROR")

        if not target:
            continue

        manual = _pick_execution_mode()
        if manual is None:
            continue
        if not target.startswith("http"):
            target = "http://" + target
        try:
            run_auto_pwn(target, manual_mode=manual, known_open_ports=lan_known_ports)
        except KeyboardInterrupt:
            log("\nExecution interrupted by user. Returning to main menu...", "WARNING")
        except Exception as exc:
            log(f"\nAn error occurred during execution: {exc}", "ERROR")
        input("\nPress Enter to return to the main menu...")


def _pick_execution_mode():
    """Return True=manual, False=auto, None=back to main menu."""
    while True:
        print("\n[M] Select Execution Mode:")
        print("    [1] FULL AUTO-PWN (Everything automatically)")
        print("    [2] EXPERT MANUAL (Choose tools manually)")
        print("    [0] Back to Main Menu")
        mode = input("\n[?] Select mode [1/2/0]: ").strip()
        if mode == "0":
            return None
        if mode == "1":
            return False
        if mode == "2":
            return True
        log("Invalid mode. Please choose 1, 2, or 0.", "ERROR")


def _lan_device_picker():
    scanner = LANScanner()
    devices = scanner.run_scan()
    if not devices:
        log("No devices found on LAN. Try manual entry.", "ERROR")
        return "", None

    print("\n" + "=" * 100)
    print("      SELECT DEVICE TO START AUTO-PWN")
    print("      (nmap -sV + vendor + services — see logs/lan_engine_devices.json)")
    print("=" * 100)
    from engines.lan_scanner import format_device_line

    for i, dev in enumerate(devices, start=1):
        print(format_device_line(dev, i))
    print("=" * 100)

    while True:
        idx = input("\n[?] Select Device ID (or 'b' to go back): ").strip()
        if idx.lower() == "b":
            return "", None
        try:
            dev = devices[int(idx) - 1]
            return dev.get("url") or f"http://{dev['ip']}", dev.get("open_ports") or []
        except (ValueError, IndexError):
            log("Invalid ID. Please try again.", "ERROR")


def _history_picker() -> str:
    db_dir = "db"
    if not os.path.isdir(db_dir):
        log("No previous targets found.", "ERROR")
        return ""
    history_files = [f for f in os.listdir(db_dir) if f.endswith(".json")]
    if not history_files:
        log("No previous targets found.", "ERROR")
        return ""

    print("\n" + "=" * 60)
    print("      PREVIOUS TARGETS HISTORY")
    print("=" * 60)
    targets_list = []
    for i, file_name in enumerate(history_files):
        try:
            with open(os.path.join(db_dir, file_name), encoding="utf-8") as fh:
                data = json.load(fh)
            ip = data.get("ip", file_name.replace(".json", ""))
            status = data.get("status", "UNKNOWN")
            targets_list.append(ip)
            print(f"  [{i + 1}] IP: {ip:<15} | Status: {status:<10}")
        except OSError:
            pass
    print("=" * 60)

    while True:
        idx = input("\n[?] Select Target ID to resume (or 'b' to go back): ").strip()
        if idx.lower() == "b":
            return ""
        try:
            return "http://" + targets_list[int(idx) - 1]
        except (ValueError, IndexError):
            log("Invalid ID. Please try again.", "ERROR")


def _run_zero_day_scraper() -> None:
    log("Launching GitHub Zero-Day PoC Scraper...", "INFO")
    from engines.zero_day_scraper import ZeroDayScraper
    found = ZeroDayScraper().search_and_download()
    if found:
        log(f"Scraper finished. {len(found)} repositories found/updated.", "SUCCESS")
    else:
        log("Scraper finished. No new PoCs found.", "INFO")
    input("\nPress Enter to return to the main menu...")
