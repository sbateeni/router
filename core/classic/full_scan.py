import os
import re
import time

from core.bruteforce import run_hydra, run_web_hydra
from core.classic.context import (
    ScanContext,
    build_url,
    extract_query_urls,
    get_login_ports,
    get_web_ports,
)
from core.classic.helpers import (
    handle_keyboard_interrupt,
    is_tool_available,
    refresh_report,
    run_ffuf,
    run_gau,
)
from core.classic.metasploit import run_metasploit_recon
from core.exploitation import run_ingram, run_routersploit
from core.recon.target_profile import (
    build_target_profile,
    get_tool_config,
    print_target_profile,
    save_target_profile,
    should_run_tool,
)
from core.recon_tools import run_nikto, run_whatweb
from core.scan_config import get_profile_name, get_scan_profile
from core.scanner import run_nmap
from core.web import run_dirsearch, run_nuclei, run_searchsploit
from core.web.sqlmap import run_sqlmap_phase


def _phase_delay():
    time.sleep(get_scan_profile().get("phase_delay_seconds", 5))


def _sync_profile(ip, target_dir, context, phase_label):
    """Rebuild profile from all artifacts so far and persist routing plan."""
    profile = build_target_profile(ip, target_dir, context=context)
    save_target_profile(target_dir, profile)
    print(f"\n[*] Target profile updated ({phase_label}) → {os.path.join(target_dir, 'target_profile.json')}")
    print_target_profile(profile)
    return profile


def run_all_classic_tools(ip, target_dir, selection=1):
    """Full classic scan — tools chosen from live target profile after each phase."""
    context = ScanContext()
    profile = {}

    print(f"\n>>> PHASE 1: Scanning & Reconnaissance [{get_profile_name()}]")
    try:
        context.open_ports = run_nmap(ip, target_dir)
    except KeyboardInterrupt:
        handle_keyboard_interrupt()
        context.open_ports = []

    if not context.open_ports:
        print(f"[-] No open ports found on {ip}.")
        context.web_ports = []
        context.login_ports = []
    else:
        context.web_ports = get_web_ports(context.open_ports)
        context.login_ports = get_login_ports(context.open_ports)

    profile = _sync_profile(ip, target_dir, context, "after Nmap")

    try:
        if should_run_tool(profile, "whatweb"):
            for port in profile.get("web_ports") or context.web_ports:
                run_whatweb(build_url(ip, port), target_dir)

        if should_run_tool(profile, "searchsploit"):
            queries = get_tool_config(profile, "searchsploit").get("queries") or profile.get("searchsploit_queries", [])
            if queries:
                print(f"\n[+] SearchSploit ({len(queries)} queries from profile)...")
                first = True
                for q in queries:
                    run_searchsploit(q, target_dir, append=not first)
                    first = False

        if should_run_tool(profile, "metasploit"):
            vendor = profile.get("vendor")
            run_metasploit_recon(ip, target_dir, context.open_ports, vendor=vendor)
        else:
            print("[*] Metasploit skipped by target profile (not a router/Fortinet CPE fingerprint).")

        if should_run_tool(profile, "nikto"):
            for port in profile.get("web_ports") or []:
                run_nikto(build_url(ip, port), target_dir)
    except Exception as exc:
        print(f"[!] Phase 1 optional tools error: {exc}")

    refresh_report(ip, target_dir, selection, context.exploited, context, "Phase 1 - Reconnaissance")
    profile = _sync_profile(ip, target_dir, context, "after Phase 1")
    _phase_delay()

    web_ports = profile.get("web_ports") or context.web_ports
    if web_ports:
        print("\n======================================================")
        print(">>> PHASE 2: Web Enumeration (profile-driven)")
        print("======================================================")
        try:
            if should_run_tool(profile, "dirsearch"):
                for port in web_ports:
                    target_url = build_url(ip, port)
                    print(f"\n[*] Dirsearch → {target_url}")
                    context.discovered_paths.extend(run_dirsearch(target_url, target_dir))
            else:
                print("[*] Dirsearch skipped by profile.")

            profile = _sync_profile(ip, target_dir, context, "after Dirsearch")

            if should_run_tool(profile, "gau") and is_tool_available("gau"):
                for port in web_ports:
                    context.gau_urls.extend(run_gau(build_url(ip, port), target_dir))
                context.gau_urls = list(dict.fromkeys(context.gau_urls))

            if should_run_tool(profile, "ffuf") and is_tool_available("ffuf"):
                for port in web_ports:
                    context.ffuf_candidates.extend(run_ffuf(build_url(ip, port), target_dir))
                context.ffuf_candidates = list(dict.fromkeys(context.ffuf_candidates))

            context.discovered_paths = list(dict.fromkeys(context.discovered_paths))
            context.discovered_urls = list(dict.fromkeys(
                context.discovered_paths + context.gau_urls + context.ffuf_candidates
            ))

            profile = _sync_profile(ip, target_dir, context, "after path discovery")

            nuclei_cfg = get_tool_config(profile, "nuclei")
            if should_run_tool(profile, "nuclei"):
                tags = nuclei_cfg.get("tags")
                query_urls = extract_query_urls(context.discovered_urls)
                if not query_urls:
                    query_urls = [build_url(ip, port) for port in web_ports]
                url_limit = get_scan_profile()["nuclei_url_limit"]
                print(f"\n[+] Nuclei on {min(len(query_urls), url_limit)} URL(s), tags={tags}")
                for target_url in query_urls[:url_limit]:
                    if run_nuclei(target_url, target_dir, tags=tags):
                        context.exploited = True
            else:
                print(f"[*] Nuclei skipped: {nuclei_cfg.get('reason', '')}")

            sql_cfg = get_tool_config(profile, "sqlmap")
            if should_run_tool(profile, "sqlmap"):
                print("\n[+] SQLMap (URLs from profile)...")
                if run_sqlmap_phase(ip, web_ports, context.discovered_urls, target_dir):
                    context.exploited = True
            else:
                print(f"[*] SQLMap skipped: {sql_cfg.get('reason', '')}")

        except KeyboardInterrupt:
            handle_keyboard_interrupt()

        refresh_report(ip, target_dir, selection, context.exploited, context, "Phase 2 - Web Enumeration")
        profile = _sync_profile(ip, target_dir, context, "after Phase 2")
    _phase_delay()

    print("\n======================================================")
    print(">>> PHASE 3: Exploitation (profile-driven)")
    print("======================================================")
    try:
        if should_run_tool(profile, "routersploit"):
            if run_routersploit(ip, target_dir):
                context.exploited = True
        else:
            print(f"[*] RouterSploit skipped: {get_tool_config(profile, 'routersploit').get('reason', '')}")

        if should_run_tool(profile, "ingram"):
            if run_ingram(ip, target_dir):
                context.exploited = True
        else:
            print(f"[*] Ingram skipped: {get_tool_config(profile, 'ingram').get('reason', '')}")
    except KeyboardInterrupt:
        handle_keyboard_interrupt()

    refresh_report(ip, target_dir, selection, context.exploited, context, "Phase 3 - Exploitation")
    profile = _sync_profile(ip, target_dir, context, "after Phase 3")
    _phase_delay()

    if (profile.get("login_ports") or context.login_ports or profile.get("login_paths")) and should_run_tool(profile, "hydra"):
        print("\n======================================================")
        print(">>> PHASE 4: Credential Brute-Force (profile-driven)")
        print("======================================================")
        try:
            if context.login_ports and run_hydra(ip, context.login_ports, target_dir):
                pass
            hydra_cfg = get_tool_config(profile, "hydra")
            forms = hydra_cfg.get("http_forms")
            hydra_plan = {"http_forms": forms, "source": "target_profile"} if forms else None
            if context.web_ports and run_web_hydra(ip, context.web_ports, target_dir, hydra_plan=hydra_plan):
                pass
        except KeyboardInterrupt:
            handle_keyboard_interrupt()
    else:
        print("[*] Hydra skipped by target profile or no login surface.")

    _, confirmed = refresh_report(ip, target_dir, selection, context.exploited, context, "Phase 4 - Brute Force")
    _sync_profile(ip, target_dir, context, "final")
    return confirmed
