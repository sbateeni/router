import sys

from core.bruteforce import run_hydra, run_web_hydra
from core.classic.context import (
    ScanContext,
    build_url,
    extract_query_urls,
    extract_service_queries,
    get_login_ports,
    get_web_ports,
    should_run_ingram,
)
from core.classic.helpers import (
    handle_keyboard_interrupt,
    is_tool_available,
    refresh_report,
    run_ffuf,
    run_gau,
    run_metasploit_search,
)
from core.exploitation import run_ingram, run_routersploit
from core.scan_config import get_profile_name, get_scan_profile
from core.scanner import run_nmap
from core.web import run_dirsearch, run_nuclei, run_searchsploit, run_sqlmap


def run_all_classic_tools(ip, target_dir, selection=1):
    """Full classic scan — all tools, no AI planning."""
    context = ScanContext()
    print(f"\n>>> PHASE 1: Scanning & Reconnaissance [{get_profile_name()}]")
    try:
        context.open_ports = run_nmap(ip, target_dir)
    except KeyboardInterrupt:
        handle_keyboard_interrupt()
        context.open_ports = []

    if not context.open_ports:
        print(f"[-] No open ports found on {ip}. Moving on to the next phases.")
        context.web_ports = []
        context.login_ports = []
    else:
        context.web_ports = get_web_ports(context.open_ports)
        context.login_ports = get_login_ports(context.open_ports)
        try:
            service_queries = extract_service_queries(context.open_ports)
            if service_queries:
                print("\n[+] Performing SearchSploit lookups based on detected services...")
                for q in service_queries:
                    if run_searchsploit(q, target_dir):
                        run_metasploit_search(q, target_dir)
        except Exception:
            pass

    refresh_report(ip, target_dir, selection, context.exploited, context, "Phase 1 - Reconnaissance")

    if context.web_ports:
        print("\n======================================================")
        print(">>> PHASE 2: Web Enumeration & Vulnerability Scanning")
        print("======================================================")
        try:
            for port in context.web_ports:
                target_url = build_url(ip, port)
                print(f"\n[*] Target URL: {target_url}")
                paths = run_dirsearch(target_url, target_dir)
                context.discovered_paths.extend(paths)
                if run_nuclei(target_url, target_dir):
                    context.exploited = True

            context.discovered_paths = list(dict.fromkeys(context.discovered_paths))
            if context.discovered_paths:
                print(f"[+] Total discovered paths: {len(context.discovered_paths)}")

            if is_tool_available("gau"):
                for port in context.web_ports:
                    context.gau_urls.extend(run_gau(build_url(ip, port), target_dir))
                context.gau_urls = list(dict.fromkeys(context.gau_urls))

            if is_tool_available("ffuf"):
                for port in context.web_ports:
                    context.ffuf_candidates.extend(run_ffuf(build_url(ip, port), target_dir))
                context.ffuf_candidates = list(dict.fromkeys(context.ffuf_candidates))

            context.discovered_urls = list(dict.fromkeys(
                context.discovered_paths + context.gau_urls + context.ffuf_candidates
            ))

            query_urls = extract_query_urls(context.discovered_urls)
            if not query_urls:
                query_urls = [build_url(ip, port) for port in context.web_ports]

            url_limit = get_scan_profile()["nuclei_url_limit"]
            if query_urls:
                print(f"\n[+] Running Nuclei on discovered URL candidates (limit: {url_limit})...")
                for target_url in query_urls[:url_limit]:
                    if run_nuclei(target_url, target_dir):
                        context.exploited = True

            print("\n[+] Running SQLMap on candidate URLs...")
            for target_url in query_urls:
                if run_sqlmap(target_url, target_dir):
                    context.exploited = True

        except KeyboardInterrupt:
            handle_keyboard_interrupt()

        refresh_report(ip, target_dir, selection, context.exploited, context, "Phase 2 - Web Enumeration")

    print("\n======================================================")
    print(">>> PHASE 3: Router & Device Exploitation")
    print("======================================================")
    try:
        if run_routersploit(ip, target_dir):
            context.exploited = True
        elif should_run_ingram(context.open_ports) and run_ingram(ip, target_dir):
            context.exploited = True
        elif not should_run_ingram(context.open_ports):
            print("[*] Skipping Ingram (target looks like a router/web UI, not a camera).")
    except KeyboardInterrupt:
        handle_keyboard_interrupt()

    refresh_report(ip, target_dir, selection, context.exploited, context, "Phase 3 - Exploitation")

    if context.login_ports or context.web_ports:
        print("\n======================================================")
        print(">>> PHASE 4: Credential Brute-Forcing (Last Resort)")
        print("======================================================")
        try:
            if context.login_ports and run_hydra(ip, context.login_ports, target_dir):
                context.exploited = True
            if context.web_ports and run_web_hydra(ip, context.web_ports, target_dir):
                context.exploited = True
        except KeyboardInterrupt:
            handle_keyboard_interrupt()

    refresh_report(ip, target_dir, selection, context.exploited, context, "Phase 4 - Brute Force")
    return context.exploited
