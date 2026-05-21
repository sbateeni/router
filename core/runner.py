import sys
import os
import re
import shutil

from core.scanner import run_nmap
from core.utils import run_cmd
from core.web_enum import run_nuclei, run_dirsearch, run_sqlmap, run_searchsploit
from core.exploitation import run_routersploit_with_ai_followup, run_ingram
from core.bruteforce import run_hydra, run_web_hydra
from core.scan_config import set_scan_profile, get_profile_name
from core.context_store import save_scan_context
from core.report import generate_scan_report
from core.ai_planner import plan_scan_tools, recommend_hydra_commands


class ScanContext:
    def __init__(self):
        self.open_ports = []
        self.web_ports = []
        self.login_ports = []
        self.discovered_paths = []
        self.discovered_urls = []
        self.nuclei_findings = []
        self.sqlmap_targets = []
        self.ffuf_candidates = []
        self.gau_urls = []
        self.exploited = False
        self.ai_scan_plan = {}
        self.ai_hydra_plan = {}


def is_tool_available(tool_name):
    return shutil.which(tool_name) is not None


def build_url(ip, port):
    return f"http://{ip}:{port}" if port not in [443, 8443] else f"https://{ip}:{port}"


def normalize_url(url):
    return url.rstrip("/")


def extract_query_urls(urls):
    return [u for u in urls if "?" in u]


def extract_service_queries(open_ports):
    """Create a list of service/product query strings from nmap results for searchsploit lookups."""
    queries = set()
    for p in open_ports:
        if not isinstance(p, dict):
            continue
        if p.get("port") == 0:
            vendor = p.get("vendor") or p.get("service")
            if vendor:
                queries.add(vendor.split()[0])
            continue
        svc = p.get("service", "")
        if not svc:
            continue
        parts = svc.split()
        if len(parts) >= 2:
            queries.add(f"{parts[0]} {parts[1]}")
        queries.add(parts[0])
    return list(queries)


def run_metasploit_search(query, target_dir):
    """Run a safe msfconsole search for modules matching the query and save output."""
    if not shutil.which("msfconsole"):
        print("[!] Metasploit (msfconsole) not found; skipping Metasploit lookup.")
        return False
    generic_queries = {"http", "https", "ssl", "tcp", "nginx", "httpd"}
    if query.lower().strip() in generic_queries:
        print(f"[*] Skipping generic Metasploit search for '{query}'.")
        return False
    log_file = os.path.join(target_dir, "msf_search.txt")
    # run msfconsole in quiet mode and run a search command then exit
    msf_cmd = f"search {query}; exit"
    command = ["msfconsole", "-q", "-x", msf_cmd]
    success, output = run_cmd(command, capture=True, log_file=log_file)
    if output:
        print(output)
        print(f"[+] Metasploit search results saved to: {log_file}")
        return True
    return False


def run_gau(target_url, target_dir):
    if not is_tool_available("gau"):
        print("[!] gau is not installed; skipping GAU enumeration.")
        return []

    print("[+] Running GAU to gather historical URLs...")
    domain = re.sub(r"^https?://", "", target_url).split("/")[0]
    log_file = os.path.join(target_dir, "gau_urls.txt")
    command = ["gau", domain]
    success, output = run_cmd(command, capture=True, log_file=log_file)
    urls = []
    if output:
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("http://") or line.startswith("https://"):
                urls.append(line)
    urls = list(dict.fromkeys(urls))
    if urls:
        print(f"[+] GAU found {len(urls)} URLs.")
    return urls


def find_common_wordlist():
    from core.scan_config import get_scan_profile
    profile = get_scan_profile()
    if profile["ffuf_wordlist"] == "medium":
        candidates = [
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
        ]
    else:
        candidates = [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/wordlists/rockyou.txt",
        ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


def refresh_report(ip, target_dir, selection, exploited, context, phase):
    save_scan_context(target_dir, context, phase, get_profile_name(), exploited)
    report_path = generate_scan_report(
        ip, target_dir, selection, exploited, current_phase=phase, profile=get_profile_name()
    )
    print(f"[*] Report updated after {phase}: {report_path}")
    return report_path


def run_ffuf(target_url, target_dir):
    from core.scan_config import get_scan_profile
    profile = get_scan_profile()
    if not is_tool_available("ffuf"):
        print("[!] ffuf is not installed; skipping FFUF enumeration.")
        return []

    wordlist = find_common_wordlist()
    if not wordlist:
        print("[!] No common wordlist found for ffuf; skipping.")
        return []

    print("[+] Running ffuf for hidden content discovery...")
    port = target_url.split(":")[-1] if ":" in target_url.replace("https://", "").replace("http://", "") else "80"
    json_file = os.path.join(target_dir, f"ffuf_port_{port}.json")
    stdout_log = os.path.join(target_dir, f"ffuf_port_{port}_stdout.txt")
    fuzz_url = normalize_url(target_url) + "/FUZZ"
    command = [
        "ffuf", "-u", fuzz_url, "-w", wordlist,
        "-t", str(profile["ffuf_threads"]), "-s",
        "-o", json_file, "-of", "json",
        "-mc", "200,204,301,302,307,401,403,405,500",
    ]
    success, output = run_cmd(command, capture=True, log_file=stdout_log)
    if not success:
        print(f"[-] ffuf failed for {target_url}. Check {stdout_log}")

    urls = []
    if os.path.exists(json_file):
        try:
            import json
            with open(json_file, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read().strip()
                if content:
                    data = json.loads(content)
                    for result in data.get("results", []):
                        url = result.get("url")
                        if url:
                            urls.append(url)
                            continue
                        fuzz_value = result.get("input", {}).get("FUZZ")
                        if fuzz_value:
                            urls.append(normalize_url(target_url) + "/" + fuzz_value.lstrip("/"))
        except Exception:
            pass
    urls = list(dict.fromkeys(urls))
    if urls:
        print(f"[+] ffuf discovered {len(urls)} paths.")
    return urls



def prompt_next_stage():
    while True:
        choice = input("\n[!] Ctrl+C detected. Do you want to skip the current phase and continue to the next stage? [Y/n] ").strip().lower()
        if choice in ("", "y", "yes"):
            return True
        if choice in ("n", "no", "q", "quit", "exit"):
            return False
        print("Please enter 'y' to continue or 'n' to exit.")


def select_tool_menu():
    print("\nAvailable tools:")
    print("  1) All tools")
    print("  2) Nmap scan only")
    print("  3) Nuclei only")
    print("  4) Dirsearch only")
    print("  5) SQLMap only")
    print("  6) RouterSploit only")
    print("  7) Ingram only")
    print("  8) Hydra only")
    print("  9) FFUF only (optional)")
    print(" 10) GAU only (optional)")
    print(" 11) Exit")

    valid_choices = {str(i) for i in range(1, 12)}
    while True:
        choice = input("Select an option [1-11]: ").strip()
        if choice in valid_choices:
            return int(choice)
        print("Please enter a number between 1 and 11.")


def get_web_ports(open_ports):
    ports = []
    for p in open_ports:
        if not isinstance(p, dict) or not p.get("port"):
            continue
        if p["port"] in [80, 443, 8080, 8443] or "http" in p["service"].lower():
            ports.append(p["port"])
    return ports


def get_login_ports(open_ports):
    login = []
    for p in open_ports:
        if not isinstance(p, dict) or not p.get("port"):
            continue
        if p["port"] in [21, 22, 23] or p["service"].lower().split()[0] in ["ssh", "ftp", "telnet"]:
            login.append(p)
    return login


def run_nmap_only(ip, target_dir):
    print("\n>>> TOOL: Nmap scan only")
    run_nmap(ip, target_dir)
    return False


def run_nuclei_only(ip, target_dir):
    open_ports = run_nmap(ip, target_dir)
    if not open_ports:
        return False
    web_ports = get_web_ports(open_ports)
    if not web_ports:
        # Fallback to common web ports and common camera/web-UI ports if nmap didn't identify any
        camera_ports = [81, 8000, 8001, 8081, 9000, 37777, 5000]
        default_ports = [80, 443, 8080, 8443]
        web_ports = default_ports + camera_ports
        print(f"[!] No web ports detected by Nmap; falling back to ports for Nuclei: {web_ports}")
    for port in web_ports:
        target_url = f"http://{ip}:{port}" if port not in [443, 8443] else f"https://{ip}:{port}"
        if run_nuclei(target_url, target_dir):
            return True
    return False


def run_dirsearch_only(ip, target_dir):
    open_ports = run_nmap(ip, target_dir)
    if not open_ports:
        return False
    web_ports = get_web_ports(open_ports)
    if not web_ports:
        print("[-] No web ports found for Dirsearch.")
        return False
    for port in web_ports:
        target_url = f"http://{ip}:{port}" if port not in [443, 8443] else f"https://{ip}:{port}"
        run_dirsearch(target_url, target_dir)
    return False


def run_sqlmap_only(ip, target_dir):
    open_ports = run_nmap(ip, target_dir)
    if not open_ports:
        return False
    web_ports = get_web_ports(open_ports)
    if not web_ports:
        print("[-] No web ports found for SQLMap.")
        return False
    for port in web_ports:
        target_url = f"http://{ip}:{port}" if port not in [443, 8443] else f"https://{ip}:{port}"
        if run_sqlmap(target_url, target_dir):
            return True
    return False


def run_routersploit_only(ip, target_dir, use_ai=False):
    from core.exploitation import run_routersploit_with_ai_followup
    return run_routersploit_with_ai_followup(ip, target_dir, use_ai=use_ai)


def run_ingram_only(ip, target_dir):
    return run_ingram(ip, target_dir)


def run_hydra_only(ip, target_dir):
    open_ports = run_nmap(ip, target_dir)
    if not open_ports:
        return False
    login_ports = get_login_ports(open_ports)
    web_ports = get_web_ports(open_ports)
    success = False
    if login_ports:
        success = run_hydra(ip, login_ports, target_dir) or success
    if web_ports:
        success = run_web_hydra(ip, web_ports, target_dir) or success
    if not login_ports and not web_ports:
        print("[-] No login or web ports found for Hydra.")
    return success


def run_ffuf_only(ip, target_dir):
    open_ports = run_nmap(ip, target_dir)
    if not open_ports:
        return False
    web_ports = get_web_ports(open_ports)
    if not web_ports:
        print("[-] No web ports found for FFUF.")
        return False

    if not is_tool_available("ffuf"):
        print("[!] ffuf is not installed; skipping FFUF enumeration.")
        return False

    discovered = []
    for port in web_ports:
        target_url = build_url(ip, port)
        discovered.extend(run_ffuf(target_url, target_dir))

    if discovered:
        print(f"[+] FFUF discovered {len(set(discovered))} unique paths.")
    return False


def run_gau_only(ip, target_dir):
    open_ports = run_nmap(ip, target_dir)
    if not open_ports:
        return False
    web_ports = get_web_ports(open_ports)
    if not web_ports:
        print("[-] No web ports found for GAU.")
        return False

    if not is_tool_available("gau"):
        print("[!] gau is not installed; skipping GAU enumeration.")
        return False

    discovered = []
    for port in web_ports:
        target_url = build_url(ip, port)
        discovered.extend(run_gau(target_url, target_dir))

    if discovered:
        print(f"[+] GAU discovered {len(set(discovered))} unique URLs.")
    return False


def should_run_tool(scan_plan, tool_key, default=True):
    if not scan_plan:
        return default
    return bool(scan_plan.get(tool_key, default))


def run_all_tools(ip, target_dir, selection=1, use_ai=False):
    context = ScanContext()
    print(f"\n>>> PHASE 1: Scanning & Reconnaissance [{get_profile_name()}]")
    try:
        context.open_ports = run_nmap(ip, target_dir)
    except KeyboardInterrupt:
        if not prompt_next_stage():
            print("\n[-] Exiting as requested.")
            sys.exit(0)
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
                    found = run_searchsploit(q, target_dir)
                    if found:
                        run_metasploit_search(q, target_dir)
        except Exception:
            pass

    refresh_report(ip, target_dir, selection, context.exploited, context, "Phase 1 - Reconnaissance")

    context.ai_scan_plan = plan_scan_tools(ip, target_dir, context, use_ai=use_ai)
    refresh_report(ip, target_dir, selection, context.exploited, context, "Phase 1 - AI Planning")

    scan_plan = context.ai_scan_plan
    phase2_tools = ("run_dirsearch", "run_nuclei", "run_ffuf", "run_gau", "run_sqlmap")
    run_phase2 = context.web_ports and any(should_run_tool(scan_plan, key) for key in phase2_tools)

    if run_phase2:
        print("\n======================================================")
        print(">>> PHASE 2: Web Enumeration & Vulnerability Scanning")
        print("======================================================")
        try:
            for port in context.web_ports:
                target_url = build_url(ip, port)
                print(f"\n[*] Target URL: {target_url}")

                if should_run_tool(scan_plan, "run_dirsearch"):
                    paths = run_dirsearch(target_url, target_dir)
                    context.discovered_paths.extend(paths)
                else:
                    print("[*] AI/heuristic plan: skipping Dirsearch on this port.")

                if should_run_tool(scan_plan, "run_nuclei") and run_nuclei(target_url, target_dir):
                    context.exploited = True

            context.discovered_paths = list(dict.fromkeys(context.discovered_paths))
            if context.discovered_paths:
                print(f"[+] Total discovered paths: {len(context.discovered_paths)}")

            if should_run_tool(scan_plan, "run_gau") and is_tool_available("gau"):
                for port in context.web_ports:
                    target_url = build_url(ip, port)
                    context.gau_urls.extend(run_gau(target_url, target_dir))
                context.gau_urls = list(dict.fromkeys(context.gau_urls))
            elif not should_run_tool(scan_plan, "run_gau"):
                print("[*] AI/heuristic plan: skipping GAU.")

            if should_run_tool(scan_plan, "run_ffuf") and is_tool_available("ffuf"):
                for port in context.web_ports:
                    target_url = build_url(ip, port)
                    context.ffuf_candidates.extend(run_ffuf(target_url, target_dir))
                context.ffuf_candidates = list(dict.fromkeys(context.ffuf_candidates))
            elif not should_run_tool(scan_plan, "run_ffuf"):
                print("[*] AI/heuristic plan: skipping FFUF.")

            context.discovered_urls = list(dict.fromkeys(
                context.discovered_paths + context.gau_urls + context.ffuf_candidates
            ))

            query_urls = extract_query_urls(context.discovered_urls)
            if not query_urls:
                query_urls = [build_url(ip, port) for port in context.web_ports]

            if should_run_tool(scan_plan, "run_nuclei") and query_urls:
                from core.scan_config import get_scan_profile
                url_limit = get_scan_profile()["nuclei_url_limit"]
                print(f"\n[+] Running Nuclei on discovered URL candidates (limit: {url_limit})...")
                for target_url in query_urls[:url_limit]:
                    if run_nuclei(target_url, target_dir):
                        context.exploited = True

            if should_run_tool(scan_plan, "run_sqlmap"):
                print("\n[+] Running SQLMap on candidate URLs...")
                for target_url in query_urls:
                    if run_sqlmap(target_url, target_dir):
                        context.exploited = True
            else:
                print("[*] AI/heuristic plan: skipping SQLMap.")

        except KeyboardInterrupt:
            if not prompt_next_stage():
                print("\n[-] Exiting as requested.")
                sys.exit(0)

        refresh_report(ip, target_dir, selection, context.exploited, context, "Phase 2 - Web Enumeration")
    elif context.web_ports:
        print("[*] AI/heuristic plan: skipping all Phase 2 web tools.")

    print("\n======================================================")
    print(">>> PHASE 3: Router & Device Exploitation")
    print("======================================================")
    try:
        if should_run_tool(scan_plan, "run_routersploit"):
            if run_routersploit_with_ai_followup(ip, target_dir, use_ai=use_ai):
                context.exploited = True
        else:
            print("[*] AI/heuristic plan: skipping RouterSploit AutoPwn.")

        if not context.exploited and should_run_tool(scan_plan, "run_ingram") and should_run_ingram(context.open_ports):
            if run_ingram(ip, target_dir):
                context.exploited = True
        elif should_run_tool(scan_plan, "run_ingram") is False:
            print("[*] AI/heuristic plan: skipping Ingram (not a camera target).")
        elif not should_run_ingram(context.open_ports):
            print("[*] Skipping Ingram (target looks like a router/web UI, not a camera).")
    except KeyboardInterrupt:
        if not prompt_next_stage():
            print("\n[-] Exiting as requested.")
            sys.exit(0)

    refresh_report(ip, target_dir, selection, context.exploited, context, "Phase 3 - Exploitation")

    if (context.login_ports or context.web_ports) and should_run_tool(scan_plan, "run_hydra"):
        print("\n======================================================")
        print(">>> PHASE 4: Credential Brute-Forcing (Last Resort)")
        print("======================================================")
        try:
            context.ai_hydra_plan = recommend_hydra_commands(
                ip, target_dir, context, scan_plan=scan_plan, use_ai=use_ai,
            )
            if context.login_ports and run_hydra(ip, context.login_ports, target_dir):
                context.exploited = True
            if context.web_ports and run_web_hydra(
                ip, context.web_ports, target_dir, hydra_plan=context.ai_hydra_plan,
            ):
                context.exploited = True
        except KeyboardInterrupt:
            if not prompt_next_stage():
                print("\n[-] Exiting as requested.")
                sys.exit(0)
    elif context.login_ports or context.web_ports:
        print("[*] AI/heuristic plan: skipping Hydra brute-force.")

    refresh_report(ip, target_dir, selection, context.exploited, context, "Phase 4 - Brute Force")

    return context.exploited


def should_run_ingram(open_ports):
    """Skip Ingram when the target looks like a generic router/web UI, not a camera."""
    camera_services = {"rtsp", "onvif", "dvr", "ipcam", "hikvision", "dahua"}
    for entry in open_ports:
        service = str(entry.get("service", "")).lower()
        port = entry.get("port")
        if port in {554, 37777, 8000, 34567, 9000}:
            return True
        if any(token in service for token in camera_services):
            return True
    return False


def run_selected_tool(selection, ip, target_dir, profile="normal", use_ai=False):
    set_scan_profile(profile)
    if selection == 1:
        return run_all_tools(ip, target_dir, selection=selection, use_ai=use_ai)
    if selection == 2:
        return run_nmap_only(ip, target_dir)
    if selection == 3:
        return run_nuclei_only(ip, target_dir)
    if selection == 4:
        return run_dirsearch_only(ip, target_dir)
    if selection == 5:
        return run_sqlmap_only(ip, target_dir)
    if selection == 6:
        return run_routersploit_only(ip, target_dir, use_ai=use_ai)
    if selection == 7:
        return run_ingram_only(ip, target_dir)
    if selection == 8:
        return run_hydra_only(ip, target_dir)
    if selection == 9:
        return run_ffuf_only(ip, target_dir)
    if selection == 10:
        return run_gau_only(ip, target_dir)
    return False
