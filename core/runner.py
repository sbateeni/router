import sys
import os
import re
import shutil

from core.scanner import run_nmap
from core.utils import run_cmd
from core.web_enum import run_nuclei, run_dirsearch, run_sqlmap, run_searchsploit
from core.exploitation import run_routersploit, run_ingram
from core.bruteforce import run_hydra


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
        # p may be dict with 'service' and 'version' or raw string; be defensive
        svc = None
        ver = None
        try:
            svc = p.get('service') if isinstance(p, dict) else str(p)
        except Exception:
            svc = str(p)
        # try to split common banners like 'nginx 1.14.0'
        if svc:
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
    candidates = [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


def run_ffuf(target_url, target_dir):
    if not is_tool_available("ffuf"):
        print("[!] ffuf is not installed; skipping FFUF enumeration.")
        return []

    wordlist = find_common_wordlist()
    if not wordlist:
        print("[!] No common wordlist found for ffuf; skipping.")
        return []

    print("[+] Running ffuf for hidden content discovery...")
    log_file = os.path.join(target_dir, "ffuf_results.txt")
    fuzz_url = normalize_url(target_url) + "/FUZZ"
    command = ["ffuf", "-u", fuzz_url, "-w", wordlist, "-t", "50", "-o", log_file, "-of", "json"]
    success, output = run_cmd(command, capture=True, log_file=log_file)
    urls = []
    if os.path.exists(log_file):
        try:
            import json
            with open(log_file, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read().strip()
                if content:
                    data = json.loads(content)
                    for result in data.get("results", []):
                        path = result.get("input", "").replace(fuzz_url.replace("FUZZ", ""), "")
                        if path:
                            urls.append(normalize_url(target_url) + path)
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
    return [p['port'] for p in open_ports if p['port'] in [80, 443, 8080, 8443] or 'http' in p['service'].lower()]


def get_login_ports(open_ports):
    return [p for p in open_ports if p['port'] in [21, 22, 23] or p['service'].lower() in ['ssh', 'ftp', 'telnet']]


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


def run_routersploit_only(ip, target_dir):
    return run_routersploit(ip, target_dir)


def run_ingram_only(ip, target_dir):
    return run_ingram(ip, target_dir)


def run_hydra_only(ip, target_dir):
    open_ports = run_nmap(ip, target_dir)
    if not open_ports:
        return False
    login_ports = get_login_ports(open_ports)
    if not login_ports:
        print("[-] No login ports found for Hydra.")
        return False
    return run_hydra(ip, login_ports, target_dir)


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


def run_all_tools(ip, target_dir):
    context = ScanContext()
    print("\n>>> PHASE 1: Scanning & Reconnaissance")
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

        # Link Nmap results to SearchSploit and Metasploit lookups
        try:
            service_queries = extract_service_queries(context.open_ports)
            if service_queries:
                print("\n[+] Performing SearchSploit lookups based on detected services...")
                for q in service_queries:
                    found = run_searchsploit(q, target_dir)
                    if found:
                        # If searchsploit returned something, try a metasploit search as well
                        run_metasploit_search(q, target_dir)
        except Exception:
            pass

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
                    target_url = build_url(ip, port)
                    context.gau_urls.extend(run_gau(target_url, target_dir))
                context.gau_urls = list(dict.fromkeys(context.gau_urls))

            if is_tool_available("ffuf"):
                for port in context.web_ports:
                    target_url = build_url(ip, port)
                    context.ffuf_candidates.extend(run_ffuf(target_url, target_dir))
                context.ffuf_candidates = list(dict.fromkeys(context.ffuf_candidates))

            context.discovered_urls = list(dict.fromkeys(
                context.discovered_paths + context.gau_urls + context.ffuf_candidates
            ))

            query_urls = extract_query_urls(context.discovered_urls)
            if not query_urls:
                query_urls = [build_url(ip, port) for port in context.web_ports]

            if query_urls:
                print("\n[+] Running Nuclei on discovered URL candidates...")
                for target_url in query_urls[:20]:
                    if run_nuclei(target_url, target_dir):
                        context.exploited = True

            print("\n[+] Running SQLMap on candidate URLs...")
            for target_url in query_urls:
                if run_sqlmap(target_url, target_dir):
                    context.exploited = True

        except KeyboardInterrupt:
            if not prompt_next_stage():
                print("\n[-] Exiting as requested.")
                sys.exit(0)

    if not context.exploited:
        print("\n======================================================")
        print(">>> PHASE 3: Router & Device Exploitation")
        print("======================================================")
        try:
            if run_routersploit(ip, target_dir):
                context.exploited = True
            elif run_ingram(ip, target_dir):
                context.exploited = True
        except KeyboardInterrupt:
            if not prompt_next_stage():
                print("\n[-] Exiting as requested.")
                sys.exit(0)

    if not context.exploited and context.login_ports:
        try:
            if run_hydra(ip, context.login_ports, target_dir):
                context.exploited = True
        except KeyboardInterrupt:
            if not prompt_next_stage():
                print("\n[-] Exiting as requested.")
                sys.exit(0)

    return context.exploited


def run_selected_tool(selection, ip, target_dir):
    if selection == 1:
        return run_all_tools(ip, target_dir)
    if selection == 2:
        return run_nmap_only(ip, target_dir)
    if selection == 3:
        return run_nuclei_only(ip, target_dir)
    if selection == 4:
        return run_dirsearch_only(ip, target_dir)
    if selection == 5:
        return run_sqlmap_only(ip, target_dir)
    if selection == 6:
        return run_routersploit_only(ip, target_dir)
    if selection == 7:
        return run_ingram_only(ip, target_dir)
    if selection == 8:
        return run_hydra_only(ip, target_dir)
    if selection == 9:
        return run_ffuf_only(ip, target_dir)
    if selection == 10:
        return run_gau_only(ip, target_dir)
    return False
