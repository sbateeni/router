import sys

from core.scanner import run_nmap
from core.web_enum import run_nuclei, run_dirsearch, run_sqlmap
from core.exploitation import run_routersploit, run_ingram
from core.bruteforce import run_hydra


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
    print("  9) Exit")

    valid_choices = {str(i) for i in range(1, 10)}
    while True:
        choice = input("Select an option [1-9]: ").strip()
        if choice in valid_choices:
            return int(choice)
        print("Please enter a number between 1 and 9.")


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
        print("[-] No web ports found for Nuclei.")
        return False
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


def run_all_tools(ip, target_dir):
    print("\n>>> PHASE 1: Scanning & Reconnaissance")
    try:
        open_ports = run_nmap(ip, target_dir)
    except KeyboardInterrupt:
        if not prompt_next_stage():
            print("\n[-] Exiting as requested.")
            sys.exit(0)
        open_ports = []

    if not open_ports:
        print(f"[-] No open ports found on {ip}. Moving on to the next phases.")
        open_ports = []
        web_ports = []
        login_ports = []
    else:
        web_ports = get_web_ports(open_ports)
        login_ports = get_login_ports(open_ports)
    exploited = False

    if web_ports and not exploited:
        print("\n======================================================")
        print(">>> PHASE 2: Web Enumeration & Vulnerability Scanning")
        print("======================================================")
        try:
            for port in web_ports:
                target_url = f"http://{ip}:{port}" if port not in [443, 8443] else f"https://{ip}:{port}"
                print(f"\n[*] Target URL: {target_url}")
                if run_nuclei(target_url, target_dir):
                    exploited = True
                    break
                run_dirsearch(target_url, target_dir)
        except KeyboardInterrupt:
            if not prompt_next_stage():
                print("\n[-] Exiting as requested.")
                sys.exit(0)

    if not exploited:
        print("\n======================================================")
        print(">>> PHASE 3: Router & Device Exploitation")
        print("======================================================")
        try:
            if run_routersploit(ip, target_dir):
                exploited = True
            elif run_ingram(ip, target_dir):
                exploited = True
        except KeyboardInterrupt:
            if not prompt_next_stage():
                print("\n[-] Exiting as requested.")
                sys.exit(0)

    if not exploited and login_ports:
        try:
            if run_hydra(ip, login_ports, target_dir):
                exploited = True
        except KeyboardInterrupt:
            if not prompt_next_stage():
                print("\n[-] Exiting as requested.")
                sys.exit(0)

    return exploited


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
    return False
