from core.bruteforce import run_hydra, run_web_hydra
from core.classic.context import build_context_from_ports, build_url, get_web_ports
from core.classic.helpers import is_tool_available, run_ffuf, run_gau
from core.exploitation import run_ingram, run_routersploit
from core.scanner import run_nmap
from core.web import run_dirsearch, run_nuclei, run_sqlmap


def _open_ports_for_tool(ip: str, target_dir: str) -> list:
    """Use saved Nmap results when workspace has them; otherwise run Nmap."""
    from core.workspace_ports import load_open_ports_from_workspace

    cached = load_open_ports_from_workspace(target_dir)
    if cached:
        tcp_n = len([p for p in cached if isinstance(p, dict) and p.get("port", 0) > 0])
        print(f"[*] Reusing {tcp_n} open port(s) from workspace (skip Nmap re-scan)")
        return cached
    return run_nmap(ip, target_dir)


def run_nmap_only(ip, target_dir):
    print("\n>>> TOOL: Nmap scan only")
    run_nmap(ip, target_dir)
    return False


def run_nuclei_only(ip, target_dir):
    open_ports = _open_ports_for_tool(ip, target_dir)
    if not open_ports:
        return False
    web_ports = get_web_ports(open_ports)
    if not web_ports:
        camera_ports = [81, 8000, 8001, 8081, 9000, 37777, 5000]
        default_ports = [80, 443, 8080, 8443]
        web_ports = default_ports + camera_ports
        print(f"[!] No web ports detected by Nmap; falling back to ports for Nuclei: {web_ports}")
    for port in web_ports:
        target_url = build_url(ip, port)
        if run_nuclei(target_url, target_dir):
            return True
    return False


def run_dirsearch_only(ip, target_dir):
    open_ports = _open_ports_for_tool(ip, target_dir)
    if not open_ports:
        return False
    web_ports = get_web_ports(open_ports)
    if not web_ports:
        print("[-] No web ports found for Dirsearch.")
        return False
    for port in web_ports:
        run_dirsearch(build_url(ip, port), target_dir)
    return False


def run_sqlmap_only(ip, target_dir):
    open_ports = _open_ports_for_tool(ip, target_dir)
    if not open_ports:
        return False
    web_ports = get_web_ports(open_ports)
    if not web_ports:
        print("[-] No web ports found for SQLMap.")
        return False
    for port in web_ports:
        if run_sqlmap(build_url(ip, port), target_dir):
            return True
    return False


def run_routersploit_only(ip, target_dir):
    print("\n>>> TOOL: RouterSploit only")
    return run_routersploit(ip, target_dir)


def run_ingram_only(ip, target_dir):
    print("\n>>> TOOL: Ingram only")
    return run_ingram(ip, target_dir)


def run_hydra_only(ip, target_dir):
    print("\n>>> TOOL: Hydra only")
    open_ports = _open_ports_for_tool(ip, target_dir)
    if not open_ports:
        return False
    context = build_context_from_ports(open_ports)
    success = False
    if context.login_ports:
        success = run_hydra(ip, context.login_ports, target_dir) or success
    if context.web_ports:
        success = run_web_hydra(ip, context.web_ports, target_dir) or success
    if not context.login_ports and not context.web_ports:
        print("[-] No login or web ports found for Hydra.")
    return success


def run_ffuf_only(ip, target_dir):
    open_ports = _open_ports_for_tool(ip, target_dir)
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
        discovered.extend(run_ffuf(build_url(ip, port), target_dir))
    if discovered:
        print(f"[+] FFUF discovered {len(set(discovered))} unique paths.")
    return False


def run_gau_only(ip, target_dir):
    open_ports = _open_ports_for_tool(ip, target_dir)
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
        discovered.extend(run_gau(build_url(ip, port), target_dir))
    if discovered:
        print(f"[+] GAU discovered {len(set(discovered))} unique URLs.")
    return False
