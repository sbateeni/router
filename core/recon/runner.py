from core.network_discovery import discover_lan_hosts, guess_local_subnet, prompt_subnet
from core.recon_tools import run_nikto_only, run_nmap_vuln_only, run_whatweb_only


def run_lan_discovery_only(target_dir, subnet=None):
    print("\n>>> TOOL: LAN network discovery")
    cidr = subnet or prompt_subnet(guess_local_subnet())
    hosts = discover_lan_hosts(cidr, target_dir)
    return bool(hosts)


def run_nikto_tool(ip, target_dir):
    print("\n>>> TOOL: Nikto web scan only")
    return run_nikto_only(ip, target_dir)


def run_whatweb_tool(ip, target_dir):
    print("\n>>> TOOL: WhatWeb fingerprint only")
    return run_whatweb_only(ip, target_dir)


def run_nmap_vuln_tool(ip, target_dir):
    print("\n>>> TOOL: Nmap vuln scripts only")
    return run_nmap_vuln_only(ip, target_dir)
