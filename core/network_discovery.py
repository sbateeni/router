import ipaddress
import json
import os
import re
import shutil
import subprocess

from core.utils import run_cmd

HOST_PATTERN = re.compile(
    r"Nmap scan report for (?:([^\s(]+)\s)?\(?(\d+\.\d+\.\d+\.\d+)\)?",
    re.MULTILINE,
)
MAC_PATTERN = re.compile(r"MAC Address:\s+([0-9A-Fa-f:]+)\s+\((.+?)\)")


def is_valid_ip(value):
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def guess_local_subnet():
    try:
        result = subprocess.run(
            ["ip", "-4", "route"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 1 and "/" in parts[0]:
                    if "link" in line or any(token.startswith("192.168.") or token.startswith("10.") for token in parts):
                        return parts[0]
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return "192.168.1.0/24"


def parse_nmap_host_discovery(output):
    hosts = []
    blocks = re.split(r"Nmap scan report for ", output)
    for block in blocks[1:]:
        header = "Nmap scan report for " + block
        match = HOST_PATTERN.search(header)
        if not match:
            continue
        hostname = (match.group(1) or "").strip()
        ip = match.group(2)
        if ip.endswith(".0") or ip.endswith(".255"):
            continue
        mac_match = MAC_PATTERN.search(block)
        hosts.append({
            "ip": ip,
            "hostname": hostname,
            "mac": mac_match.group(1) if mac_match else None,
            "vendor": mac_match.group(2).strip() if mac_match else None,
        })

    unique = {}
    for host in hosts:
        unique[host["ip"]] = host
    return list(unique.values())


def discover_lan_hosts(cidr, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    log_file = os.path.join(output_dir, "lan_discovery.txt")
    print(f"\n[+] Discovering live hosts on {cidr} ...")

    if shutil.which("arp-scan"):
        command = ["arp-scan", "--localnet", "--ignoredups"]
        if "/" in cidr:
            command = ["arp-scan", cidr]
        success, output = run_cmd(command, capture=True, log_file=log_file)
        if success and output:
            hosts = []
            for line in output.splitlines():
                parts = line.split("\t")
                if len(parts) >= 2 and is_valid_ip(parts[0].strip()):
                    hosts.append({
                        "ip": parts[0].strip(),
                        "hostname": "",
                        "mac": parts[1].strip() if len(parts) > 1 else None,
                        "vendor": parts[2].strip() if len(parts) > 2 else None,
                    })
            if hosts:
                save_host_list(output_dir, cidr, hosts)
                return hosts

    command = ["nmap", "-sn", "-T4", "--max-retries", "1", cidr]
    success, output = run_cmd(command, capture=True, log_file=log_file)
    hosts = parse_nmap_host_discovery(output or "")
    save_host_list(output_dir, cidr, hosts)
    if hosts:
        print(f"[+] Found {len(hosts)} live host(s) on {cidr}.")
    else:
        print(f"[-] No live hosts found on {cidr}.")
    return hosts


def save_host_list(output_dir, cidr, hosts):
    payload = {"subnet": cidr, "hosts": hosts, "count": len(hosts)}
    path = os.path.join(output_dir, "discovered_hosts.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    return path


def print_host_table(hosts):
    print("\nDiscovered hosts:")
    print("  0) ALL hosts")
    for index, host in enumerate(hosts, start=1):
        label = host.get("hostname") or "-"
        vendor = host.get("vendor") or "unknown vendor"
        print(f"  {index}) {host['ip']}  {label}  [{vendor}]")


def select_targets_interactive(hosts):
    if not hosts:
        return []

    print_host_table(hosts)
    while True:
        choice = input("\nSelect target [0=all, 1-N=one host, q=quit]: ").strip().lower()
        if choice in {"q", "quit", "exit"}:
            return []
        if choice in {"0", "all", "a", "*"}:
            return [host["ip"] for host in hosts]
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(hosts):
                return [hosts[idx - 1]["ip"]]
        print("Enter 0 for all hosts, a number from the list, or q to quit.")


def prompt_manual_ip():
    while True:
        value = input("Enter target IP (example: 192.168.1.1): ").strip()
        if is_valid_ip(value):
            return value
        print("Invalid IP address. Try again.")


def prompt_subnet(default_subnet):
    value = input(f"Enter subnet CIDR [{default_subnet}]: ").strip()
    subnet = value or default_subnet
    try:
        ipaddress.ip_network(subnet, strict=False)
        return str(subnet)
    except ValueError:
        print("Invalid subnet. Example: 192.168.1.0/24")
        return prompt_subnet(default_subnet)


from core.report.parsers import parse_target_input, save_target_hints, target_scan_host, target_workspace_name


def resolve_target_list(args, base_dir):
    if getattr(args, "target", None):
        parsed = parse_target_input(args.target)
        if parsed:
            return [target_scan_host(parsed)]
        print(f"[-] Invalid target (use IP, domain, or URL): {args.target}")
        return []

    discovery_dir = os.path.join(base_dir, "targets", "_network_discovery")
    os.makedirs(discovery_dir, exist_ok=True)

    if getattr(args, "subnet", None):
        cidr = args.subnet
        hosts = discover_lan_hosts(cidr, discovery_dir)
        if not hosts:
            return []
        if getattr(args, "all", False):
            return [host["ip"] for host in hosts]
        return select_targets_interactive(hosts)

    if getattr(args, "auto", False) and not getattr(args, "target", None):
        cidr = getattr(args, "subnet", None) or guess_local_subnet()
        print(f"[*] Auto mode: discovering hosts on {cidr}")
        hosts = discover_lan_hosts(cidr, discovery_dir)
        if not hosts:
            return []
        if getattr(args, "all", False) or not getattr(args, "subnet", None):
            return [host["ip"] for host in hosts]
        return select_targets_interactive(hosts)

    print("\n======================================================")
    print(" TARGET SELECTION")
    print("======================================================")
    print("  1) Enter IP manually")
    print("  2) Scan local network (auto-detect subnet)")
    print("  3) Scan custom subnet")
    print("  4) Exit")

    while True:
        choice = input("Select an option [1-4]: ").strip()
        if choice == "1":
            return [prompt_manual_ip()]
        if choice == "2":
            cidr = guess_local_subnet()
            print(f"[*] Using detected subnet: {cidr}")
            hosts = discover_lan_hosts(cidr, discovery_dir)
            if not hosts:
                return []
            return select_targets_interactive(hosts)
        if choice == "3":
            cidr = prompt_subnet(guess_local_subnet())
            hosts = discover_lan_hosts(cidr, discovery_dir)
            if not hosts:
                return []
            return select_targets_interactive(hosts)
        if choice == "4":
            return []
        print("Please enter a number between 1 and 4.")
