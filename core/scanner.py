import re
import os
from core.utils import run_cmd

def run_nmap(ip, target_dir):
    print(f"\n[*] Starting Nmap scan on {ip}...")
    log_file = os.path.join(target_dir, "nmap_scan.txt")
    command = ["nmap", "-sV", "-T4", "--open", ip]
    
    success, output = run_cmd(command, capture=True, log_file=log_file)
    if not success and not output:
        print("[-] Nmap scan failed or Nmap is not installed.")
        return []

    if success and os.path.exists(log_file):
        print(f"[+] Nmap results saved to: {log_file}")
    return parse_nmap(output)

def parse_nmap(nmap_output):
    open_ports = []
    pattern = re.compile(r"^(\d+)/tcp\s+open\s+(\S+)", re.MULTILINE)
    for match in pattern.finditer(nmap_output):
        port = int(match.group(1))
        service = match.group(2)
        open_ports.append({"port": port, "service": service})
    return open_ports
