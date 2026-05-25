import os
import shutil

from core.scanner import run_nmap
from core.utils import run_cmd


def build_url(ip, port):
    return f"http://{ip}:{port}" if port not in [443, 8443] else f"https://{ip}:{port}"


def get_web_ports(open_ports):
    from core.classic.context import get_web_ports as _ctx_web_ports
    return _ctx_web_ports(open_ports)


def run_nikto(target_url, target_dir):
    if not shutil.which("nikto"):
        print("[!] Nikto is not installed. Install with: sudo apt install nikto")
        return False

    port = target_url.split(":")[-1] if ":" in target_url.replace("https://", "").replace("http://", "") else "80"
    log_file = os.path.join(target_dir, f"nikto_port_{port}.txt")
    command = ["nikto", "-h", target_url, "-o", log_file, "-Format", "txt"]
    success, output = run_cmd(
        command, capture=True,
        log_file=os.path.join(target_dir, f"nikto_port_{port}_stdout.txt"),
    )
    if output:
        print(output[-1500:] if len(output) > 1500 else output)
    if os.path.exists(log_file):
        print(f"[+] Nikto results saved to: {log_file}")
    return success or os.path.exists(log_file)


def run_whatweb(target_url, target_dir):
    if not shutil.which("whatweb"):
        print("[!] WhatWeb is not installed. Install with: sudo apt install whatweb")
        return False

    port = target_url.split(":")[-1] if ":" in target_url.replace("https://", "").replace("http://", "") else "80"
    log_file = os.path.join(target_dir, f"whatweb_port_{port}.txt")
    command = ["whatweb", "-a", "3", target_url]
    success, output = run_cmd(command, capture=True, log_file=log_file)
    if output:
        print(output)
    if os.path.exists(log_file):
        print(f"[+] WhatWeb results saved to: {log_file}")
    return bool(output.strip())


def run_nmap_vuln_scripts(ip, target_dir):
    log_file = os.path.join(target_dir, "nmap_vuln_scripts.txt")
    command = [
        "nmap", "-sV", "--script", "vuln,http-enum,http-title,default",
        "-p", "21,22,23,53,80,443,8080,8443,554,8000,37777", ip,
    ]
    success, output = run_cmd(command, capture=True, log_file=log_file)
    if output:
        print(output[-2000:] if len(output) > 2000 else output)
    if os.path.exists(log_file):
        print(f"[+] Nmap vuln script results saved to: {log_file}")
    return success


def run_nikto_only(ip, target_dir):
    open_ports = run_nmap(ip, target_dir)
    web_ports = get_web_ports(open_ports)
    if not web_ports:
        print("[-] No web ports found for Nikto.")
        return False
    success = False
    for port in web_ports:
        if run_nikto(build_url(ip, port), target_dir):
            success = True
    return success


def run_whatweb_only(ip, target_dir):
    open_ports = run_nmap(ip, target_dir)
    web_ports = get_web_ports(open_ports)
    if not web_ports:
        print("[-] No web ports found for WhatWeb.")
        return False
    for port in web_ports:
        run_whatweb(build_url(ip, port), target_dir)
    return True


def run_nmap_vuln_only(ip, target_dir):
    return run_nmap_vuln_scripts(ip, target_dir)
