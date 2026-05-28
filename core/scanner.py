import json
import os
import re

from core.utils import run_cmd
from core.scan_config import get_scan_profile


def run_nmap(ip, target_dir):
    profile = get_scan_profile()
    print(f"\n[*] Starting Nmap scan on {ip} [{profile['label']}]...")

    masscan_ports: list[int] = []
    if profile.get("masscan_enabled"):
        try:
            from core.recon.masscan import run_masscan_discovery

            masscan_ports = run_masscan_discovery(ip, target_dir)
        except Exception as exc:
            print(f"[!] Masscan skipped: {exc}")

    quick_log = os.path.join(target_dir, "nmap_scan.txt")
    quick_args = list(profile["nmap_quick_args"])
    if masscan_ports:
        port_str = ",".join(str(p) for p in masscan_ports[:300])
        quick_args = ["-sS", "-sV", "-T4", "--open", "-p", port_str]
        print(f"[*] Nmap focused on {len(masscan_ports)} Masscan port(s)")
    quick_cmd = ["nmap"] + quick_args + [ip]
    success, output = run_cmd(quick_cmd, capture=True, log_file=quick_log)
    if not success and not output:
        print("[-] Nmap scan failed or Nmap is not installed.")
        return []

    open_ports = parse_nmap(output)
    if open_ports:
        print(f"[+] Quick Nmap found {len([p for p in open_ports if p.get('port')])} open TCP port(s).")

    if profile["nmap_deep_enabled"] and open_ports:
        tcp_ports = [str(p["port"]) for p in open_ports if p.get("port")]
        if tcp_ports:
            print(f"[*] Running deep Nmap with OS fingerprinting (-O) on open ports: {', '.join(tcp_ports)}")
            deep_log = os.path.join(target_dir, "nmap_deep_scan.txt")
            deep_cmd = [
                "nmap", "-O", "-sV", "--osscan-guess", "--script=default,vuln,http-enum,http-title",
                "-p", ",".join(tcp_ports), ip,
            ]
            deep_success, deep_output = run_cmd(deep_cmd, capture=True, log_file=deep_log)
            if deep_success and deep_output:
                open_ports = merge_nmap_results(open_ports, parse_nmap(deep_output))
                print(f"[+] Deep Nmap results saved to: {deep_log}")

    save_recon_summary(target_dir, ip, open_ports, profile)
    if os.path.exists(quick_log):
        print(f"[+] Nmap results saved to: {quick_log}")
    return open_ports


def merge_nmap_results(base_ports, deep_ports):
    merged = {}
    for entry in base_ports + deep_ports:
        port = entry.get("port")
        if port == 0:
            merged[0] = entry
            continue
        if port not in merged:
            merged[port] = entry
            continue
        if len(entry.get("service", "")) > len(merged[port].get("service", "")):
            merged[port] = entry
    return list(merged.values())


def parse_nmap(nmap_output):
    open_ports = []
    os_match = None
    pattern = re.compile(r"^(\d+)/tcp\s+open\s+(\S+)\s*(.*)$", re.MULTILINE)
    for match in pattern.finditer(nmap_output):
        port = int(match.group(1))
        service = match.group(2)
        version = match.group(3).strip()
        if version:
            service = f"{service} {version}".strip()
        open_ports.append({"port": port, "service": service})

    vendor_match = re.search(r"MAC Address:.*\((.+)\)", nmap_output)
    if vendor_match:
        vendor = vendor_match.group(1).strip()
        open_ports.append({"port": 0, "service": vendor, "vendor": vendor})
        
    os_guess_match = re.search(r"OS guesses?:\s*(.+)", nmap_output, re.IGNORECASE)
    os_details_match = re.search(r"OS details?:\s*(.+)", nmap_output, re.IGNORECASE)
    
    os_info = None
    if os_details_match:
        os_info = os_details_match.group(1).strip()
    elif os_guess_match:
        os_info = os_guess_match.group(1).strip()
        
    if os_info:
        # Determine OS Family
        os_family = "UNKNOWN_OS"
        if "Windows" in os_info: os_family = "WINDOWS"
        elif "Linux" in os_info: os_family = "LINUX"
        elif "Mac OS" in os_info or "Apple" in os_info: os_family = "MACOS"
        open_ports.append({"port": -1, "os_family": os_family, "os_details": os_info})

    return open_ports


def save_recon_summary(target_dir, ip, open_ports, profile):
    summary = {
        "target": ip,
        "profile": profile.get("label", "unknown"),
        "open_ports": [p for p in open_ports if p.get("port") and p.get("port") > 0],
        "vendor": next((p.get("vendor") for p in open_ports if p.get("port") == 0), None),
        "os_family": next((p.get("os_family") for p in open_ports if p.get("port") == -1), None),
        "os_details": next((p.get("os_details") for p in open_ports if p.get("port") == -1), None),
        "service_queries": [],
    }
    for entry in summary["open_ports"]:
        service = entry.get("service", "")
        parts = service.split()
        if len(parts) >= 2:
            summary["service_queries"].append(f"{parts[0]} {parts[1]}")
        if parts:
            summary["service_queries"].append(parts[0])
    summary["service_queries"] = sorted(set(summary["service_queries"]))

    path = os.path.join(target_dir, "recon_summary.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, ensure_ascii=False)
    return path
