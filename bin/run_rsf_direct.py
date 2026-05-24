import sys

from core.paths import setup_project_env

setup_project_env()

from engines.external_tools import ExternalTools
from engines.utils import log, extract_ip
from engines.lan_scanner import LANScanner

def run_direct_rsf():
    print("\n" + "="*50)
    print("      ROUTERSPLOIT EXPERT SCANNER")
    print("="*50)
    print("  [1] Enter Target IP manually")
    print("  [2] Scan Local Network (LAN) to find targets")
    choice = input("\n[?] Select option: ").strip()

    target_ip = ""

    if choice == '1':
        target_ip = input("\n[?] Enter Target IP: ").strip()
    elif choice == '2':
        scanner = LANScanner()
        devices = scanner.run_scan()
        if not devices:
            log("No devices found on LAN.", "ERROR")
            return
        
        print("\n" + "="*60)
        print("      SELECT DEVICE TO ATTACK WITH ROUTERSPLOIT")
        print("="*60)
        for i, dev in enumerate(devices):
            print(f"  [{i+1}] IP: {dev['ip']:<15} | Type: {dev['type']:<15}")
        print("="*60)
        
        idx = input("\n[?] Select Device ID (or 'q' to quit): ").strip()
        if idx.lower() == 'q': return
        try:
            target_ip = devices[int(idx)-1]['ip']
        except:
            log("Invalid selection.", "ERROR")
            return
    else:
        log("Invalid option.", "ERROR")
        return

    ip = extract_ip(target_ip)
    if not ip:
        log("Invalid IP provided.", "ERROR")
        return

    log(f"Targeting {ip} with RouterSploit...", "SUCCESS")
    ext = ExternalTools(ip)
    ext.run_routersploit_scan()

if __name__ == "__main__":
    run_direct_rsf()
