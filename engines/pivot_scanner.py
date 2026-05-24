import subprocess
import re
import socket
import json
import os
from engines.utils import log

class PivotScanner:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.subnet = self._get_subnet(target_ip)
        self.discovered_devices = []

    def _get_subnet(self, ip):
        """Extract the /24 subnet from an IP (e.g., 192.168.1.1 -> 192.168.1.0/24)"""
        parts = ip.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return f"{ip}/24" # Fallback

    def discover_subnet_devices(self):
        """Run nmap ping sweep to find live hosts."""
        log(f"Starting Pivot Scan on subnet {self.subnet}...", "INFO")
        try:
            # -sn: Ping Scan (disable port scan), -T4: fast
            cmd = ["nmap", "-sn", "-T4", self.subnet]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()
            
            # Parse nmap output for IP and MAC/Vendor
            current_ip = None
            for line in stdout.splitlines():
                # "Nmap scan report for 192.168.1.5" or "Nmap scan report for host.domain (192.168.1.5)"
                ip_match = re.search(r"Nmap scan report for .*?(\d+\.\d+\.\d+\.\d+)", line)
                if ip_match:
                    current_ip = ip_match.group(1)
                    if current_ip not in [d['ip'] for d in self.discovered_devices]:
                        self.discovered_devices.append({"ip": current_ip, "mac": "", "vendor": ""})
                
                # "MAC Address: 00:11:22:33:44:55 (Vendor Name)"
                mac_match = re.search(r"MAC Address: ([0-9A-Fa-f:]+) \((.*?)\)", line)
                if mac_match and current_ip:
                    for d in self.discovered_devices:
                        if d['ip'] == current_ip:
                            d['mac'] = mac_match.group(1)
                            d['vendor'] = mac_match.group(2)
                            break
                            
            log(f"Pivot Scan discovered {len(self.discovered_devices)} live hosts.", "SUCCESS")
            return self.discovered_devices
        except Exception as e:
            log(f"Pivot Scan error: {e}", "ERROR")
            return []

    def classify_devices(self):
        """Quickly classify discovered devices based on basic port scans (80, 443, 22, etc.)."""
        log("Classifying discovered devices...", "INFO")
        for dev in self.discovered_devices:
            ip = dev['ip']
            dev['type'] = "UNKNOWN"
            open_ports = []
            
            # Quick check on common ports
            for port in [80, 443, 8000, 8080, 554, 22]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        open_ports.append(port)
                    sock.close()
                except:
                    pass
            
            dev['ports'] = open_ports
            
            vendor = dev.get('vendor', '').lower()
            if 'hikvision' in vendor or 554 in open_ports or 8000 in open_ports:
                 dev['type'] = "CAMERA/DVR"
            elif 'cisco' in vendor or 'tp-link' in vendor or 'd-link' in vendor:
                 dev['type'] = "ROUTER/SWITCH"
            elif 22 in open_ports and not open_ports: # Only SSH
                 dev['type'] = "SERVER/PC"
            elif 80 in open_ports or 443 in open_ports or 8080 in open_ports:
                 dev['type'] = "WEB_SERVICE"

        return self.discovered_devices
