"""LAN discovery — Kali tools: nmap -sn/-sV, arp-scan, http-title, optional whatweb."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime

import requests

from engines.fingerprinter import Fingerprinter
from engines.platform_utils import ping_host
from engines.utils import log

try:
    from core.scanner import parse_nmap
except ImportError:
    parse_nmap = None

requests.packages.urllib3.disable_warnings()

# Ports where HTTP fingerprint makes sense (service name or well-known)
HTTP_PORTS = frozenset({
    80, 443, 81, 88, 443, 8080, 8443, 8000, 8081, 8888, 9000, 9090,
    3000, 5000, 5001, 8008, 8088, 8880, 37777, 34567,
})

HTTP_SERVICE_PREFIXES = ("http", "https", "ssl", "proxy")


class LANScanner:
    def __init__(self):
        self.local_ip = self.get_local_ip()
        self.subnet = ".".join(self.local_ip.split(".")[:-1]) + "."
        self.cidr = self.subnet + "0/24"
        self.discovered_devices: list[dict] = []
        self._host_meta: dict[str, dict] = {}
        self._log_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "logs",
        )

    def get_local_ip(self):
        import socket

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
        finally:
            sock.close()

    def _run_cmd(self, cmd: list[str], timeout: int = 600) -> str:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return ((result.stdout or "") + ("\n" + result.stderr if result.stderr else "")).strip()
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            log(f"Command failed ({cmd[0]}): {exc}", "ERROR")
            return ""

    def _run_nmap(self, args: list[str], timeout: int = 600) -> str:
        if not shutil.which("nmap"):
            return ""
        return self._run_cmd(["nmap", *args], timeout=timeout)

    def _arp_scan_hosts(self) -> dict[str, dict]:
        """MAC + vendor via arp-scan (Kali)."""
        if not shutil.which("arp-scan"):
            return {}
        log("ARP scan (vendor/MAC) ...", "INFO")
        output = self._run_cmd(["arp-scan", "--localnet", "--ignoredups"], timeout=120)
        if not output and "/" in self.cidr:
            output = self._run_cmd(["arp-scan", self.cidr], timeout=120)
        self._save_log("lan_engine_arp.txt", output)
        meta: dict[str, dict] = {}
        for line in output.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2 and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0].strip()):
                ip = parts[0].strip()
                meta[ip] = {
                    "mac": parts[1].strip() if len(parts) > 1 else "",
                    "vendor": parts[2].strip() if len(parts) > 2 else "",
                }
        if meta:
            log(f"arp-scan: {len(meta)} host(s) with MAC/vendor.", "SUCCESS")
        return meta

    def _discover_live_hosts(self) -> list[str]:
        log(f"Phase 1/4: Host discovery on {self.cidr} ...", "INFO")
        output = self._run_nmap(["-sn", "-T4", "--max-retries", "1", self.cidr], timeout=300)
        self._save_log("lan_engine_nmap_hosts.txt", output)

        ips: list[str] = []
        for block in re.split(r"(?=Nmap scan report for )", output):
            ip_match = re.search(
                r"Nmap scan report for (?:([^\s(]+)\s)?\(?(\d+\.\d+\.\d+\.\d+)\)?",
                block,
            )
            if not ip_match:
                continue
            hostname = (ip_match.group(1) or "").strip()
            ip = ip_match.group(2)
            if ip.endswith(".0") or ip.endswith(".255"):
                continue
            mac_match = re.search(r"MAC Address:\s+([0-9A-Fa-f:]+)\s+\((.+?)\)", block)
            self._host_meta.setdefault(ip, {})
            if hostname and hostname != ip:
                self._host_meta[ip]["hostname"] = hostname
            if mac_match:
                self._host_meta[ip]["mac"] = mac_match.group(1)
                self._host_meta[ip]["vendor"] = mac_match.group(2)
            if ip not in ips:
                ips.append(ip)

        arp_meta = self._arp_scan_hosts()
        for ip, info in arp_meta.items():
            self._host_meta.setdefault(ip, {}).update(info)
            if ip not in ips:
                ips.append(ip)

        if ips:
            log(f"Found {len(ips)} live host(s).", "SUCCESS")
            return sorted(ips, key=lambda x: tuple(int(p) for p in x.split(".")))

        log("Falling back to ping sweep.", "WARNING")
        return self._discover_live_hosts_ping()

    def _discover_live_hosts_ping(self) -> list[str]:
        ips: list[str] = []
        for i in range(1, 255):
            ip = f"{self.subnet}{i}"
            try:
                if ping_host(ip):
                    ips.append(ip)
            except OSError:
                continue
        return ips

    def _port_scan_hosts(self, ips: list[str]) -> dict[str, list[dict]]:
        if not ips:
            return {}

        log(
            f"Phase 2/4: Nmap service scan (-sV) on {len(ips)} host(s), top 200 ports ...",
            "INFO",
        )
        host_services: dict[str, list[dict]] = {ip: [] for ip in ips}

        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as fh:
            fh.write("\n".join(ips))
            hostfile = fh.name
        try:
            output = self._run_nmap(
                ["-Pn", "-sV", "-T4", "--version-light", "--open", "--top-ports", "200", "-iL", hostfile],
                timeout=max(900, len(ips) * 45),
            )
            self._save_log("lan_engine_nmap_ports.txt", output)
            host_services = self._parse_nmap_batch(output, ips)
        finally:
            try:
                os.unlink(hostfile)
            except OSError:
                pass

        if not any(host_services.values()):
            log("Using quick TCP probe fallback.", "WARNING")
            for ip in ips:
                host_services[ip] = [{"port": p, "service": "open"} for p in self._quick_port_probe(ip)]
        return host_services

    def _parse_nmap_batch(self, output: str, ips: list[str]) -> dict[str, list[dict]]:
        result: dict[str, list[dict]] = {ip: [] for ip in ips}
        if not output:
            return result
        for block in re.split(r"(?=Nmap scan report for )", output):
            ip_match = re.search(
                r"Nmap scan report for (?:[^\s(]+)\s)?\(?(\d+\.\d+\.\d+\.\d+)\)?",
                block,
            )
            if not ip_match:
                continue
            ip = ip_match.group(1)
            if parse_nmap:
                parsed = parse_nmap(block)
                for entry in parsed:
                    port = entry.get("port")
                    if port and port > 0:
                        result.setdefault(ip, []).append({
                            "port": port,
                            "service": entry.get("service", "open"),
                        })
                vendor = next((p.get("vendor") for p in parsed if p.get("port") == 0), None)
                if vendor:
                    self._host_meta.setdefault(ip, {})["vendor"] = vendor
                os_entry = next((p for p in parsed if p.get("port") == -1), None)
                if os_entry:
                    self._host_meta.setdefault(ip, {})["os"] = os_entry.get("os_details", "")
                    self._host_meta.setdefault(ip, {})["os_family"] = os_entry.get("os_family", "")
        return result

    def _quick_port_probe(self, ip: str) -> list[int]:
        import socket

        ports: list[int] = []
        for port in sorted(HTTP_PORTS | {22, 445, 53, 554, 37777}):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.35)
            try:
                if sock.connect_ex((ip, port)) == 0:
                    ports.append(port)
            except OSError:
                pass
            finally:
                sock.close()
        return ports

    @staticmethod
    def _is_http_service(port: int, service: str) -> bool:
        svc = (service or "").lower()
        if any(svc.startswith(p) for p in HTTP_SERVICE_PREFIXES):
            return True
        if "http" in svc:
            return True
        return port in HTTP_PORTS

    @staticmethod
    def _best_web_target(ip: str, services: list[dict]) -> tuple[str | None, int | None]:
        http_entries = [
            s for s in services
            if LANScanner._is_http_service(s.get("port", 0), s.get("service", ""))
        ]
        if not http_entries:
            return None, None
        priority = list(HTTP_PORTS) + [s["port"] for s in http_entries]
        seen = set()
        ordered = []
        for p in priority:
            if p in seen:
                continue
            if any(s["port"] == p for s in http_entries):
                ordered.append(p)
                seen.add(p)
        port = ordered[0]
        if port in (443, 8443):
            return (f"https://{ip}" if port == 443 else f"https://{ip}:{port}"), port
        return (f"http://{ip}" if port == 80 else f"http://{ip}:{port}"), port

    @staticmethod
    def _classify_from_services(vendor: str, services: list[dict]) -> str:
        vendor_l = (vendor or "").lower()
        svc_text = " ".join((s.get("service") or "").lower() for s in services)
        ports = {s.get("port") for s in services}

        if any(k in vendor_l for k in ("hikvision", "dahua", "xm", "dvr")):
            return "CAMERA/DVR"
        if any(k in vendor_l for k in ("tp-link", "tplink", "d-link", "netgear", "cisco", "ubiquiti", "mikrotik")):
            return "ROUTER/AP"
        if any(k in vendor_l for k in ("raspberry", "arduino", "espressif")):
            return "IoT/EMBED"

        if "rtsp" in svc_text or 554 in ports or 8554 in ports:
            return "CAMERA/DVR"
        if 37777 in ports or 34567 in ports:
            return "CAMERA/DVR"
        if "domain" in svc_text or (53 in ports and not HTTP_PORTS.intersection(ports)):
            return "DNS"
        if "microsoft-ds" in svc_text or "netbios" in svc_text or 445 in ports:
            return "WINDOWS/SMB"
        if "ssh" in svc_text or (22 in ports and not HTTP_PORTS.intersection(ports)):
            return "LINUX/SSH"
        if any(k in svc_text for k in ("http", "https", "nginx", "apache", "lighttpd")):
            return "WEB/IoT"
        if HTTP_PORTS.intersection(ports):
            return "WEB/IoT"
        if ports:
            return "HOST/SVC"
        return "UNKNOWN"

    def _nmap_http_enrich(self, ip: str, http_ports: list[int]) -> dict:
        if not http_ports or not shutil.which("nmap"):
            return {}
        ports_csv = ",".join(str(p) for p in http_ports[:8])
        output = self._run_nmap(
            ["-Pn", "-p", ports_csv, "--script", "http-title,http-server-header", ip],
            timeout=90,
        )
        info: dict = {}
        title_m = re.search(r"http-title:\s*\|?\s*(.+)", output)
        if title_m:
            info["http_title"] = title_m.group(1).strip().strip('"')
        server_m = re.search(r"http-server-header:\s*\|?\s*(.+)", output)
        if server_m:
            info["http_server"] = server_m.group(1).strip().strip('"')
        return info

    def _whatweb_enrich(self, url: str) -> str:
        if not shutil.which("whatweb") or not url:
            return ""
        output = self._run_cmd(["whatweb", "-q", url], timeout=45)
        return output.splitlines()[0].strip() if output else ""

    def _fingerprint_http(self, url: str) -> str:
        try:
            return Fingerprinter(url).identify()
        except requests.RequestException:
            return "UNKNOWN"
        except Exception:
            return "UNKNOWN"

    def _build_device(self, ip: str, services: list[dict]) -> dict:
        meta = self._host_meta.get(ip, {})
        vendor = meta.get("vendor", "")
        ports = sorted({s["port"] for s in services if s.get("port")})
        device_type = self._classify_from_services(vendor, services)
        url, web_port = self._best_web_target(ip, services)

        http_info: dict = {}
        if url:
            http_ports = [s["port"] for s in services if self._is_http_service(s["port"], s.get("service", ""))]
            http_info = self._nmap_http_enrich(ip, http_ports)
            fp_type = self._fingerprint_http(url)
            if fp_type and fp_type != "UNKNOWN":
                device_type = fp_type
            elif http_info.get("http_title"):
                title = http_info["http_title"].lower()
                if "hikvision" in title:
                    device_type = "HIKVISION"
                elif "router" in title or "gateway" in title:
                    device_type = "ROUTER"

            whatweb = self._whatweb_enrich(url)
            if whatweb:
                http_info["whatweb"] = whatweb

        services_label = ", ".join(
            f"{s['port']}/{s.get('service', '?').split()[0]}"
            for s in sorted(services, key=lambda x: x["port"])[:8]
        )
        if len(services) > 8:
            services_label += f", +{len(services) - 8}"

        return {
            "ip": ip,
            "hostname": meta.get("hostname", ""),
            "mac": meta.get("mac", ""),
            "vendor": vendor,
            "os": meta.get("os", ""),
            "port": web_port or (ports[0] if ports else None),
            "type": device_type,
            "open_ports": ports,
            "services": services,
            "services_label": services_label,
            "http_title": http_info.get("http_title", ""),
            "http_server": http_info.get("http_server", ""),
            "whatweb": http_info.get("whatweb", ""),
            "url": url or (f"http://{ip}" if ports else ""),
        }

    def _save_log(self, name: str, content: str) -> None:
        if not content:
            return
        os.makedirs(self._log_dir, exist_ok=True)
        with open(os.path.join(self._log_dir, name), "w", encoding="utf-8") as fh:
            fh.write(content)

    def _save_results(self) -> None:
        os.makedirs(self._log_dir, exist_ok=True)
        path = os.path.join(self._log_dir, "lan_engine_devices.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({
                "scanned_at": datetime.now().isoformat(timespec="seconds"),
                "subnet": self.cidr,
                "devices": self.discovered_devices,
            }, fh, indent=2, ensure_ascii=False)

    def run_scan(self):
        log(f"Starting LAN Scan on {self.cidr} (nmap + arp-scan + service detect) ...", "INFO")
        if not shutil.which("nmap"):
            log("Install: sudo apt install nmap arp-scan whatweb", "WARNING")

        live_ips = self._discover_live_hosts()
        if not live_ips:
            log("No devices found.", "ERROR")
            return []

        host_services = self._port_scan_hosts(live_ips)
        log("Phase 3/4: Classify + HTTP scripts (http-title) ...", "INFO")

        self.discovered_devices = []
        for ip in live_ips:
            services = host_services.get(ip) or []
            device = self._build_device(ip, services)
            self.discovered_devices.append(device)
            extra = device.get("services_label") or "no open ports"
            vendor = device.get("vendor") or "?"
            log(f"  {ip} | {device['type']} | {vendor} | {extra}", "SUCCESS" if services else "INFO")

        log("Phase 4/4: Done. See logs/lan_engine_devices.json", "SUCCESS")
        self._save_results()
        return self.discovered_devices

    def display_results(self):
        if not self.discovered_devices:
            log("No devices found.", "ERROR")
            return None
        _print_device_table(self.discovered_devices)
        try:
            choice = input("\n[?] Select Device ID to attack (or 'q' to quit): ").strip()
            if choice.lower() == "q":
                return None
            idx = int(choice) - 1
            if 0 <= idx < len(self.discovered_devices):
                return self.discovered_devices[idx]
        except (ValueError, EOFError):
            print("Invalid selection.")
        return None


def _print_device_table(devices: list[dict]) -> None:
    print("\n" + "=" * 100)
    print("  LAN SCAN — nmap -sV + arp-scan + http-title (+ whatweb if installed)")
    print("=" * 100)
    print(f"  {'#':<3} {'IP':<16} {'Type':<14} {'Vendor':<18} {'Ports/Services'}")
    print("  " + "-" * 96)
    for i, dev in enumerate(devices):
        vendor = (dev.get("vendor") or "—")[:17]
        svc = dev.get("services_label") or "—"
        title = dev.get("http_title") or ""
        if title:
            svc += f' | "{title[:40]}"'
        print(f"  [{i + 1:<2}] {dev['ip']:<16} {dev.get('type', '?'):<14} {vendor:<18} {svc}")
    print("=" * 100)
    print("  Logs: logs/lan_engine_nmap_ports.txt | lan_engine_devices.json")


def format_device_line(dev: dict, index: int) -> str:
    vendor = (dev.get("vendor") or "—")[:16]
    svc = dev.get("services_label") or "—"
    title = f' | {dev["http_title"][:35]}' if dev.get("http_title") else ""
    return (
        f"  [{index}] IP: {dev['ip']:<15} | {dev.get('type', '?'):<12} | "
        f"{vendor} | {svc}{title}"
    )
