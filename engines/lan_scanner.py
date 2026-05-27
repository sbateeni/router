"""LAN discovery for Device Engine — nmap host discovery + port scan before AUTO-PWN."""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from datetime import datetime
from urllib.parse import urlparse

from engines.fingerprinter import Fingerprinter
from engines.platform_utils import ping_host
from engines.utils import log

try:
    from core.scanner import parse_nmap
except ImportError:
    parse_nmap = None

WEB_PORT_PRIORITY = (
    80, 443, 8080, 8443, 8000, 8081, 81, 8888, 9000, 9090,
    37777, 34567, 5000, 5001, 8008, 8088, 554, 8554, 22, 23,
)


class LANScanner:
    def __init__(self):
        self.local_ip = self.get_local_ip()
        self.subnet = ".".join(self.local_ip.split(".")[:-1]) + "."
        self.cidr = self.subnet + "0/24"
        self.discovered_devices: list[dict] = []
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

    def _run_nmap(self, args: list[str], timeout: int = 600) -> str:
        if not self._nmap_available():
            return ""
        try:
            result = subprocess.run(
                ["nmap", *args],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            output = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
            return output.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            log(f"Nmap error: {exc}", "ERROR")
            return ""

    @staticmethod
    def _nmap_available() -> bool:
        import shutil

        return bool(shutil.which("nmap"))

    def _discover_live_hosts_nmap(self) -> list[str]:
        log(f"Phase 1/3: Nmap host discovery on {self.cidr} ...", "INFO")
        output = self._run_nmap(["-sn", "-T4", "--max-retries", "1", self.cidr], timeout=300)
        ips: list[str] = []
        for match in re.finditer(
            r"Nmap scan report for (?:[^\s(]+\s)?\(?(\d+\.\d+\.\d+\.\d+)\)?",
            output,
        ):
            ip = match.group(1)
            if ip.endswith(".0") or ip.endswith(".255"):
                continue
            if ip not in ips:
                ips.append(ip)
        if ips:
            log(f"Nmap found {len(ips)} live host(s).", "SUCCESS")
            return ips

        log("Nmap host discovery empty — falling back to ping sweep.", "WARNING")
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
        log(f"Ping sweep found {len(ips)} host(s).", "SUCCESS" if ips else "ERROR")
        return ips

    def _port_scan_hosts(self, ips: list[str]) -> dict[str, list[int]]:
        if not ips:
            return {}

        log(f"Phase 2/3: Nmap port scan on {len(ips)} host(s) (--top-ports 200) ...", "INFO")
        if self._nmap_available():
            host_ports = self._nmap_batch_port_scan(ips)
            if host_ports:
                return host_ports

        log("Using quick TCP probe on common IoT/router ports.", "WARNING")
        return {ip: self._quick_port_probe(ip) for ip in ips}

    def _nmap_batch_port_scan(self, ips: list[str]) -> dict[str, list[int]]:
        host_ports: dict[str, list[int]] = {ip: [] for ip in ips}
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as fh:
            fh.write("\n".join(ips))
            hostfile = fh.name
        try:
            output = self._run_nmap(
                ["-Pn", "-T4", "--open", "--top-ports", "200", "-iL", hostfile],
                timeout=max(600, len(ips) * 30),
            )
            self._save_log("lan_engine_nmap_ports.txt", output)
            if output and parse_nmap:
                for block in re.split(r"(?=Nmap scan report for )", output):
                    ip_match = re.search(
                        r"Nmap scan report for (?:[^\s(]+\s)?\(?(\d+\.\d+\.\d+\.\d+)\)?",
                        block,
                    )
                    if not ip_match:
                        continue
                    ip = ip_match.group(1)
                    parsed = parse_nmap(block)
                    host_ports[ip] = sorted(
                        {entry["port"] for entry in parsed if entry.get("port")}
                    )
        finally:
            try:
                os.unlink(hostfile)
            except OSError:
                pass
        return host_ports

    def _quick_port_probe(self, ip: str) -> list[int]:
        import socket

        open_ports: list[int] = []
        for port in WEB_PORT_PRIORITY:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.4)
            try:
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
            except OSError:
                pass
            finally:
                sock.close()
        return open_ports

    @staticmethod
    def _best_web_target(ip: str, ports: list[int]) -> tuple[str | None, int | None]:
        if not ports:
            return None, None
        ordered = [p for p in WEB_PORT_PRIORITY if p in ports]
        ordered.extend(p for p in sorted(ports) if p not in ordered)
        port = ordered[0]
        if port in (443, 8443):
            url = f"https://{ip}" if port == 443 else f"https://{ip}:{port}"
        else:
            url = f"http://{ip}" if port == 80 else f"http://{ip}:{port}"
        return url, port

    def _fingerprint_device(self, ip: str, ports: list[int]) -> dict:
        url, web_port = self._best_web_target(ip, ports)
        device_type = "UNKNOWN"
        if url:
            try:
                device_type = Fingerprinter(url).identify()
            except Exception:
                device_type = "UNKNOWN"
        elif ports:
            if 554 in ports or 37777 in ports or 8000 in ports:
                device_type = "CAMERA/DVR"
            elif 22 in ports and not any(p in ports for p in (80, 443, 8080)):
                device_type = "SSH/HOST"

        return {
            "ip": ip,
            "port": web_port or (ports[0] if ports else None),
            "type": device_type,
            "open_ports": ports,
            "url": url or f"http://{ip}",
        }

    def _save_log(self, name: str, content: str) -> None:
        if not content:
            return
        os.makedirs(self._log_dir, exist_ok=True)
        path = os.path.join(self._log_dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)

    def _save_results(self) -> None:
        os.makedirs(self._log_dir, exist_ok=True)
        path = os.path.join(self._log_dir, "lan_engine_devices.json")
        payload = {
            "scanned_at": datetime.now().isoformat(timespec="seconds"),
            "subnet": self.cidr,
            "devices": self.discovered_devices,
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)

    def run_scan(self):
        """Discover hosts, nmap ports, fingerprint — then return device list."""
        log(f"Starting LAN Scan on subnet {self.cidr} ...", "INFO")
        if not self._nmap_available():
            log("nmap not installed — using ping + TCP probe only (sudo apt install nmap)", "WARNING")

        live_ips = self._discover_live_hosts_nmap()
        if not live_ips:
            log("No devices found in the local network.", "ERROR")
            return []

        host_ports = self._port_scan_hosts(live_ips)
        log("Phase 3/3: Fingerprinting web services ...", "INFO")

        self.discovered_devices = []
        for ip in live_ips:
            ports = host_ports.get(ip) or []
            device = self._fingerprint_device(ip, ports)
            self.discovered_devices.append(device)
            ports_label = ",".join(str(p) for p in ports[:15]) if ports else "none"
            log(
                f"  {ip} | {device['type']} | ports: {ports_label}",
                "SUCCESS" if ports else "INFO",
            )

        self._save_results()
        return self.discovered_devices

    def display_results(self):
        if not self.discovered_devices:
            log("No devices found in the local network.", "ERROR")
            return None

        print("\n" + "=" * 68)
        print("      LAN SCAN RESULTS — NMAP + FINGERPRINT")
        print("=" * 68)
        for i, dev in enumerate(self.discovered_devices):
            ports = dev.get("open_ports") or []
            ports_str = ",".join(str(p) for p in ports[:12])
            if len(ports) > 12:
                ports_str += f",+{len(ports) - 12}"
            print(
                f"  [{i + 1}] IP: {dev['ip']:<15} | Type: {dev['type']:<12} | "
                f"Ports: {ports_str or '—'}"
            )
        print("=" * 68)

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
