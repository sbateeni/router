import subprocess
import json
import re
import socket
import os
import shutil
from engines.utils import log

def _resolve_nuclei_path():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    names = ("nuclei.exe", "nuclei") if os.name == "nt" else ("nuclei", "nuclei.exe")
    for sub in ("tools/nuclei", "bin", "tools"):
        for name in names:
            path = os.path.join(root, sub.replace("/", os.sep), name)
            if os.path.exists(path):
                return path
    found = shutil.which("nuclei")
    if found:
        return found
    return os.path.join(root, "bin", names[0])

class Scanner:
    def __init__(self, nuclei_path=None):
        self.nuclei_path = nuclei_path or _resolve_nuclei_path()

    def _check_ports(self, target_ip, ports, label=""):
        """فحص قائمة منافذ وإرجاع المفتوحة"""
        open_ports = []
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                log(f"Found open {label} port: {port}", "SUCCESS")
                open_ports.append(port)
            sock.close()
        return open_ports

    def discover_ports(self, target_ip):
        """فحص شامل للمنافذ المشهورة للكاميرات والراوترات (HTTP/HTTPS فقط)"""
        web_ports = [
            80, 443, 81, 88, 1080, 8000, 8080, 8081, 8443, 8888, 9000, 9090, 7755,
            35990, 47960, 37777, 34567, 1024, 8008, 8088, 5000, 5001,
        ]
        log(f"Searching for open web ports on {target_ip}...")
        return self._check_ports(target_ip, web_ports, "WEB")

    def discover_rtsp_ports(self, target_ip):
        """فحص منفذ RTSP للكاميرات"""
        rtsp_ports = [554, 8554]
        log(f"Searching for open RTSP ports on {target_ip}...")
        return self._check_ports(target_ip, rtsp_ports, "RTSP")

    def discover_ssh_ports(self, target_ip):
        """فحص منافذ SSH الشائعة وغير التقليدية"""
        ssh_ports = [22, 2222, 2378, 2200, 8022, 22222]
        log(f"Searching for open SSH ports on {target_ip}...")
        return self._check_ports(target_ip, ssh_ports, "SSH")

    def scan(self, target):
        log(f"Starting Live Nuclei Scan on {target}...")
        findings = []
        tags = "cve,env,exposed-panel,hikvision,laravel,zte,upnp,rce"
        # تشغيل نيوكلي بدون وضع الصامت لرؤية كل شيء
        cmd = [self.nuclei_path, "-u", target, "-tags", tags, "-jsonl"]
        
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, encoding='utf-8', errors='ignore')
            
            # قراءة المخرجات سطراً بسطر وتوجيهها للـ Monitor
            for line in process.stdout:
                line = line.strip()
                if line:
                    # إذا كان السطر يحتوي على نتيجة (JSON)
                    if line.startswith("{"):
                        try:
                            finding = json.loads(line)
                            tid = finding.get("template-id")
                            log(f"FINDING: {tid}", "PWN")
                            findings.append(finding)
                        except: pass
                    else:
                        # عرض المخرجات العادية (Progress, Info, Banner)
                        log(line, "INFO")
            
            process.wait()
        except Exception as e:
            log(f"Live Scan error: {e}", "ERROR")
        return findings

    def scan_specific_template(self, target, template_path):
        """فحص قالب محدد مع إظهار المخرجات"""
        log(f"Targeting: {template_path}")
        cmd = [self.nuclei_path, "-u", target, "-t", template_path, "-jsonl", "-silent"]
        findings = []
        try:
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, encoding="utf-8", errors="ignore",
            )
            for line in process.stdout:
                line = line.strip()
                if line.startswith("{"):
                    try:
                        finding = json.loads(line)
                        tid = finding.get("template-id", template_path)
                        log(f"CVE HIT: {tid}", "PWN")
                        findings.append(finding)
                    except json.JSONDecodeError:
                        pass
                elif line and "no templates" not in line.lower():
                    log(line, "INFO")
            process.wait()
        except Exception as e:
            log(f"Template scan error ({template_path}): {e}", "ERROR")
        return findings[0] if findings else None

    def scan_tags(self, target, tags: str):
        """فحص بوسوم CVE محددة (أسرع من الفحص الكامل)"""
        log(f"Nuclei tag scan: {tags}")
        findings = []
        cmd = [self.nuclei_path, "-u", target, "-tags", tags, "-jsonl", "-silent", "-rate-limit", "30"]
        try:
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, encoding="utf-8", errors="ignore",
            )
            for line in process.stdout:
                line = line.strip()
                if line.startswith("{"):
                    try:
                        finding = json.loads(line)
                        log(f"TAG FINDING: {finding.get('template-id')}", "PWN")
                        findings.append(finding)
                    except json.JSONDecodeError:
                        pass
            process.wait()
        except Exception as e:
            log(f"Tag scan error: {e}", "ERROR")
        return findings

    def scan_cve_intel(self, target, intel) -> list:
        """Run all Nuclei checks from DeviceIntel CVE assessment."""
        from engines.device_cve_checker import run_targeted_nuclei
        return run_targeted_nuclei(self, target, intel)

    def detect_os_with_nmap(self, target_ip: str) -> dict:
        """
        Run nmap -O -sV to detect OS family and service versions.
        Returns: {"os_family": "WINDOWS"|"LINUX"|"MACOS"|"UNKNOWN_OS", "os_details": "..."}
        Also saves result to targets/{ip}/recon_summary.json for caching.
        """
        import shutil, json, os

        result = {"os_family": "UNKNOWN_OS", "os_details": ""}

        # Check cache first
        cache_path = os.path.join("targets", target_ip, "recon_summary.json")
        if os.path.exists(cache_path):
            try:
                with open(cache_path, 'r') as f:
                    cached = json.load(f)
                    if cached.get("os_family") and cached["os_family"] != "UNKNOWN_OS":
                        log(f"[Cache] OS: {cached['os_family']} ({cached.get('os_details','')})", "INFO")
                        return cached
            except Exception:
                pass

        nmap_bin = shutil.which("nmap")
        if not nmap_bin:
            log("nmap not found in PATH — OS detection skipped.", "WARNING")
            return result

        log(f"Running Nmap OS detection on {target_ip} (requires sudo/root for -O)...", "INFO")
        cmd = ["nmap", "-O", "-sV", "--osscan-guess", "--max-retries", "2",
               "-T4", "--open", target_ip]

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=90, encoding="utf-8", errors="ignore"
            )
            output = proc.stdout + proc.stderr

            # Parse OS family
            os_family = "UNKNOWN_OS"
            os_details = ""

            # Look for "OS details:" or "Aggressive OS guesses:"
            details_match = re.search(
                r"OS details:\s*(.+)", output, re.IGNORECASE
            )
            guess_match = re.search(
                r"Aggressive OS guesses:\s*(.+?)(?:\n|$)", output, re.IGNORECASE
            )
            running_match = re.search(
                r"Running(?:\s*\(JUST GUESSING\))?:\s*(.+)", output, re.IGNORECASE
            )

            raw_os = ""
            if details_match:
                raw_os = details_match.group(1).strip()
            elif guess_match:
                raw_os = guess_match.group(1).strip().split(",")[0].strip()
            elif running_match:
                raw_os = running_match.group(1).strip()

            if raw_os:
                os_details = raw_os
                lower = raw_os.lower()
                if any(k in lower for k in ["windows", "win32", "win64", "microsoft"]):
                    os_family = "WINDOWS"
                elif any(k in lower for k in ["linux", "ubuntu", "debian", "centos", "kali", "fedora", "red hat"]):
                    os_family = "LINUX"
                elif any(k in lower for k in ["mac os", "macos", "darwin", "apple"]):
                    os_family = "MACOS"
                elif any(k in lower for k in ["unix", "bsd", "freebsd", "openbsd", "solaris"]):
                    os_family = "UNIX"
                elif any(k in lower for k in ["ios", "ios-xe", "nx-os", "cisco"]):
                    os_family = "CISCO_IOS"
                else:
                    os_family = "LINUX"  # Default to Linux if something detected but unrecognized

            result = {"os_family": os_family, "os_details": os_details}

            # Cache the result
            try:
                os.makedirs(os.path.dirname(cache_path), exist_ok=True)
                with open(cache_path, 'w') as f:
                    json.dump(result, f, indent=2)
            except Exception:
                pass

            if os_family != "UNKNOWN_OS":
                log(f"OS Detected: {os_family} — {os_details}", "SUCCESS")
            else:
                log("OS detection inconclusive (try running with sudo for -O accuracy).", "WARNING")

        except subprocess.TimeoutExpired:
            log("Nmap OS detection timed out.", "WARNING")
        except Exception as e:
            log(f"Nmap OS detection error: {e}", "ERROR")

        return result
