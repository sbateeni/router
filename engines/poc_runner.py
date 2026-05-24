"""Run GitHub PoCs from scripts/new_pocs/ against the current target."""

import os
import re
import subprocess
import sys

from engines.utils import log

POC_DIR = "scripts/new_pocs"
SKIP_DIRS = {".git", "__pycache__", "venv", ".venv", "node_modules"}
SKIP_FILES = {"setup.py", "conftest.py", "__init__.py"}

DEVICE_KEYWORDS: dict[str, list[str]] = {
    "HIKVISION": ["hikvision", "hik", "dvr", "nvr", "camera"],
    "DAHUA": ["dahua", "dvr", "camera"],
    "ZTE": ["zte", "router", "gateway"],
    "NETIS": ["netis", "router"],
    "TPLINK": ["tp-link", "tplink", "router"],
    "MIKROTIK": ["mikrotik", "router"],
    "OPENWRT": ["openwrt", "luci", "router"],
    "GENERIC_ROUTER": ["router", "iot", "gateway", "wan"],
    "GENERIC_CAMERA": ["camera", "cctv", "ipcam", "surveillance"],
    "LINUX": ["linux", "rce", "shell"],
    "UNKNOWN": ["exploit", "poc", "rce", "cve"],
}


class PoCRunner:
    def __init__(self, target_ip: str, port: int = 80, poc_dir: str = POC_DIR):
        self.target_ip = target_ip
        self.port = port
        self.poc_dir = poc_dir
        self.target_url = f"http://{target_ip}:{port}"

    def discover_pocs(self) -> list[dict]:
        """Find runnable Python scripts under scripts/new_pocs/."""
        if not os.path.isdir(self.poc_dir):
            return []

        pocs: list[dict] = []
        for root, dirs, files in os.walk(self.poc_dir):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for name in files:
                if not name.endswith(".py") or name in SKIP_FILES:
                    continue
                path = os.path.join(root, name)
                try:
                    with open(path, encoding="utf-8", errors="ignore") as f:
                        head = f.read(4096).lower()
                except OSError:
                    continue

                if "__main__" not in head and "argparse" not in head:
                    # Still allow if filename looks like exploit
                    if not any(k in name.lower() for k in ("exploit", "poc", "cve", "rce")):
                        continue

                rel = os.path.relpath(path, self.poc_dir)
                pocs.append({
                    "path": path,
                    "rel": rel,
                    "name": name,
                    "text": head,
                    "keywords": self._keywords_from_text(head + " " + name.lower()),
                })
        return pocs

    @staticmethod
    def _keywords_from_text(text: str) -> set[str]:
        tokens = set(re.findall(r"[a-z0-9]+", text.lower()))
        return tokens

    def score_poc(self, poc: dict, device_type: str) -> int:
        score = 0
        dt = device_type.upper()
        for keyword in DEVICE_KEYWORDS.get(dt, []) + DEVICE_KEYWORDS.get("UNKNOWN", []):
            if keyword in poc["keywords"] or keyword in poc["text"]:
                score += 2
        if self.target_ip in poc["text"]:
            score += 1
        if "router" in poc["text"] and dt in ROUTER_TYPES:
            score += 1
        if "camera" in poc["text"] and dt in CAMERA_TYPES:
            score += 1
        return score

    def match_pocs(self, device_type: str, min_score: int = 2, limit: int = 5) -> list[dict]:
        ranked = []
        for poc in self.discover_pocs():
            s = self.score_poc(poc, device_type)
            if s >= min_score:
                ranked.append((s, poc))
        ranked.sort(key=lambda x: x[0], reverse=True)
        return [p for _, p in ranked[:limit]]

    def _invoke_variants(self, script_path: str) -> list[list[str]]:
        ip, port, url = self.target_ip, str(self.port), self.target_url
        py = sys.executable
        return [
            [py, script_path, ip],
            [py, script_path, "--target", ip],
            [py, script_path, "-t", ip],
            [py, script_path, "--ip", ip],
            [py, script_path, "-u", url],
            [py, script_path, "--url", url],
            [py, script_path, ip, port],
        ]

    def run_poc(self, script_path: str, timeout: int = 90) -> dict:
        """Try common CLI patterns used by GitHub PoCs."""
        last_result = {"script": script_path, "success": False, "output": "", "cmd": None}

        for cmd in self._invoke_variants(script_path):
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    cwd=os.path.dirname(script_path) or None,
                )
            except subprocess.TimeoutExpired:
                last_result["output"] = "timeout"
                continue
            except Exception as exc:
                last_result["output"] = str(exc)
                continue

            out = (proc.stdout or "") + (proc.stderr or "")
            last_result.update({"output": out[:2000], "cmd": " ".join(cmd)})

            success_markers = (
                "success", "pwned", "exploit completed", "shell", "vulnerable",
                "access granted", "rce", "command executed",
            )
            if proc.returncode == 0 or any(m in out.lower() for m in success_markers):
                last_result["success"] = True
                return last_result

        return last_result

    def run_matching(self, device_type: str) -> list[dict]:
        matches = self.match_pocs(device_type)
        if not matches:
            log(f"No matching PoCs in {self.poc_dir} for device type {device_type}.", "INFO")
            return []

        log(f"Running {len(matches)} GitHub PoC(s) for {device_type}...", "INFO")
        results = []
        for poc in matches:
            log(f"  PoC: {poc['rel']}", "INFO")
            result = self.run_poc(poc["path"])
            result["rel"] = poc["rel"]
            results.append(result)
            if result["success"]:
                log(f"  PoC reported success: {poc['rel']}", "PWN")
            else:
                log(f"  PoC finished (no clear success): {poc['rel']}", "INFO")
        return results


ROUTER_TYPES = {
    "NETIS", "TPLINK", "DLINK", "ZTE", "MIKROTIK", "OPENWRT", "CISCO", "UBIQUITI", "SYNOLOGY",
    "GENERIC_ROUTER",
}
CAMERA_TYPES = {"HIKVISION", "DAHUA", "GENERIC_DVR", "GENERIC_CAMERA"}
