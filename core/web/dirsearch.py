import os

from core.scan_config import get_scan_profile
from core.utils import TOOLS_DIR, PYTHON, missing_python_modules, install_python_packages, run_cmd

DIRSEARCH_PATH = os.path.join(TOOLS_DIR, "dirsearch", "dirsearch.py")


def ensure_dirsearch_deps():
    missing = missing_python_modules()
    if not missing:
        return True
    print("[*] Ensuring Python dependencies required by Dirsearch...")
    if not install_python_packages(["mysql-connector-python", "defusedxml", "colorama"]):
        print("[!] Failed to install Dirsearch core dependencies.")
        return False
    still_missing = missing_python_modules()
    if still_missing:
        print(f"[!] Missing Python modules after install: {', '.join(still_missing)}")
        return False
    return True


def run_dirsearch(target_url, target_dir):
    profile = get_scan_profile()
    print(f"\n[+] Running Dirsearch (Path Enumeration) [{profile['label']}]...")
    if not os.path.exists(DIRSEARCH_PATH):
        print(f"[-] Dirsearch not found at {DIRSEARCH_PATH}")
        return []
    if not ensure_dirsearch_deps():
        print("[-] Dirsearch dependencies are missing; skipping.")
        return []

    port = target_url.split(":")[-1] if ":" in target_url.replace("https://", "").replace("http://", "") else "80"
    log_file = os.path.join(target_dir, f"dirsearch_port_{port}.txt")
    stdout_log = os.path.join(target_dir, f"dirsearch_port_{port}_stdout.txt")
    command = [
        PYTHON, DIRSEARCH_PATH,
        "-u", target_url,
        "-e", "php,html,bak,js,txt,xml,conf",
        "-x", "404,500",
        "-t", str(profile["dirsearch_threads"]),
        "-o", log_file,
        "--no-color",
    ]
    success, output = run_cmd(command, capture=True, log_file=stdout_log)
    if not success:
        print(f"[-] Dirsearch failed for {target_url}. Check {stdout_log}")

    discovered = []
    for source in [log_file, stdout_log]:
        if not os.path.exists(source):
            continue
        with open(source, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("Usage:"):
                    continue
                if line.startswith("http://") or line.startswith("https://"):
                    discovered.append(line)
                    continue
                if line.startswith("/"):
                    discovered.append(target_url.rstrip("/") + line)
                    continue
                parts = line.split()
                if len(parts) >= 2 and parts[1].startswith(("http://", "https://")):
                    discovered.append(parts[1])
                    continue
                if len(parts) >= 2 and parts[1].startswith("/"):
                    discovered.append(target_url.rstrip("/") + parts[1])
                    continue
                if "://" not in line and line and line[0].isalnum() and "error" not in line.lower():
                    discovered.append(f"{target_url.rstrip('/')}/{line}")

    discovered = list(dict.fromkeys(discovered))
    print(f"[+] Dirsearch results saved to: {log_file}")
    if discovered:
        print(f"[+] Dirsearch discovered {len(discovered)} paths.")
    return discovered
