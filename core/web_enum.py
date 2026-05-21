import json
import os
import glob
import shutil
import sys

from core.utils import run_cmd, TOOLS_DIR, PYTHON, missing_python_modules

DIRSEARCH_PATH = os.path.join(TOOLS_DIR, "dirsearch", "dirsearch.py")
DIRSEARCH_REQUIREMENTS = os.path.join(TOOLS_DIR, "dirsearch", "requirements.txt")
SQLMAP_PATH = os.path.join(TOOLS_DIR, "sqlmap", "sqlmap.py")
NUCLEI_CMD = os.path.join(TOOLS_DIR, "nuclei", "v2", "cmd", "nuclei", "nuclei")
if not os.path.exists(NUCLEI_CMD):
    NUCLEI_CMD = "nuclei"


def ensure_dirsearch_deps():
    missing = missing_python_modules()
    if not missing and not os.path.exists(DIRSEARCH_REQUIREMENTS):
        return True

    print("[*] Installing Python dependencies required by Dirsearch...")
    commands = []
    if os.path.exists(DIRSEARCH_REQUIREMENTS):
        commands.append([PYTHON, "-m", "pip", "install", "-r", DIRSEARCH_REQUIREMENTS, "--break-system-packages"])
    if missing:
        commands.append([PYTHON, "-m", "pip", "install", "mysql-connector-python", "defusedxml", "colorama", "--break-system-packages"])

    for command in commands:
        result = __import__("subprocess").run(command)
        if result.returncode != 0:
            print("[!] Failed to install Dirsearch dependencies.")
            return False

    still_missing = missing_python_modules()
    if still_missing:
        print(f"[!] Missing Python modules after install: {', '.join(still_missing)}")
        return False
    return True


def nuclei_templates_installed():
    """Return True if it looks like nuclei templates exist locally."""
    candidates = [
        os.path.expanduser("~/.nuclei/templates"),
        os.path.expanduser("~/.config/nuclei/templates"),
        os.path.join(os.path.expanduser("~"), ".local", "nuclei-templates"),
        os.path.join(os.path.expanduser("~"), ".local", "share", "nuclei-templates"),
        os.path.join(TOOLS_DIR, "nuclei-templates"),
        os.path.join("/usr/share/nuclei-templates"),
    ]
    for c in candidates:
        if os.path.exists(c) and any(glob.glob(os.path.join(c, "**", "*.yaml"), recursive=True)):
            return True
    try:
        home = os.path.expanduser("~")
        patterns = [
            os.path.join(home, "**", "nuclei-templates", "**", "*.yaml"),
            os.path.join(home, "**", "nuclei", "**", "*.yaml"),
        ]
        for pat in patterns:
            if any(glob.glob(pat, recursive=True)):
                return True
    except Exception:
        pass
    return False


def update_nuclei_templates():
    print("\n[+] Ensuring Nuclei templates are up-to-date...")
    commands = [[NUCLEI_CMD, "-ut"], [NUCLEI_CMD, "-update-templates"], [NUCLEI_CMD, "-ut", "-no-colors"]]
    success = False
    for command in commands:
        success, output = run_cmd(command, capture=True)
        if output:
            print(output)
        if success:
            break

    if not nuclei_templates_installed():
        print("[-] Nuclei templates not detected after update. Please ensure nuclei is installed and can access the network.")
        return False

    print("[+] Nuclei templates are present.")
    return success


def parse_nuclei_jsonl(jsonl_path):
    findings = []
    if not os.path.exists(jsonl_path):
        return findings

    with open(jsonl_path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return findings


def run_nuclei(target_url, target_dir):
    print("\n[+] Running Nuclei (Vulnerability Scanning)...")
    port = target_url.split(":")[-1] if ":" in target_url.replace("https://", "").replace("http://", "") else "80"
    log_txt = os.path.join(target_dir, f"nuclei_port_{port}.txt")
    log_jsonl = os.path.join(target_dir, f"nuclei_port_{port}.jsonl")
    stdout_log = os.path.join(target_dir, f"nuclei_port_{port}_stdout.txt")

    if not nuclei_templates_installed():
        ok = update_nuclei_templates()
        if not ok:
            print("[!] Skipping nuclei scan due to missing templates.")
            return False

    validate_log = os.path.join(target_dir, "nuclei_validate.txt")
    run_cmd([NUCLEI_CMD, "-validate"], capture=True, log_file=validate_log)

    def run_scan(base_command, export_path):
        if os.path.exists(export_path):
            os.remove(export_path)
        command = base_command + ["-silent", "-jle", export_path]
        return run_cmd(command, capture=True, log_file=stdout_log)

    base_cmd = [NUCLEI_CMD, "-u", target_url, "-no-color"]
    tag_cmd = base_cmd + ["-tags", "default-logins,cves,misconfiguration"]

    success, output = run_scan(tag_cmd, log_jsonl)
    findings = parse_nuclei_jsonl(log_jsonl)

    if not findings:
        log_jsonl2 = os.path.join(target_dir, f"nuclei_port_{port}_notags.jsonl")
        success2, output2 = run_scan(base_cmd, log_jsonl2)
        findings = parse_nuclei_jsonl(log_jsonl2)
        if output2:
            output = output2
        if success2:
            success = success2

    try:
        summary_lines = []
        if output:
            summary_lines.append(output)
        for item in findings:
            info = item.get("info", {})
            summary_lines.append(
                f"[{info.get('severity', 'unknown')}] {item.get('template-id', 'unknown')} -> {item.get('matched-at', target_url)}"
            )
        with open(log_txt, "w", encoding="utf-8") as fh:
            fh.write("\n".join(summary_lines))
    except OSError:
        pass

    if not success and not findings:
        print(f"[-] Nuclei scan failed for {target_url}. Check {stdout_log}")

    if findings:
        print(f"[!] Nuclei found {len(findings)} findings (saved to {log_jsonl}).")
        return True

    print(f"[+] Nuclei scan completed for {target_url}. No results found.")
    return False


def run_dirsearch(target_url, target_dir):
    print("\n[+] Running Dirsearch (Path Enumeration)...")
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
        "-t", "50",
        "--format", "plain",
        "-o", log_file,
        "--no-color",
    ]
    success, output = run_cmd(command, capture=True, log_file=stdout_log)
    if not success:
        print(f"[-] Dirsearch failed for {target_url}. Check {stdout_log}")

    discovered = []
    if os.path.exists(log_file):
        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("http://") or line.startswith("https://"):
                    discovered.append(line)
                elif line.startswith("/"):
                    discovered.append(target_url.rstrip("/") + line)
                elif "://" not in line and line[0].isalnum():
                    discovered.append(f"{target_url.rstrip('/')}/{line}")

    discovered = list(dict.fromkeys(discovered))
    print(f"[+] Dirsearch results saved to: {log_file}")
    if discovered:
        print(f"[+] Dirsearch discovered {len(discovered)} paths.")
    return discovered


def run_sqlmap(target_url, target_dir):
    print("\n[+] Running SQLMap (SQL Injection Test)...")
    if not os.path.exists(SQLMAP_PATH):
        print(f"[-] SQLMap not found at {SQLMAP_PATH}")
        return False

    log_file = os.path.join(target_dir, "sqlmap_scan.txt")
    command = [PYTHON, SQLMAP_PATH, "-u", target_url, "--forms", "--batch", "--level=2", "--risk=2"]
    success, output = run_cmd(command, capture=True, log_file=log_file)

    if output:
        print(output)
        print(f"[+] SQLMap results saved to: {log_file}")

    if not success:
        print(f"[-] SQLMap exited with errors for {target_url}.")

    if "is vulnerable" in output.lower():
        print("[!] SQLMap successfully injected the target!")
        return True
    return False


def run_searchsploit(query, target_dir):
    """Run searchsploit for a free-text query and save results. Returns True if any results found."""
    if not shutil.which("searchsploit"):
        print("[!] searchsploit is not installed; skipping SearchSploit lookup.")
        return False
    log_file = os.path.join(target_dir, "searchsploit.txt")
    command = ["searchsploit", query]
    success, output = run_cmd(command, capture=True, log_file=log_file)
    if output and "No Results" not in output:
        print(output)
        print(f"[+] searchsploit results saved to: {log_file}")
        return True
    return False
