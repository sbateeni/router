import glob
import json
import os

from core.scan_config import get_scan_profile
from core.utils import TOOLS_DIR, run_cmd

NUCLEI_CMD = os.path.join(TOOLS_DIR, "nuclei", "v2", "cmd", "nuclei", "nuclei")
if not os.path.exists(NUCLEI_CMD):
    NUCLEI_CMD = "nuclei"

SIGNIFICANT_NUCLEI_SEVERITIES = {"critical", "high", "medium"}
ACTIONABLE_NUCLEI_TAGS = ("default-login", "default-logins", "cve", "rce", "auth-bypass")


def nuclei_actionable_findings(findings):
    actionable = []
    for item in findings:
        info = item.get("info", {})
        severity = str(info.get("severity", "unknown")).lower()
        template = str(item.get("template-id", "")).lower()
        tags = [str(tag).lower() for tag in info.get("tags", [])]
        if severity in SIGNIFICANT_NUCLEI_SEVERITIES:
            actionable.append(item)
            continue
        if any(tag in tags for tag in ("default-login", "default-logins")):
            actionable.append(item)
            continue
        if any(keyword in template for keyword in ACTIONABLE_NUCLEI_TAGS):
            actionable.append(item)
    return actionable


def nuclei_templates_installed():
    candidates = [
        os.path.expanduser("~/.nuclei/templates"),
        os.path.expanduser("~/.config/nuclei/templates"),
        os.path.join(os.path.expanduser("~"), ".local", "nuclei-templates"),
        os.path.join(os.path.expanduser("~"), ".local", "share", "nuclei-templates"),
        os.path.join(TOOLS_DIR, "nuclei-templates"),
        "/usr/share/nuclei-templates",
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
        print("[-] Nuclei templates not detected after update.")
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
    profile = get_scan_profile()
    print(f"\n[+] Running Nuclei (Vulnerability Scanning) [{profile['label']}]...")
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
    tag_cmd = base_cmd if profile["nuclei_all_templates"] else base_cmd + ["-tags", "default-logins,cves,misconfiguration"]

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
        actionable = nuclei_actionable_findings(findings)
        print(f"[+] Nuclei found {len(findings)} result(s) ({len(actionable)} actionable).")
        if actionable:
            print("[!] Nuclei reported actionable findings.")
            return True
        print("[*] Nuclei findings are informational/low severity only.")
        return False

    print(f"[+] Nuclei scan completed for {target_url}. No results found.")
    return False
