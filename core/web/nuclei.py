import glob
import json
import os

from core.scan_config import get_scan_profile
from core.utils import run_cmd, valid_env_value
from core.web.nuclei_config import build_nuclei_base_cmd, custom_template_dir, nuclei_tags_for_profile, resolve_nuclei_cmd

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
        "/usr/share/nuclei-templates",
    ]
    for c in candidates:
        if os.path.exists(c) and any(glob.glob(os.path.join(c, "**", "*.yaml"), recursive=True)):
            return True
    return custom_template_dir() is not None


def update_nuclei_templates():
    nuclei_cmd = resolve_nuclei_cmd()
    print(f"\n[+] Ensuring Nuclei templates are up-to-date...")
    commands = [[nuclei_cmd, "-ut"], [nuclei_cmd, "-update-templates"], [nuclei_cmd, "-ut", "-no-colors"]]
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


def _nuclei_timeouts():
    profile = get_scan_profile()
    cmd_t = profile.get("nuclei_cmd_timeout", 480)
    http_t = profile.get("nuclei_http_timeout", 10)
    rl = profile.get("nuclei_rate_limit", 150)
    env_cmd = os.environ.get("NUCLEI_CMD_TIMEOUT", "").strip()
    env_http = os.environ.get("NUCLEI_HTTP_TIMEOUT", "").strip()
    if valid_env_value(env_cmd):
        try:
            cmd_t = int(env_cmd)
        except ValueError:
            pass
    if valid_env_value(env_http):
        try:
            http_t = int(env_http)
        except ValueError:
            pass
    return cmd_t, http_t, rl


def _nuclei_scan_flags(export_path):
    _, http_t, rl = _nuclei_timeouts()
    return [
        "-silent", "-jle", export_path,
        "-timeout", str(http_t),
        "-rl", str(rl),
        "-mhe", "30",
        "-retries", "1",
    ]


def run_nuclei(target_url, target_dir, tags=None):
    profile = get_scan_profile()
    cmd_timeout, http_t, rl = _nuclei_timeouts()
    print(f"\n[+] Running Nuclei (Vulnerability Scanning) [{profile['label']}]...")
    print(f"[*] Nuclei limits: cmd_timeout={cmd_timeout}s http_timeout={http_t}s rate={rl}/s")
    if tags:
        print(f"[*] Nuclei tags (from target profile): {tags}")
    custom = custom_template_dir()
    if custom:
        print(f"[*] Custom templates: {custom}")

    port = target_url.split(":")[-1] if ":" in target_url.replace("https://", "").replace("http://", "") else "80"
    log_txt = os.path.join(target_dir, f"nuclei_port_{port}.txt")
    log_jsonl = os.path.join(target_dir, f"nuclei_port_{port}.jsonl")
    stdout_log = os.path.join(target_dir, f"nuclei_port_{port}_stdout.txt")
    nuclei_cmd = resolve_nuclei_cmd()

    if not nuclei_templates_installed():
        ok = update_nuclei_templates()
        if not ok:
            print("[!] Skipping nuclei scan due to missing templates.")
            return False

    validate_marker = os.path.join(target_dir, ".nuclei_validated")
    if os.environ.get("NUCLEI_VALIDATE") == "1" and not os.path.isfile(validate_marker):
        validate_log = os.path.join(target_dir, "nuclei_validate.txt")
        run_cmd([nuclei_cmd, "-validate"], capture=True, log_file=validate_log, timeout=180)
        try:
            with open(validate_marker, "w", encoding="utf-8") as fh:
                fh.write("ok\n")
        except OSError:
            pass

    def run_scan(base_command, export_path):
        if os.path.exists(export_path):
            os.remove(export_path)
        command = base_command + _nuclei_scan_flags(export_path)
        return run_cmd(command, capture=True, log_file=stdout_log, timeout=cmd_timeout)

    base_cmd = build_nuclei_base_cmd(target_url)
    tag_list = tags if tags else nuclei_tags_for_profile(profile)
    tag_cmd = list(base_cmd) if not tag_list else base_cmd + ["-tags", tag_list]

    success, output = run_scan(tag_cmd, log_jsonl)
    findings = parse_nuclei_jsonl(log_jsonl)

    if not findings and tag_list:
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
