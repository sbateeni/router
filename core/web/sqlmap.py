import os
import time

from core.report.parsers import normalize_target_url
from core.scan_config import get_scan_profile
from core.utils import TOOLS_DIR, PYTHON, run_cmd

SQLMAP_PATH = os.path.join(TOOLS_DIR, "sqlmap", "sqlmap.py")
SQLMAP_LOG = "sqlmap_scan.txt"


def _append_log(target_dir, text):
    path = os.path.join(target_dir, SQLMAP_LOG)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(text)
        if not text.endswith("\n"):
            fh.write("\n")


def run_sqlmap(target_url, target_dir, append_log=True):
    print("\n[+] Running SQLMap (SQL Injection Test)...")
    if not os.path.exists(SQLMAP_PATH):
        print(f"[-] SQLMap not found at {SQLMAP_PATH}")
        return False

    url = normalize_target_url(target_url)
    profile = get_scan_profile()
    log_file = os.path.join(target_dir, SQLMAP_LOG)

    if append_log and os.path.exists(log_file):
        _append_log(target_dir, f"\n{'=' * 60}\nTARGET: {url}\n{'=' * 60}\n")
    elif not append_log and os.path.exists(log_file):
        try:
            os.remove(log_file)
        except OSError:
            pass

    command = [
        PYTHON, SQLMAP_PATH, "-u", url, "--forms", "--batch",
        f"--level={profile['sqlmap_level']}", f"--risk={profile['sqlmap_risk']}",
        "--crawl=2", "--random-agent",
        f"--timeout={profile.get('sqlmap_timeout', 30)}",
    ]
    delay = profile.get("sqlmap_delay")
    if delay:
        command.append(f"--delay={delay}")

    success, output = run_cmd(command, capture=True)
    if output:
        print(output[-2000:] if len(output) > 2000 else output)
        with open(log_file, "a" if append_log and os.path.exists(log_file) else "w", encoding="utf-8") as fh:
            fh.write(output)
            if not output.endswith("\n"):
                fh.write("\n")
        print(f"[+] SQLMap results saved to: {log_file}")
    if not success:
        print(f"[-] SQLMap exited with errors for {url}.")
    if "is vulnerable" in (output or "").lower():
        print("[!] SQLMap successfully injected the target!")
        return True
    return False


def run_sqlmap_phase(ip, web_ports, discovered_urls, target_dir):
    """Run SQLMap on normalized base URLs and priority PHP/API paths."""
    profile = get_scan_profile()
    if os.path.exists(os.path.join(target_dir, SQLMAP_LOG)):
        try:
            os.remove(os.path.join(target_dir, SQLMAP_LOG))
        except OSError:
            pass

    from core.report.parsers import pick_priority_web_targets

    targets = pick_priority_web_targets(ip, web_ports, discovered_urls, limit=profile.get("sqlmap_url_limit", 8))
    if not targets:
        return False

    delay_between = profile.get("phase_delay_seconds", 5)
    exploited = False
    for idx, url in enumerate(targets):
        if idx > 0:
            time.sleep(delay_between)
        if run_sqlmap(url, target_dir, append_log=True):
            exploited = True
    return exploited
