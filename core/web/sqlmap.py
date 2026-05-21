import os

from core.scan_config import get_scan_profile
from core.utils import TOOLS_DIR, PYTHON, run_cmd

SQLMAP_PATH = os.path.join(TOOLS_DIR, "sqlmap", "sqlmap.py")


def run_sqlmap(target_url, target_dir):
    print("\n[+] Running SQLMap (SQL Injection Test)...")
    if not os.path.exists(SQLMAP_PATH):
        print(f"[-] SQLMap not found at {SQLMAP_PATH}")
        return False

    profile = get_scan_profile()
    log_file = os.path.join(target_dir, "sqlmap_scan.txt")
    command = [
        PYTHON, SQLMAP_PATH, "-u", target_url, "--forms", "--batch",
        f"--level={profile['sqlmap_level']}", f"--risk={profile['sqlmap_risk']}",
        "--crawl=2",
    ]
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
