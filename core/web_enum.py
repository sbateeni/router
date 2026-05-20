import os
import glob
import shutil
from core.utils import run_cmd, TOOLS_DIR

DIRSEARCH_PATH = os.path.join(TOOLS_DIR, "dirsearch", "dirsearch.py")
SQLMAP_PATH = os.path.join(TOOLS_DIR, "sqlmap", "sqlmap.py")
# Prefer system-installed nuclei; fall back to a local clone path if present
NUCLEI_CMD = os.path.join(TOOLS_DIR, "nuclei", "v2", "cmd", "nuclei", "nuclei")
if not os.path.exists(NUCLEI_CMD):
    NUCLEI_CMD = "nuclei"


def nuclei_templates_installed():
    """Return True if it looks like nuclei templates exist locally."""
    candidates = [
        os.path.expanduser("~/.nuclei/templates"),
        os.path.expanduser("~/.config/nuclei/templates"),
        os.path.join(TOOLS_DIR, "nuclei-templates"),
        os.path.join("/usr/share/nuclei-templates"),
    ]
    for c in candidates:
        if os.path.exists(c) and any(glob.glob(os.path.join(c, "**", "*.yaml"), recursive=True)):
            return True
    return False


def update_nuclei_templates():
    print("\n[+] Ensuring Nuclei templates are up-to-date...")
    # Try the short flag first, then the long-form as a fallback
    commands = [[NUCLEI_CMD, "-ut"], [NUCLEI_CMD, "-update-templates"], [NUCLEI_CMD, "-ut", "-no-colors"]]
    success = False
    for command in commands:
        success, output = run_cmd(command, capture=True)
        if output:
            print(output)
        if success:
            break

    # Verify templates were actually installed
    if not nuclei_templates_installed():
        print("[-] Nuclei templates not detected after update. Please ensure nuclei is installed and can access the network.")
        return False

    print("[+] Nuclei templates are present.")
    return success


def run_nuclei(target_url, target_dir):
    print("\n[+] Running Nuclei (Vulnerability Scanning)...")
    port = target_url.split(":")[-1] if ":" in target_url.replace("https://", "").replace("http://", "") else "80"
    log_file = os.path.join(target_dir, f"nuclei_port_{port}.txt")
    
    command = [NUCLEI_CMD, "-u", target_url, "-tags", "default-logins,cves,misconfiguration"]

    # Ensure templates are present before running nuclei; attempt update if missing
    if not nuclei_templates_installed():
        ok = update_nuclei_templates()
        if not ok:
            print("[!] Skipping nuclei scan due to missing templates.")
            return False

    success, output = run_cmd(command, capture=True, log_file=log_file)
    
    if output and ("no templates provided for scan" in output.lower() or "could not find template" in output.lower()):
        if update_nuclei_templates():
            success, output = run_cmd(command, capture=True, log_file=log_file)
    
    if output:
        print(output)
        print(f"[+] Nuclei results saved to: {log_file}")
        
    if "critical" in output.lower() or "high" in output.lower():
        print("[!] Nuclei found a HIGH/CRITICAL vulnerability!")
        return True
    return False

def run_dirsearch(target_url, target_dir):
    print("\n[+] Running Dirsearch (Path Enumeration)...")
    if not os.path.exists(DIRSEARCH_PATH):
        print(f"[-] Dirsearch not found at {DIRSEARCH_PATH}")
        return []
        
    port = target_url.split(":")[-1] if ":" in target_url.replace("https://", "").replace("http://", "") else "80"
    log_file = os.path.join(target_dir, f"dirsearch_port_{port}.txt")
    
    # Dirsearch لديه خاصية للحفظ بشكل منظم، يمكننا استخدام -o أيضاً
    command = ["python3", DIRSEARCH_PATH, "-u", target_url, "-e", "php,html,bak", "-x", "400,404,403,500", "-t", "50", "-o", log_file]
    success, _ = run_cmd(command, capture=True, log_file=log_file)
    
    discovered = []
    if os.path.exists(log_file):
        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line.startswith("http://") or line.startswith("https://"):
                    discovered.append(line)
                elif line.startswith("/"):
                    base = target_url.rstrip("/")
                    discovered.append(base + line)
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
    command = ["python3", SQLMAP_PATH, "-u", target_url, "--forms", "--batch", "--level=2", "--risk=2"]
    success, output = run_cmd(command, capture=True, log_file=log_file)
    
    if output:
        print(output)
        print(f"[+] SQLMap results saved to: {log_file}")
        
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
    if output:
        print(output)
        print(f"[+] searchsploit results saved to: {log_file}")
        return True
    return False
