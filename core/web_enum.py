import os
from core.utils import run_cmd, TOOLS_DIR

DIRSEARCH_PATH = os.path.join(TOOLS_DIR, "dirsearch", "dirsearch.py")
SQLMAP_PATH = os.path.join(TOOLS_DIR, "sqlmap", "sqlmap.py")
NUCLEI_CMD = os.path.join(TOOLS_DIR, "nuclei", "v2", "cmd", "nuclei", "nuclei")  # Or just rely on system installed nuclei if we prefer. But let's fallback to system one if local is not built
# Actually nuclei is a go project and requires `go build`. It's better to keep assuming it's installed via apt/go on kali or use the release binaries. But we'll leave it as "nuclei" because kali has it usually or we can download the binary.
NUCLEI_CMD = "nuclei"

def run_nuclei(target_url, target_dir):
    print("\n[+] Running Nuclei (Vulnerability Scanning)...")
    port = target_url.split(":")[-1] if ":" in target_url.replace("https://", "").replace("http://", "") else "80"
    log_file = os.path.join(target_dir, f"nuclei_port_{port}.txt")
    
    command = [NUCLEI_CMD, "-u", target_url, "-t", "default-logins,cves,misconfiguration"]
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
        return False
        
    port = target_url.split(":")[-1] if ":" in target_url.replace("https://", "").replace("http://", "") else "80"
    log_file = os.path.join(target_dir, f"dirsearch_port_{port}.txt")
    
    # Dirsearch لديه خاصية للحفظ بشكل منظم، يمكننا استخدام -o أيضاً
    command = ["python3", DIRSEARCH_PATH, "-u", target_url, "-e", "php,html,bak", "-x", "400,404,403,500", "-t", "50", "-o", log_file]
    success, _ = run_cmd(command, capture=False)
    
    print(f"[+] Dirsearch results saved to: {log_file}")
    return False

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
