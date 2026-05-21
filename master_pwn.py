#!/usr/bin/env python3

import argparse
import sys
import os
import subprocess
import hashlib
import importlib.util
from core.runner import select_tool_menu, run_selected_tool
from core.web_enum import update_nuclei_templates, ensure_dirsearch_deps
from core.utils import missing_python_modules

def update_self_repo():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    git_dir = os.path.join(base_dir, ".git")
    print(f"[*] Repository base path: {base_dir}")
    if not os.path.exists(git_dir):
        print("[*] No local Git repository found; skipping repository update.")
        return

    print("[*] Checking local repository status...")
    try:
        status = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=base_dir,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
    except FileNotFoundError:
        print("[!] Git is not installed or not available in PATH.")
        return
    except subprocess.CalledProcessError as exc:
        print("[!] Unable to check Git status.")
        if exc.stderr:
            print(exc.stderr.strip())
        return

    dirty = bool(status.stdout.strip())
    stash_created = False
    if dirty:
        print("[!] Local changes detected. Stashing changes before pulling updates...")
        try:
            stash = subprocess.run(
                ["git", "stash", "push", "--include-untracked", "-m", "router auto-update"],
                cwd=base_dir,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stash_output = stash.stdout.strip()
            if stash_output:
                print(stash_output)
            if "No local changes to save" not in stash_output:
                stash_created = True
        except subprocess.CalledProcessError as exc:
            print("[!] Failed to stash local changes.")
            if exc.stderr:
                print(exc.stderr.strip())
            return

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
        if result.stderr:
            print(result.stderr.strip())
        print("[+] Repository update completed.")
    except subprocess.CalledProcessError as exc:
        print("[!] Failed to pull latest repository updates.")
        if exc.stdout:
            print(exc.stdout.strip())
        if exc.stderr:
            print(exc.stderr.strip())
        return

    if stash_created:
        print("[*] Restoring your local changes...")
        try:
            pop = subprocess.run(
                ["git", "stash", "apply"],
                cwd=base_dir,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            if pop.stdout:
                print(pop.stdout.strip())
            if pop.stderr:
                print(pop.stderr.strip())
            drop = subprocess.run(
                ["git", "stash", "drop"],
                cwd=base_dir,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            if drop.stdout:
                print(drop.stdout.strip())
            if drop.stderr:
                print(drop.stderr.strip())
            print("[+] Local changes restored.")
        except subprocess.CalledProcessError as exc:
            print("[!] Failed to restore stashed changes automatically.")
            if exc.stdout:
                print(exc.stdout.strip())
            if exc.stderr:
                print(exc.stderr.strip())
            print("[!] Your stash has been preserved for manual resolution.")


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
    req_hash = None
    installed_hash = None
    if os.path.exists(req_path):
        sha256 = hashlib.sha256()
        with open(req_path, "rb") as f:
            sha256.update(f.read())
        req_hash = sha256.hexdigest()

    if os.path.exists(flag_file):
        try:
            with open(flag_file, "r", encoding="utf-8") as f:
                installed_hash = f.read().strip()
        except OSError:
            installed_hash = None

    telnetlib3_installed = importlib.util.find_spec("telnetlib3") is not None
    missing_modules = missing_python_modules()
    needs_install = (
        missing_tools
        or req_hash is None
        or installed_hash != req_hash
        or not telnetlib3_installed
        or bool(missing_modules)
    )
    if needs_install:
        print("[*] Installing Python requirements (This might take a moment)...")
        if os.path.exists(req_path):
            pip_cmd = [sys.executable, "-m", "pip", "install", "-r", req_path, "--break-system-packages"]
            result = subprocess.run(pip_cmd)
            if result.returncode != 0:
                print("[!] Python requirements installation failed. Please check the output above.")
                return
        if missing_modules:
            subprocess.run([
                sys.executable, "-m", "pip", "install",
                "mysql-connector-python", "defusedxml", "colorama",
                "--break-system-packages",
            ])
        with open(flag_file, "w", encoding="utf-8") as f:
            f.write(req_hash or "")

    ensure_dirsearch_deps()
            
    print("[+] All tools and dependencies are ready!\n")

def main():
    parser = argparse.ArgumentParser(description="Master Auto-Pwn Script for Routers (Modular Version)")
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument(
        "-a", "--auto",
        action="store_true",
        help="Run all tools automatically without showing the menu",
    )
    args = parser.parse_args()
    ip = args.target

    # التحقق من التحديثات من GitHub قبل التشغيل
    update_self_repo()
    auto_install_tools()
    # تأكد من أن قوالب Nuclei محدثة عند بداية التشغيل
    try:
        update_nuclei_templates()
    except Exception:
        print("[!] Warning: failed to update Nuclei templates at startup; continuing.")

    print(f"======================================================")
    print(f"      TARGET ACQUIRED: {ip}                           ")
    print(f"======================================================\n")

    # إنشاء مجلد مخصص للهدف
    # إذا كنت تستخدم كالي، سيتم إنشاؤه داخل مجلد targets في نفس مسار السكربت
    target_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "targets", ip)
    os.makedirs(target_dir, exist_ok=True)
    try:
        os.chmod(target_dir, 0o755)
    except PermissionError:
        pass
    print(f"[*] Workspace created for target: {target_dir}\n")

    if args.auto:
        print("[*] Auto mode enabled: running all tools without menu.\n")

    selection = 1 if args.auto else select_tool_menu()
    if selection == 11:
        print("[-] Exiting without running any tools.")
        return

    exploited = run_selected_tool(selection, ip, target_dir)

    print("\n======================================================")
    if selection == 2:
        print("[*] Nmap-only execution completed.")
    elif exploited:
        print("[★] SUCCESS: Tool found a likely issue or exploitation succeeded!")
    else:
        print("[-] Tool execution completed without finding a successful exploit.")

    print(f"[*] All output logs for {ip} have been saved in: {target_dir}")
    print("======================================================")

if __name__ == "__main__":
    main()
