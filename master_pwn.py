#!/usr/bin/env python3

import argparse
import sys
import os
import subprocess
import hashlib
import importlib.util
from core.runner import select_tool_menu, run_selected_tool
from core.web_enum import update_nuclei_templates, ensure_dirsearch_deps
from core.utils import missing_python_modules, reset_target_workspace
from core.report import generate_scan_report
from core.notify import load_dotenv, notify_scan_complete
from core.ai_analyst import generate_ai_analysis, ai_configured


def repo_base_dir():
    return os.path.dirname(os.path.abspath(__file__))


def current_user_name():
    try:
        import pwd
        return pwd.getpwuid(os.getuid()).pw_name
    except Exception:
        return os.environ.get("USER") or os.environ.get("LOGNAME") or "kali"


def git_permission_problem(base_dir):
    git_dir = os.path.join(base_dir, ".git")
    objects_dir = os.path.join(git_dir, "objects")
    if not os.path.exists(git_dir):
        return False
    for path in (git_dir, objects_dir):
        if os.path.exists(path) and not os.access(path, os.W_OK):
            return True
    return False


DEFAULT_BRANCH = "main"


def run_git(args, base_dir, check=True):
    result = subprocess.run(
        ["git"] + args,
        cwd=base_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode,
            ["git"] + args,
            result.stdout,
            result.stderr,
        )
    return result


def print_git_sync_fix(base_dir):
    user = current_user_name()
    print("\n[!] Unable to sync repository automatically.")
    print("[!] Run these commands once on Kali:\n")
    print(f"    sudo chown -R {user}:{user} {base_dir}")
    print(f"    cd {base_dir}")
    print("    git fetch origin")
    print(f"    git checkout -B {DEFAULT_BRANCH} origin/{DEFAULT_BRANCH}")
    print("    python3 master_pwn.py -t 192.168.1.1 --auto\n")
    print("[!] Do NOT use sudo when running master_pwn.py.")


def print_git_permission_fix(base_dir):
    user = current_user_name()
    print("\n[!] Git permission problem detected in this repository.")
    print("[!] This usually happens after running the project with sudo.")
    print("[!] Fix it once with these commands:\n")
    print(f"    sudo chown -R {user}:{user} {base_dir}")
    print(f"    cd {base_dir}")
    print("    git fetch origin")
    print(f"    git checkout -B {DEFAULT_BRANCH} origin/{DEFAULT_BRANCH}")
    print("    python3 master_pwn.py -t 192.168.1.1 --auto\n")
    print("[!] Do NOT use sudo when running master_pwn.py after fixing permissions.")


def warn_if_running_as_root():
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        print("[!] Warning: running as root/sudo can break git and file ownership.")
        print("[!] Prefer running as your normal user inside the virtualenv.\n")


def update_self_repo():
    base_dir = repo_base_dir()
    git_dir = os.path.join(base_dir, ".git")
    print(f"[*] Repository base path: {base_dir}")
    if not os.path.exists(git_dir):
        print("[*] No local Git repository found; skipping repository update.")
        return False

    if git_permission_problem(base_dir):
        print_git_permission_fix(base_dir)
        return False

    def current_head():
        result = run_git(["rev-parse", "HEAD"], base_dir, check=False)
        if result.returncode != 0:
            return None
        return result.stdout.strip()

    print("[*] Checking local repository status...")
    try:
        run_git(["fetch", "origin"], base_dir)
    except FileNotFoundError:
        print("[!] Git is not installed or not available in PATH.")
        return False
    except subprocess.CalledProcessError as exc:
        print("[!] Failed to fetch updates from GitHub.")
        if exc.stdout:
            print(exc.stdout.strip())
        if exc.stderr:
            print(exc.stderr.strip())
        combined = f"{exc.stdout or ''}\n{exc.stderr or ''}".lower()
        if "insufficient permission" in combined or "failed to write object" in combined:
            print_git_permission_fix(base_dir)
        else:
            print_git_sync_fix(base_dir)
        return False

    try:
        status = run_git(["status", "--porcelain"], base_dir)
    except subprocess.CalledProcessError as exc:
        print("[!] Unable to check Git status.")
        if exc.stderr:
            print(exc.stderr.strip())
        return False

    dirty = bool(status.stdout.strip())
    stash_created = False
    if dirty:
        print("[!] Local tracked changes detected. Stashing before syncing with origin/main...")
        try:
            stash = run_git(
                ["stash", "push", "-m", "router auto-update"],
                base_dir,
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
            print_git_sync_fix(base_dir)
            return False

    head_before = current_head()
    branch_result = run_git(["rev-parse", "--abbrev-ref", "HEAD"], base_dir, check=False)
    current_branch = branch_result.stdout.strip() if branch_result.returncode == 0 else ""

    if current_branch != DEFAULT_BRANCH:
        print(f"[*] Switching branch from '{current_branch}' to '{DEFAULT_BRANCH}'...")
        try:
            run_git(["checkout", "-B", DEFAULT_BRANCH, f"origin/{DEFAULT_BRANCH}"], base_dir)
        except subprocess.CalledProcessError as exc:
            print("[!] Failed to switch to main branch.")
            if exc.stderr:
                print(exc.stderr.strip())
            print_git_sync_fix(base_dir)
            return False

    print(f"[*] Syncing local '{DEFAULT_BRANCH}' with origin/{DEFAULT_BRANCH}...")
    updated = False
    try:
        merge = run_git(["merge", "--ff-only", f"origin/{DEFAULT_BRANCH}"], base_dir)
        if merge.stdout:
            print(merge.stdout.strip())
        if merge.stderr:
            print(merge.stderr.strip())
        print("[+] Repository update completed.")
    except subprocess.CalledProcessError:
        print("[!] Fast-forward merge failed. Resetting local main to origin/main...")
        try:
            reset = run_git(["reset", "--hard", f"origin/{DEFAULT_BRANCH}"], base_dir)
            if reset.stdout:
                print(reset.stdout.strip())
            if reset.stderr:
                print(reset.stderr.strip())
            print("[+] Repository reset to latest origin/main.")
        except subprocess.CalledProcessError as exc:
            print("[!] Failed to sync repository with origin/main.")
            if exc.stdout:
                print(exc.stdout.strip())
            if exc.stderr:
                print(exc.stderr.strip())
            print_git_sync_fix(base_dir)
            return False

    head_after = current_head()
    updated = bool(head_before and head_after and head_before != head_after)

    if stash_created:
        print("[*] Local stashed changes were kept aside to avoid overwriting updates.")
        print("[*] If needed, review them later with: git stash list")

    if updated:
        print("[*] New code downloaded. Restarting with the latest version...")
    return updated


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
    warn_if_running_as_root()
    load_dotenv(repo_base_dir())

    # تحديث الكود من GitHub قبل قراءة أي معاملات جديدة (مثل --auto)
    if update_self_repo():
        os.execv(sys.executable, [sys.executable] + sys.argv)

    parser = argparse.ArgumentParser(description="Master Auto-Pwn Script for Routers (Modular Version)")
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument(
        "-a", "--auto",
        action="store_true",
        help="Run all tools automatically without showing the menu",
    )
    parser.add_argument(
        "--deep",
        action="store_true",
        help="Use deep/full-power scan profile (slower, more thorough)",
    )
    parser.add_argument(
        "--ai",
        action="store_true",
        help="Enable AI planning during scan + final analysis (requires API keys in .env)",
    )
    args = parser.parse_args()
    ip = args.target
    scan_profile = "deep" if args.deep else "normal"
    use_ai = args.ai or ai_configured()

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
    reset_target_workspace(target_dir)
    print(f"[*] Workspace ready for target: {target_dir}\n")

    if args.auto:
        print("[*] Auto mode enabled: running all tools without menu.\n")
    if args.deep:
        print("[*] Deep scan profile enabled: all tools will run at full power.\n")
    if use_ai:
        print("[*] AI enabled: smart tool selection, Hydra hints, RouterSploit follow-up.\n")

    selection = 1 if args.auto else select_tool_menu()
    if selection == 11:
        print("[-] Exiting without running any tools.")
        return

    exploited = run_selected_tool(selection, ip, target_dir, profile=scan_profile, use_ai=use_ai)

    report_path = generate_scan_report(
        ip, target_dir, selection, exploited,
        current_phase="Completed", profile=scan_profile,
    )

    ai_analysis = None
    if use_ai:
        ai_analysis = generate_ai_analysis(ip, target_dir)

    print("\n======================================================")
    if selection == 2:
        print("[*] Nmap-only execution completed.")
    elif exploited:
        print("[★] SUCCESS: Tool found a likely issue or exploitation succeeded!")
    else:
        print("[-] Tool execution completed without finding a successful exploit.")

    print(f"[*] All output logs for {ip} have been saved in: {target_dir}")
    print(f"[*] Results summary report: {report_path}")
    print("[*] Share RESULTS_SUMMARY.txt to review tool health and findings.")
    notify_scan_complete(
        ip, target_dir, report_path, exploited,
        profile=scan_profile, ai_analysis=ai_analysis,
    )
    print("======================================================")

if __name__ == "__main__":
    main()
