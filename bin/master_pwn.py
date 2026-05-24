#!/usr/bin/env python3

import argparse
import sys
import os
import subprocess
import hashlib
import importlib.util

import _bootstrap

_bootstrap.install()

from core.paths import setup_project_env, project_root

setup_project_env()

from core.runner import select_tool_menu, run_selected_tool
from core.network_discovery import resolve_target_list
from core.web_enum import update_nuclei_templates, ensure_dirsearch_deps
from core.utils import missing_python_modules, reset_target_workspace, install_python_packages, ensure_routersploit_deps
from core.report import generate_scan_report
from core.notify import load_dotenv, notify_scan_complete, telegram_placeholder_keys_present
from core.ai.analyst import ai_placeholder_keys_present


def repo_base_dir():
    return project_root()


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
    safe_dir = os.path.abspath(base_dir)
    result = subprocess.run(
        ["git", "-c", f"safe.directory={safe_dir}"] + args,
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
    print("\n[!] Unable to sync repository automatically.")
    print("[!] Run these commands once on Kali (as normal user kali, NOT sudo):\n")
    print(f"    sudo chown -R kali:kali {base_dir}")
    print(f"    cd {base_dir}")
    print("    git fetch origin")
    print(f"    git checkout -B {DEFAULT_BRANCH} origin/{DEFAULT_BRANCH}")
    print("    python3 bin/master_pwn.py -t 192.168.1.1 --auto\n")
    print("[!] Do NOT use sudo when running bin/master_pwn.py.")


def print_git_permission_fix(base_dir):
    user = current_user_name()
    print("\n[!] Git permission problem detected in this repository.")
    print("[!] This usually happens after running the project with sudo.")
    print("[!] Fix it once with these commands:\n")
    print(f"    sudo chown -R {user}:{user} {base_dir}")
    print(f"    cd {base_dir}")
    print("    git fetch origin")
    print(f"    git checkout -B {DEFAULT_BRANCH} origin/{DEFAULT_BRANCH}")
    print("    python3 bin/master_pwn.py -t 192.168.1.1 --auto\n")
    print("[!] Do NOT use sudo when running bin/master_pwn.py after fixing permissions.")


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
    base_dir = project_root()
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
                    subprocess.run(
                        ["git", "-c", f"safe.directory={os.path.abspath(tool_path)}", "pull", "--ff-only"],
                        cwd=tool_path,
                        check=True,
                    )
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
                print("[!] Full requirements install failed; installing critical packages individually...")
                install_python_packages([
                    "mysql-connector-python", "defusedxml", "colorama", "requests",
                    "pycryptodome", "telnetlib3",
                ])
        if missing_modules:
            install_python_packages([
                "mysql-connector-python", "defusedxml", "colorama",
            ])
        with open(flag_file, "w", encoding="utf-8") as f:
            f.write(req_hash or "")

    ensure_routersploit_deps()
    ensure_dirsearch_deps()
            
    print("[+] All tools and dependencies are ready!\n")


def run_scan_for_target(ip, args, selection, scan_profile, base_dir):
    from core.menu import AI_CHOICES

    from core.report.parsers import parse_target_input, save_target_hints, target_scan_host, target_workspace_name

    raw_target = getattr(args, "target", None) or ip
    parsed = parse_target_input(raw_target)
    scan_host = target_scan_host(parsed) if parsed else ip
    workspace_name = target_workspace_name(parsed, fallback=ip)

    print("======================================================")
    display = parsed.get("raw") if parsed else ip
    print(f"      TARGET ACQUIRED: {display}                           ")
    print("======================================================\n")

    target_dir = os.path.join(base_dir, "targets", workspace_name)
    os.makedirs(target_dir, exist_ok=True)
    try:
        os.chmod(target_dir, 0o755)
    except PermissionError:
        pass
    reset_target_workspace(target_dir)

    if parsed and (parsed.get("login_path") or parsed.get("seed_url") or parsed.get("query_string")):
        save_target_hints(target_dir, {
            "host": parsed.get("host"),
            "login_path": parsed.get("login_path"),
            "seed_url": parsed.get("seed_url"),
            "query_string": parsed.get("query_string"),
            "port": parsed.get("port"),
            "scheme": parsed.get("scheme"),
            "resolved_ip": parsed.get("resolved_ip"),
            "is_domain": parsed.get("is_domain"),
            "raw": parsed.get("raw"),
        })
        print(f"[*] Target hint: {parsed.get('raw')}")
        if parsed.get("is_domain") and parsed.get("resolved_ip"):
            print(f"[*] DNS: {parsed['host']} → {parsed['resolved_ip']}")

    print(f"[*] Workspace ready for target: {target_dir}\n")

    exploited = run_selected_tool(
        selection, scan_host, target_dir,
        profile=scan_profile, subnet=getattr(args, "subnet", None),
    )

    report_path, confirmed = generate_scan_report(
        scan_host, target_dir, selection, exploited,
        current_phase="Completed", profile=scan_profile,
    )

    ai_analysis = None
    if selection == 14:
        ai_path = os.path.join(target_dir, "AI_ANALYSIS.txt")
        if os.path.exists(ai_path):
            with open(ai_path, "r", encoding="utf-8") as fh:
                ai_analysis = fh.read()
    elif selection in AI_CHOICES:
        print("[*] AI tool finished (classic pipeline was not modified).")

    print("\n======================================================")
    if selection == 2:
        print("[*] Nmap-only execution completed.")
    elif confirmed:
        print("[★] SUCCESS: Confirmed exploit or critical vulnerability found!")
    elif exploited and not confirmed:
        print("[!] Scan flagged findings but nothing confirmed — check Hydra manually and read MSF_EXPLOIT_COMMANDS.txt")
    else:
        print("[-] Tool execution completed without finding a confirmed exploit.")

    print(f"[*] All output logs for {workspace_name} have been saved in: {target_dir}")
    print(f"[*] Results summary report: {report_path}")
    notify_scan_complete(
        scan_host, target_dir, report_path, confirmed,
        profile=scan_profile, ai_analysis=ai_analysis,
    )
    print("======================================================\n")
    return confirmed


def main():
    warn_if_running_as_root()
    load_dotenv(repo_base_dir())
    if ai_placeholder_keys_present():
        print("[!] .env still has placeholder API keys (your_*_here). Replace them with real keys for AI.\n")
    if telegram_placeholder_keys_present():
        print("[!] .env still has placeholder Telegram values. Replace them for notifications.\n")

    # تحديث الكود من GitHub قبل قراءة أي معاملات جديدة (مثل --auto)
    if update_self_repo():
        os.execv(sys.executable, [sys.executable] + sys.argv)

    parser = argparse.ArgumentParser(description="Master Auto-Pwn Script for Routers (Modular Version)")
    parser.add_argument("-t", "--target", help="Target IP address (optional — interactive menu if omitted)")
    parser.add_argument(
        "--subnet",
        help="Subnet to discover hosts on, e.g. 192.168.1.0/24",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Scan all hosts discovered on --subnet (use with --auto)",
    )
    parser.add_argument(
        "-a", "--auto",
        action="store_true",
        help="Run all tools automatically without showing the tool menu",
    )
    parser.add_argument(
        "--deep",
        action="store_true",
        help="Use deep/full-power scan profile (slower, more thorough)",
    )
    parser.add_argument(
        "--telegram",
        action="store_true",
        help="Telegram bot only (no local menu). Default: bot in background + local menu together",
    )
    parser.add_argument(
        "--no-telegram",
        action="store_true",
        help="Disable background Telegram bot; local menu / CLI only",
    )
    args = parser.parse_args()
    base_dir = repo_base_dir()

    from core.telegram_bot import run_telegram_bot, should_run_telegram_background, start_telegram_bot_background

    if args.telegram:
        print("[*] Telegram-only mode (--telegram)\n")
        raise SystemExit(run_telegram_bot(base_dir))

    if should_run_telegram_background(args):
        start_telegram_bot_background(base_dir)

    scan_profile = "deep" if args.deep else "normal"

    auto_install_tools()
    try:
        update_nuclei_templates()
    except Exception:
        print("[!] Warning: failed to update Nuclei templates at startup; continuing.")

    if args.auto:
        print("[*] Auto mode enabled: running all classic tools without tool menu.\n")
    if args.deep:
        print("[*] Deep scan profile enabled: all tools will run at full power.\n")

    targets = resolve_target_list(args, base_dir)

    if args.auto:
        selection = 1
    else:
        selection = select_tool_menu()

    if selection == 20:
        print("[-] Exiting without running any tools.")
        return

    if selection == 16:
        discovery_dir = os.path.join(base_dir, "targets", "_network_discovery")
        os.makedirs(discovery_dir, exist_ok=True)
        from core.runner import run_lan_discovery_only
        run_lan_discovery_only(discovery_dir, subnet=args.subnet)
        print(f"[*] Discovery results saved in: {discovery_dir}")
        return

    if not targets:
        print("[-] No targets selected.")
        return

    if len(targets) > 1:
        print(f"\n[*] Selected {len(targets)} target(s): {', '.join(targets)}\n")

    any_exploited = False
    for ip in targets:
        exploited = run_scan_for_target(ip, args, selection, scan_profile, base_dir)
        any_exploited = any_exploited or exploited

    if len(targets) > 1:
        print(f"[*] Batch scan finished for {len(targets)} target(s).")
        if any_exploited:
            print("[★] At least one target reported a likely finding.")
        else:
            print("[-] No confirmed exploits across selected targets.")

if __name__ == "__main__":
    main()
