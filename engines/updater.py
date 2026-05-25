import os
import shutil
import subprocess
import sys

from engines.utils import log

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS_DIR = os.path.join(ROOT_DIR, "tools")

EXTERNAL_TOOLS = [
    {
        "dir": "routersploit",
        "url": "https://github.com/threat9/routersploit.git",
        "depth": None,
    },
    {
        "dir": "ingram",
        "url": "https://github.com/jorhelp/Ingram.git",
        "depth": None,
    },
    {
        "dir": "DefaultCreds-cheat-sheet",
        "url": "https://github.com/ihebski/DefaultCreds-cheat-sheet.git",
        "depth": None,
    },
    {
        "dir": "dirsearch",
        "url": "https://github.com/maurosoria/dirsearch.git",
        "depth": 1,
    },
    {
        "dir": "sqlmap",
        "url": "https://github.com/sqlmapproject/sqlmap.git",
        "depth": 1,
    },
    {
        "dir": "changeme",
        "url": "https://github.com/ztgrace/changeme.git",
        "depth": 1,
    },
    {
        "dir": "default-hunter",
        "url": "https://github.com/SySS-Research/Default-Hunter.git",
        "depth": 1,
    },
    {
        "dir": "jeanphorn-wordlist",
        "url": "https://github.com/jeanphorn/wordlist.git",
        "depth": 1,
    },
    {
        "dir": "iotbreaker",
        "url": "https://github.com/servais1983/IoTBreaker.git",
        "depth": 1,
    },
    {
        "dir": "iotscan",
        "url": "https://github.com/sundi133/iotscan.git",
        "depth": 1,
    },
    {
        "dir": "rustsploit",
        "url": "https://github.com/s-b-repo/r-routersploit.git",
        "depth": 1,
    },
    {
        "dir": "router_analysis",
        "url": "https://github.com/dom-one/router_analysis.git",
        "depth": 1,
    },
]


def _git_available():
    return shutil.which("git") is not None


def _run_git(args, cwd, timeout=180):
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
        return result.returncode == 0, (result.stdout or "").strip(), (result.stderr or "").strip()
    except subprocess.TimeoutExpired:
        return False, "", "git command timed out"
    except FileNotFoundError:
        return False, "", "git not found"
    except OSError as exc:
        return False, "", str(exc)


def _is_git_repo(path):
    return os.path.isdir(os.path.join(path, ".git"))


def pull_repo(path, label=None):
    name = label or os.path.basename(path)
    if not _is_git_repo(path):
        return False

    log(f"Updating {name}...", "INFO")
    ok, stdout, stderr = _run_git(["pull", "--ff-only"], path)
    if ok:
        if stdout and "Already up to date" not in stdout:
            log(f"{name}: {stdout}", "SUCCESS")
        else:
            log(f"{name}: already up to date.", "INFO")
        return True

    message = stderr or stdout or "pull failed"
    if "would be overwritten by merge" in message or "local changes" in message.lower():
        log(
            f"{name}: local changes block update. Run: git stash && git pull origin master",
            "ERROR",
        )
    else:
        log(f"{name}: update failed ({message})", "ERROR")
    return False


def clone_repo(url, path, depth=None):
    name = os.path.basename(path)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    args = ["clone"]
    if depth:
        args.extend(["--depth", str(depth)])
    args.extend([url, path])

    log(f"Cloning {name}...", "INFO")
    ok, stdout, stderr = _run_git(args, ROOT_DIR)
    if ok:
        log(f"{name}: downloaded.", "SUCCESS")
        return True

    message = stderr or stdout or "clone failed"
    log(f"{name}: download failed ({message})", "ERROR")
    return False


def sync_external_tool(tool):
    tool_path = os.path.join(TOOLS_DIR, tool["dir"])
    if os.path.isdir(tool_path):
        return pull_repo(tool_path, tool["dir"])

    return clone_repo(tool["url"], tool_path, tool.get("depth"))


def install_external_tool_dependencies():
    """Sync .venv with pinned deps (Kali-safe). Do not pip routersploit/ingram reqs — they break theHarvester pins."""
    subprocess.run([sys.executable, "-m", "pip", "install", "-q", "setuptools", "telnetlib3"], check=False)

    # NetExec in .venv conflicts with RouterSploit paramiko==2.12 — use: sudo apt install netexec
    subprocess.run(
        [sys.executable, "-m", "pip", "uninstall", "-y", "netexec", "certipy-ad"],
        capture_output=True,
        check=False,
    )

    kali_req = os.path.join(ROOT_DIR, "requirements-kali.txt")
    constraints = os.path.join(ROOT_DIR, "constraints-kali.txt")
    if os.path.isfile(kali_req):
        log("Syncing Python deps from requirements-kali.txt...", "INFO")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "-q", "-r", kali_req],
            check=False,
        )
    if os.path.isfile(constraints):
        subprocess.run(
            [
                sys.executable, "-m", "pip", "install", "-q",
                "-c", constraints,
                "paramiko", "beautifulsoup4", "dnspython", "lxml", "requests",
            ],
            check=False,
        )

    harvester = os.path.join(TOOLS_DIR, "theHarvester")
    if os.path.isdir(harvester) and os.path.isfile(os.path.join(harvester, "pyproject.toml")):
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "-q", "--no-deps", harvester],
            check=False,
        )


def update_external_tools():
    os.makedirs(TOOLS_DIR, exist_ok=True)
    log("Syncing external tools from GitHub...", "INFO")

    results = [sync_external_tool(tool) for tool in EXTERNAL_TOOLS]
    install_external_tool_dependencies()
    return all(results)


def update_project_repo():
    if not _is_git_repo(ROOT_DIR):
        log("Project is not a git repository; skipping self-update.", "INFO")
        return True

    log("Updating main project from GitHub...", "INFO")
    return pull_repo(ROOT_DIR, "router")


def update_nuclei_templates():
    from engines.scanner import _resolve_nuclei_path

    nuclei_path = _resolve_nuclei_path()
    if not nuclei_path or not os.path.exists(nuclei_path):
        log("Nuclei binary not found; skipping template update.", "INFO")
        return True

    log("Updating Nuclei templates...", "INFO")
    try:
        result = subprocess.run(
            [nuclei_path, "-update-templates"],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        output = (result.stdout or result.stderr or "").strip()
        if result.returncode == 0:
            if output:
                log(output.splitlines()[-1], "SUCCESS")
            else:
                log("Nuclei templates updated.", "SUCCESS")
                
            # Extract CVEs from newly updated templates
            from engines.cve_updater import update_cve_database
            update_cve_database()
            
            return True

        log(f"Nuclei template update failed: {output or 'unknown error'}", "ERROR")
        return False
    except subprocess.TimeoutExpired:
        log("Nuclei template update timed out.", "ERROR")
        return False
    except OSError as exc:
        log(f"Nuclei template update failed: {exc}", "ERROR")
        return False


def run_startup_update(update_project=True, update_tools=True, update_templates=True):
    if not _git_available():
        log("Git is not installed; skipping GitHub sync.", "ERROR")
        return False

    print("\n" + "=" * 54)
    print("       SYNCING WITH GITHUB (KEEP TOOLS UPDATED)")
    print("=" * 54 + "\n")

    success = True

    if update_project:
        success = update_project_repo() and success

    if update_tools:
        success = update_external_tools() and success

    if update_templates:
        success = update_nuclei_templates() and success

    print()
    if success:
        log("GitHub sync completed.", "SUCCESS")
    else:
        log("GitHub sync finished with some errors.", "ERROR")

    return success


if __name__ == "__main__":
    ok = run_startup_update()
    sys.exit(0 if ok else 1)
