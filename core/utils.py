import subprocess
import os
import shutil
import sys

TOOLS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools")
PYTHON = sys.executable

CRITICAL_MODULES = (
    "mysql.connector",
    "requests",
    "colorama",
    "defusedxml",
)

ROUTERSPLOIT_PACKAGES = (
    "setuptools>=65.0.0",
    "pycryptodome",
    "paramiko==2.12.0",
)

PLACEHOLDER_MARKERS = ("your_", "_here", "changeme", "placeholder", "example")


def looks_like_placeholder(value):
    if not value or not str(value).strip():
        return True
    lowered = str(value).strip().lower()
    return any(marker in lowered for marker in PLACEHOLDER_MARKERS)


def valid_env_value(value):
    return bool(value) and not looks_like_placeholder(value)


def ensure_parent_dir(file_path):
    directory = os.path.dirname(file_path)
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)


def reset_target_workspace(target_dir):
    """Delete previous scan artifacts so re-scanning the same IP starts fresh."""
    if not os.path.isdir(target_dir):
        return 0

    removed = 0
    for name in os.listdir(target_dir):
        path = os.path.join(target_dir, name)
        try:
            if os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
            removed += 1
        except OSError as exc:
            print(f"[!] Could not remove {path}: {exc}")

    if removed:
        print(f"[*] Cleared {removed} previous file(s) from target workspace.")
    return removed


def missing_python_modules():
    missing = []
    for module_name in CRITICAL_MODULES:
        root = module_name.split(".", 1)[0]
        try:
            __import__(root if root != "mysql" else "mysql.connector")
        except ImportError:
            missing.append(module_name)
    return missing


def routersploit_python_ready():
    try:
        import pkg_resources  # noqa: F401  # setuptools — required by routersploit wordlists
        from Crypto.Cipher import AES  # noqa: F401
        import paramiko
        return hasattr(paramiko, "DSSKey")
    except ImportError:
        return False


def install_python_packages(packages):
    if not packages:
        return True
    command = [PYTHON, "-m", "pip", "install", "-q", *packages]
    in_venv = getattr(sys, "prefix", "") != getattr(sys, "base_prefix", "")
    if not in_venv:
        command.extend(["--break-system-packages", "--ignore-installed"])
    print(f"[*] Installing Python packages: {', '.join(packages)}")
    result = subprocess.run(command)
    return result.returncode == 0


def ensure_routersploit_deps():
    if routersploit_python_ready():
        return True
    print("[*] RouterSploit needs setuptools + pycryptodome + paramiko==2.12.0...")
    rsf_req = os.path.join(TOOLS_DIR, "routersploit", "requirements.txt")
    if os.path.isfile(rsf_req):
        cmd = [PYTHON, "-m", "pip", "install", "-q", "-r", rsf_req]
        if getattr(sys, "prefix", "") == getattr(sys, "base_prefix", ""):
            cmd.extend(["--break-system-packages"])
        subprocess.run(cmd, check=False)
    if not install_python_packages(list(ROUTERSPLOIT_PACKAGES)):
        print("[!] Failed to install RouterSploit Python dependencies.")
        return False
    if routersploit_python_ready():
        print("[+] RouterSploit Python dependencies are ready.")
        return True
    print("[!] RouterSploit deps missing. Run: bash scripts/fix_routersploit_kali.sh")
    return False


SKIP_RSF_MODULES = {"scanners/autopwn"}


def normalize_routersploit_module(raw):
    if not raw:
        return None
    module = str(raw).strip().replace("\\", "/")
    if "routersploit/modules/" in module:
        module = module.split("routersploit/modules/", 1)[1]
    module = module.replace(".py", "").strip("/")
    if not module or module in SKIP_RSF_MODULES:
        return None
    if module.startswith("scanners/"):
        return None
    if not module.startswith(("exploits/", "creds/")):
        return None
    return module


def sanitize_routersploit_modules(modules):
    cleaned = []
    for entry in modules or []:
        module = normalize_routersploit_module(entry)
        if module and module not in cleaned:
            cleaned.append(module)
    return cleaned


def run_cmd(command, capture=False, log_file=None, timeout=None, cwd=None):
    """
    Run a shell command. When log_file is set, stdout/stderr are saved there.
    Returns (success, combined_output) where success reflects the process exit code.
    timeout: seconds (None = wait forever). On timeout kills the process and returns (False, message).
    """
    try:
        exec_line = f"\n[>] Executing: {' '.join(command) if isinstance(command, list) else command}"
        if timeout:
            exec_line += f" (timeout={timeout}s)"
        print(exec_line)
        try:
            from core.live_scan_log import write as live_write
            live_write(exec_line)
        except Exception:
            pass
        try:
            from core.scan_transcript import command as transcript_command, output as transcript_output
            transcript_command(command)
        except Exception:
            pass

        if capture or log_file:
            try:
                result = subprocess.run(
                    command, capture_output=True, text=True, timeout=timeout, cwd=cwd,
                )
            except subprocess.TimeoutExpired as exc:
                msg = f"Command timed out after {timeout}s"
                print(f"[-] {msg}")
                partial = ""
                if exc.stdout:
                    partial += exc.stdout
                if exc.stderr:
                    partial += ("\n" if partial else "") + exc.stderr
                partial = partial.strip()
                if log_file:
                    try:
                        ensure_parent_dir(log_file)
                        with open(log_file, "w", encoding="utf-8") as f:
                            f.write(f"{msg}\n\n{partial}".strip())
                    except OSError:
                        pass
                try:
                    from core.scan_transcript import event as transcript_event
                    transcript_event(f"[-] {msg}: {' '.join(command) if isinstance(command, list) else command}")
                except Exception:
                    pass
                return False, msg if not partial else f"{msg}\n{partial}"

            output = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
            output = output.strip()
            ok = result.returncode == 0

            if log_file:
                try:
                    ensure_parent_dir(log_file)
                    with open(log_file, "w", encoding="utf-8") as f:
                        f.write(output)
                except PermissionError:
                    print(f"[-] Permission denied writing log file: {log_file}")

            try:
                from core.scan_transcript import output as transcript_output
                transcript_output(output)
            except Exception:
                pass
            try:
                from core.live_scan_log import write as live_write
                if output:
                    live_write(output)
            except Exception:
                pass

            if capture:
                return ok, output

            if output:
                print(output)
            return ok, ""

        result = subprocess.run(command, timeout=timeout, cwd=cwd)
        return result.returncode == 0, ""
    except Exception as e:
        print(f"[-] Failed to execute command: {e}")
        try:
            from core.scan_transcript import event as transcript_event
            transcript_event(f"[-] Failed to execute command: {e}")
        except Exception:
            pass
        return False, str(e)
