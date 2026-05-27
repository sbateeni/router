import subprocess
import os
import shutil
import sys
import signal
import time

TOOLS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools")
PYTHON = sys.executable

CRITICAL_MODULES = (
    "mysql.connector",
    "requests",
    "colorama",
    "defusedxml",
)

ROUTERSPLOIT_PACKAGES = (
    "setuptools>=65.0.0,<81",
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
        from Crypto.Cipher import AES  # noqa: F401
        import paramiko
        return hasattr(paramiko, "DSSKey")
    except ImportError:
        return False


def routersploit_rsf_import_ready():
    """Verify rsf.py can import (catches missing setuptools, paramiko, etc.)."""
    rsf_dir = os.path.join(TOOLS_DIR, "routersploit")
    rsf_py = os.path.join(rsf_dir, "rsf.py")
    if not os.path.isfile(rsf_py):
        return False, f"RouterSploit not found at {rsf_py}"
    code = (
        "import sys\n"
        "sys.path.insert(0, '.')\n"
        "from routersploit.interpreter import RoutersploitInterpreter\n"
    )
    try:
        result = subprocess.run(
            [PYTHON, "-c", code],
            cwd=rsf_dir,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        return False, "RouterSploit import timed out after 60s"
    except OSError as exc:
        return False, str(exc)
    if result.returncode == 0:
        return True, ""
    err = (result.stderr or result.stdout or "RouterSploit import failed").strip()
    return False, err


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
    try:
        from core.routersploit_patch import patch_routersploit_wordlists
        patch_routersploit_wordlists()
    except Exception:
        pass

    ok, err = routersploit_rsf_import_ready()
    if ok:
        return True

    print("[*] RouterSploit deps missing or broken — installing...")
    if err:
        print(f"[*] Import check: {err.splitlines()[0][:200]}")

    rsf_req = os.path.join(TOOLS_DIR, "routersploit", "requirements.txt")
    if os.path.isfile(rsf_req):
        cmd = [PYTHON, "-m", "pip", "install", "-q", "-r", rsf_req]
        if getattr(sys, "prefix", "") == getattr(sys, "base_prefix", ""):
            cmd.extend(["--break-system-packages"])
        subprocess.run(cmd, check=False)
    if not install_python_packages(list(ROUTERSPLOIT_PACKAGES)):
        print("[!] Failed to install RouterSploit Python dependencies.")
        return False

    try:
        from core.routersploit_patch import patch_routersploit_wordlists
        patch_routersploit_wordlists()
    except Exception:
        pass

    ok, err = routersploit_rsf_import_ready()
    if ok:
        print("[+] RouterSploit dependencies are ready.")
        return True

    print("[!] RouterSploit still cannot import after install.")
    if err:
        for line in err.splitlines()[:8]:
            print(f"    {line}")
    print("[!] Run on Kali: bash scripts/fix_routersploit_kali.sh")
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


def sanitize_routersploit_modules(modules):
    cleaned = []
    for entry in modules or []:
        module = normalize_routersploit_module(entry)
        if module and module not in cleaned:
            cleaned.append(module)
    return cleaned


def _popen_kwargs(cwd=None):
    kwargs = {"cwd": cwd}
    if os.name != "nt":
        kwargs["start_new_session"] = True
    return kwargs


def _terminate_process(proc):
    if proc is None or proc.poll() is not None:
        return
    try:
        if os.name != "nt":
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        else:
            proc.terminate()
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except OSError:
            pass


def _communicate_process(proc, timeout=None):
    from core.scan_cancel import is_cancelled, register_pid, unregister_pid

    register_pid(proc.pid)
    try:
        if timeout is None:
            while proc.poll() is None:
                if is_cancelled():
                    _terminate_process(proc)
                    try:
                        proc.communicate(timeout=5)
                    except Exception:
                        pass
                    return None, None, True
                time.sleep(0.4)
            stdout, stderr = proc.communicate()
            return stdout, stderr, is_cancelled()
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            return stdout, stderr, is_cancelled()
        except subprocess.TimeoutExpired:
            _terminate_process(proc)
            partial_out, partial_err = proc.communicate()
            raise subprocess.TimeoutExpired(proc.args, timeout, output=partial_out, stderr=partial_err)
    finally:
        unregister_pid(proc.pid)
        if proc.poll() is None:
            _terminate_process(proc)


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
            from core.scan_cancel import ScanCancelled, check_cancelled

            check_cancelled()
            try:
                proc = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    **_popen_kwargs(cwd),
                )
                stdout, stderr, cancelled = _communicate_process(proc, timeout=timeout)
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

            if cancelled:
                msg = "Scan cancelled by user"
                print(f"[-] {msg}")
                if log_file:
                    try:
                        ensure_parent_dir(log_file)
                        with open(log_file, "w", encoding="utf-8") as f:
                            f.write(msg)
                    except OSError:
                        pass
                raise ScanCancelled(msg)

            output = (stdout or "") + ("\n" + stderr if stderr else "")
            output = output.strip()
            ok = proc.returncode == 0

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

        from core.scan_cancel import check_cancelled

        check_cancelled()
        proc = subprocess.Popen(command, **_popen_kwargs(cwd))
        _, _, cancelled = _communicate_process(proc, timeout=timeout)
        if cancelled:
            from core.scan_cancel import ScanCancelled
            raise ScanCancelled("Scan cancelled by user")
        return proc.returncode == 0, ""
    except Exception as e:
        from core.scan_cancel import ScanCancelled

        if isinstance(e, ScanCancelled):
            raise
        print(f"[-] Failed to execute command: {e}")
        try:
            from core.scan_transcript import event as transcript_event
            transcript_event(f"[-] Failed to execute command: {e}")
        except Exception:
            pass
        return False, str(e)
