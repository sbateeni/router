import subprocess
import os
import sys

TOOLS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools")
PYTHON = sys.executable

CRITICAL_MODULES = (
    "mysql.connector",
    "requests",
    "colorama",
    "defusedxml",
)


def ensure_parent_dir(file_path):
    directory = os.path.dirname(file_path)
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)


def missing_python_modules():
    missing = []
    for module_name in CRITICAL_MODULES:
        root = module_name.split(".", 1)[0]
        try:
            __import__(root if root != "mysql" else "mysql.connector")
        except ImportError:
            missing.append(module_name)
    return missing


def run_cmd(command, capture=False, log_file=None):
    """
    Run a shell command. When log_file is set, stdout/stderr are saved there.
    Returns (success, combined_output) where success reflects the process exit code.
    """
    try:
        print(f"\n[>] Executing: {' '.join(command) if isinstance(command, list) else command}")

        if capture or log_file:
            result = subprocess.run(command, capture_output=True, text=True)
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

            if capture:
                return ok, output

            if output:
                print(output)
            return ok, ""

        result = subprocess.run(command)
        return result.returncode == 0, ""
    except Exception as e:
        print(f"[-] Failed to execute command: {e}")
        return False, str(e)
