import os
import re
import shutil

from core.report.analysis import parse_hydra_credential
from core.utils import run_cmd, TOOLS_DIR
from core.scan_config import get_scan_profile

HYDRA_CMD = "hydra"
DEFAULT_USER = "admin"
COMMON_USERS = ["admin", "root", "user", "support", "telecomadmin"]

ROUTER_HTTP_FORMS = [
    "/login.html:user=^USER^&pass=^PASS^:F=invalid",
    "/login.cgi:user=^USER^&pass=^PASS^:F=invalid",
    "/goform/login:user=^USER^&pass=^PASS^:F=invalid",
    "/cgi-bin/login.cgi:user=^USER^&pass=^PASS^:F=invalid",
    "/cgi-bin/login:user=^USER^&pass=^PASS^:F=invalid",
    "/login:user=^USER^&pass=^PASS^:F=invalid",
]


def resolve_password_file():
    candidates = [
        os.path.join(TOOLS_DIR, "DefaultCreds-cheat-sheet", "routers.txt"),
        os.path.join(TOOLS_DIR, "DefaultCreds-cheat-sheet", "default-passwords.txt"),
        "/usr/share/seclists/Passwords/Default-Credentials/telnet-betterdefaultpasslist.txt",
        "/usr/share/wordlists/rockyou.txt",
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


def hydra_found_credentials(output):
    lowered = output.lower()
    if "login:" not in lowered or "password:" not in lowered:
        return False
    for line in (output or "").splitlines():
        if "login:" not in line.lower() or "password:" not in line.lower():
            continue
        parsed = parse_hydra_credential(line)
        if parsed and not parsed.get("likely_false_positive"):
            return True
    return False


def _hydra_hit_from_output(output):
    for line in (output or "").splitlines():
        if "login:" not in line.lower() or "password:" not in line.lower():
            continue
        parsed = parse_hydra_credential(line)
        if parsed and not parsed.get("likely_false_positive"):
            return parsed
    return None


def run_hydra(ip, login_ports, target_dir):
    profile = get_scan_profile()
    passwords_file = resolve_password_file()
    if not passwords_file:
        print("[!] No password wordlist found for Hydra.")
        return False

    success_flag = False

    for lp in login_ports:
        port = lp["port"]
        service = lp["service"].lower()
        print(f"\n[+] Brute-forcing {service} on port {port}...")

        if service not in ["ssh", "ftp", "telnet"]:
            continue

        target_str = f"{service}://{ip}:{port}"
        log_file = os.path.join(target_dir, f"hydra_{service}_{port}.txt")
        command = [HYDRA_CMD, "-l", DEFAULT_USER, "-P", passwords_file, "-t", str(profile["hydra_threads"]), "-f", target_str]
        success, output = run_cmd(command, capture=True, log_file=log_file)
        if output:
            print(output)
            print(f"[+] Hydra {service} results saved to: {log_file}")

        if hydra_found_credentials(output):
            print(f"[!] SUCCESS! Credentials found for {service}!")
            success_flag = True

    return success_flag


def run_web_hydra(ip, web_ports, target_dir, hydra_plan=None):
    profile = get_scan_profile()
    if not shutil.which(HYDRA_CMD):
        print("[!] Hydra is not installed; skipping web login brute-force.")
        return False

    passwords_file = resolve_password_file()
    if not passwords_file:
        print("[!] No password wordlist found for web Hydra.")
        return False

    users = COMMON_USERS
    forms = ROUTER_HTTP_FORMS
    if hydra_plan:
        users = hydra_plan.get("users") or users
        forms = hydra_plan.get("http_forms") or forms
        source = hydra_plan.get("source", "custom")
        print(f"[*] Using {source} Hydra plan: {len(users)} users, {len(forms)} forms")

    success_flag = False
    skip_http_get = bool(forms and hydra_plan and hydra_plan.get("source") in ("target_profile", "target_hints"))
    if skip_http_get:
        print("[*] Skipping http-get on / — using discovered login form paths first.")

    for port in web_ports:
        service = "https-get" if port in [443, 8443] else "http-get"
        print(f"\n[+] Brute-forcing router web login on port {port}...")

        if not skip_http_get:
            for user in users[: profile["hydra_users"]]:
                log_file = os.path.join(target_dir, f"hydra_web_{port}_{user}.txt")
                command = [
                    HYDRA_CMD, "-l", user, "-P", passwords_file,
                    "-t", str(profile["hydra_threads"]), "-f", "-s", str(port),
                    ip, service,
                ]
                success, output = run_cmd(command, capture=True, log_file=log_file)
                if output:
                    print(output)
                hit = _hydra_hit_from_output(output)
                if hit:
                    print(f"[!] Possible web credentials on port {port} for user {hit['login']} — verify manually.")
                    success_flag = True
                    break
                elif hydra_found_credentials(output):
                    print(f"[!] Hydra reported a hit on port {port} but it looks like a false positive — check log.")

            if success_flag:
                break

        for form in forms[: profile["hydra_forms"]]:
            form_name = form.split(":")[0].replace("/", "_").strip("_") or "root"
            log_file = os.path.join(target_dir, f"hydra_web_{port}_form_{form_name}.txt")
            users_file = os.path.join(target_dir, f"hydra_users_{port}.txt")
            with open(users_file, "w", encoding="utf-8") as fh:
                fh.write("\n".join(users))
            command = [
                HYDRA_CMD, "-L", users_file, "-P", passwords_file,
                "-t", str(profile["hydra_threads"]), "-f", "-s", str(port),
                ip, "http-post-form", form,
            ]
            success, output = run_cmd(command, capture=True, log_file=log_file)
            if output:
                print(output)
            hit = _hydra_hit_from_output(output)
            if hit:
                print(f"[!] Possible form credentials on port {port} ({form_name}) — verify manually.")
                success_flag = True
                break
            elif "login:" in (output or "").lower() and "password:" in (output or "").lower():
                print(f"[!] Hydra form hit on {form_name} looks unverified — check {log_file}")

        if success_flag:
            break

    return success_flag
