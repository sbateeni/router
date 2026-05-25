import os
import shutil

import requests

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


def resolve_password_file(target_dir=None):
    if target_dir:
        iot_pwd = os.path.join(target_dir, "hydra_iot_passwords.txt")
        if os.path.isfile(iot_pwd) and os.path.getsize(iot_pwd) > 20:
            return iot_pwd
    candidates = [
        os.path.join(TOOLS_DIR, "jeanphorn-wordlist", "passwords", "iot.txt"),
        os.path.join(TOOLS_DIR, "DefaultCreds-cheat-sheet", "default-passwords.txt"),
        os.path.join(TOOLS_DIR, "DefaultCreds-cheat-sheet", "routers.txt"),
        "/usr/share/seclists/Passwords/Default-Credentials/telnet-betterdefaultpasslist.txt",
        "/usr/share/wordlists/rockyou.txt",
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


def prepare_password_wordlist(source_path, target_dir):
    """
    Build password-only list. Strips user:pass lines (colon breaks Hydra -P and causes false positives).
    """
    out_path = os.path.join(target_dir, "hydra_passwords_filtered.txt")
    passwords = []
    seen = set()
    try:
        with open(source_path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                raw = line.strip()
                if not raw or raw.startswith("#"):
                    continue
                if ":" in raw and not raw.startswith("http"):
                    pwd = raw.split(":", 1)[1].strip()
                else:
                    pwd = raw
                if not pwd or pwd in seen:
                    continue
                seen.add(pwd)
                passwords.append(pwd)
    except OSError:
        return source_path

    if len(passwords) < 5:
        return source_path

    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(passwords))
    return out_path


def form_path(form_string):
    return (form_string or "/").split(":")[0] or "/"


def probe_http_auth(ip, port, path="/"):
    scheme = "https" if port in (443, 8443) else "http"
    netloc = ip if port in (80, 443) else f"{ip}:{port}"
    if not path.startswith("/"):
        path = f"/{path}"
    url = f"{scheme}://{netloc}{path}"
    try:
        response = requests.head(url, timeout=12, allow_redirects=False)
        status = response.status_code
        auth_header = response.headers.get("WWW-Authenticate", "")
    except requests.RequestException:
        try:
            response = requests.get(url, timeout=12, allow_redirects=False)
            status = response.status_code
            auth_header = response.headers.get("WWW-Authenticate", "")
        except requests.RequestException as exc:
            return {"path": path, "url": url, "error": str(exc)}

    lowered = auth_header.lower()
    return {
        "path": path,
        "url": url,
        "status": status,
        "basic_auth": status == 401 and "basic" in lowered,
        "digest_auth": status == 401 and "digest" in lowered,
        "www_authenticate": auth_header,
    }


def hydra_output_unreliable(output, mode="http-post-form"):
    text = (output or "").lower()
    if mode == "http-post-form" and "received http error code 401" in text:
        if "use module \"http-get\"" in text or "http auth" in text:
            return True
    return False


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


def _hydra_hit_from_output(output, mode="http-post-form"):
    if hydra_output_unreliable(output, mode):
        return None
    for line in (output or "").splitlines():
        if "login:" not in line.lower() or "password:" not in line.lower():
            continue
        parsed = parse_hydra_credential(line)
        if parsed and not parsed.get("likely_false_positive"):
            return parsed
    return None


def run_hydra(ip, login_ports, target_dir):
    profile = get_scan_profile()
    passwords_file = resolve_password_file(target_dir)
    if not passwords_file:
        print("[!] No password wordlist found for Hydra.")
        return False

    passwords_file = prepare_password_wordlist(passwords_file, target_dir)
    success_flag = False

    for lp in login_ports:
        port = lp.get("port")
        if not port:
            continue
        service = str(lp.get("service", "")).lower()
        if not service:
            continue
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


def _run_http_basic_hydra(ip, port, path, users, passwords_file, target_dir, profile):
    service = "https-get" if port in [443, 8443] else "http-get"
    safe_path = path.replace("/", "_").strip("_") or "root"
    print(f"[*] HTTP Basic/Digest auth on {path} — using {service} (not http-post-form).")
    for user in users[: profile["hydra_users"]]:
        log_file = os.path.join(target_dir, f"hydra_web_{port}_basic_{safe_path}_{user}.txt")
        command = [
            HYDRA_CMD, "-l", user, "-P", passwords_file,
            "-t", str(profile["hydra_threads"]), "-f", "-s", str(port),
            ip, service, path,
        ]
        success, output = run_cmd(command, capture=True, log_file=log_file)
        if output:
            print(output)
        hit = _hydra_hit_from_output(output, mode=service)
        if hit:
            print(
                f"[!] Possible HTTP-auth credentials on {path} "
                f"(user={hit['login']}) — verify: curl -u user:pass {probe_http_auth(ip, port, path).get('url', '')}"
            )
            return True
    return False


def run_web_hydra(ip, web_ports, target_dir, hydra_plan=None):
    profile = get_scan_profile()
    if not shutil.which(HYDRA_CMD):
        print("[!] Hydra is not installed; skipping web login brute-force.")
        return False

    raw_passwords = resolve_password_file(target_dir)
    if not raw_passwords:
        print("[!] No password wordlist found for web Hydra.")
        return False

    passwords_file = prepare_password_wordlist(raw_passwords, target_dir)
    if passwords_file != raw_passwords:
        print("[*] Using filtered password list (removed user:pass lines that cause false positives).")

    users = COMMON_USERS
    forms = ROUTER_HTTP_FORMS
    if hydra_plan:
        users = hydra_plan.get("users") or users
        forms = hydra_plan.get("http_forms") or forms
        source = hydra_plan.get("source", "custom")
        print(f"[*] Using {source} Hydra plan: {len(users)} users, {len(forms)} forms")

    success_flag = False
    probed_paths = {}

    for port in web_ports:
        print(f"\n[+] Brute-forcing router web login on port {port}...")

        unique_paths = list(dict.fromkeys(form_path(f) for f in forms[: profile["hydra_forms"]]))
        basic_paths = []
        form_paths = []

        for path in unique_paths:
            if path in probed_paths:
                info = probed_paths[path]
            else:
                info = probe_http_auth(ip, port, path)
                probed_paths[path] = info
            if info.get("basic_auth") or info.get("digest_auth"):
                basic_paths.append(path)
                print(f"[*] {path} → HTTP {info.get('status')} {info.get('www_authenticate', '')[:60]}")
            else:
                form_paths.append(path)

        for path in basic_paths:
            if _run_http_basic_hydra(ip, port, path, users, passwords_file, target_dir, profile):
                success_flag = True
                break

        if success_flag:
            break

        forms_for_port = [f for f in forms[: profile["hydra_forms"]] if form_path(f) in form_paths]
        if basic_paths and not forms_for_port:
            print("[*] All discovered login paths use HTTP auth — skipped http-post-form.")

        for form in forms_for_port:
            form_name = form_path(form).replace("/", "_").strip("_") or "root"
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
            if hydra_output_unreliable(output, "http-post-form"):
                print(f"[!] {form_name}: endpoint uses HTTP Basic Auth — post-form results ignored.")
                continue
            hit = _hydra_hit_from_output(output, "http-post-form")
            if hit:
                print(f"[!] Possible form credentials on port {port} ({form_name}) — verify manually.")
                success_flag = True
                break

        if success_flag:
            break

    return success_flag
