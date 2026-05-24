"""Telegram-friendly wrappers for OSINT, LAN, PoC scraper, updates, and device engine."""

from __future__ import annotations

import io
import json
import os
import re
import threading
from contextlib import redirect_stdout

from core.paths import project_root

EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
PHONE_RE = re.compile(r"^\+?[0-9][0-9\s\-]{7,18}[0-9]$")


def _truncate(text: str, limit: int = 3800) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 40] + "\n\n... (truncated)"


def _capture(fn, *args, **kwargs) -> str:
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            result = fn(*args, **kwargs)
    except Exception as exc:
        return f"❌ Error: {exc}"
    out = buf.getvalue().strip()
    if isinstance(result, str) and result.strip():
        return result.strip()
    return out or "✓ Done (no output)."


def format_osint_email(email: str) -> str:
    from engines.social_osint import SocialOSINT

    osint = SocialOSINT()
    sites = osint.check_email(email)
    lines = [f"📧 Email OSINT: {email}", ""]
    if sites:
        lines.append(f"Registered on {len(sites)} site(s):")
        for site in sites[:40]:
            lines.append(f"  [+] {site}")
        if len(sites) > 40:
            lines.append(f"  ... +{len(sites) - 40} more")
    else:
        lines.append("No registrations found in checked sites.")
    osint.save_results()
    return _truncate("\n".join(lines))


def format_osint_phone(phone: str) -> str:
    from engines.social_osint import SocialOSINT

    osint = SocialOSINT()
    results = osint.check_phone(phone)
    lines = [f"📱 Phone OSINT: {phone}", ""]
    for r in results or []:
        name = r.get("name") or "—"
        lines.append(f"  {r.get('platform', '?')}: {r.get('status', '?')} | {name}")
        if r.get("url"):
            lines.append(f"    {r['url']}")
    osint.save_results()
    return _truncate("\n".join(lines))


def format_osint_username(username: str) -> str:
    from engines.social_osint import SocialOSINT

    osint = SocialOSINT()
    profiles = osint.hunt_username(username)
    lines = [f"👤 Username hunt: {username}", ""]
    if profiles:
        lines.append(f"Found {len(profiles)} profile(s):")
        for p in profiles[:35]:
            lines.append(f"  [+] {p.get('site', '?')} → {p.get('url', '')}")
        if len(profiles) > 35:
            lines.append(f"  ... +{len(profiles) - 35} more")
    else:
        lines.append("No profiles found.")
    osint.save_results()
    return _truncate("\n".join(lines))


def format_osint_full(email: str) -> str:
    parts = [format_osint_email(email)]
    username = email.split("@")[0]
    parts.append("")
    parts.append(format_osint_username(username))
    return _truncate("\n\n".join(parts))


def run_osint_action(kind: str, value: str) -> str:
    kind = (kind or "").lower().strip()
    value = (value or "").strip()
    if not value:
        return "❌ Provide a value after the osint subcommand."

    if kind in ("email", "mail", "e"):
        if not EMAIL_RE.match(value):
            return "❌ Invalid email format."
        return format_osint_email(value)
    if kind in ("phone", "tel", "p"):
        return format_osint_phone(value)
    if kind in ("user", "username", "u"):
        return format_osint_username(value)
    if kind in ("full", "investigate", "f"):
        if not EMAIL_RE.match(value):
            return "❌ Full investigation requires a valid email."
        return format_osint_full(value)
    return (
        "❌ Unknown osint type. Use:\n"
        "/osint email user@mail.com\n"
        "/osint phone +966...\n"
        "/osint user username\n"
        "/osint full user@mail.com"
    )


def format_lan_scan() -> tuple[str, list[dict]]:
    from engines.lan_scanner import LANScanner

    scanner = LANScanner()
    lines = [
        f"🌐 LAN Scan — local IP: {scanner.local_ip}",
        f"   Subnet: {scanner.subnet}0/24",
        "",
    ]
    devices = scanner.run_scan()
    if not devices:
        lines.append("No devices found on LAN.")
        return "\n".join(lines), []

    lines.append(f"Found {len(devices)} device(s):")
    for i, dev in enumerate(devices, 1):
        lines.append(f"  [{i}] {dev['ip']:<15} | {dev.get('type', 'UNKNOWN'):<12} | port {dev.get('port', '?')}")
    lines.append("\nUse /lan attack N to AUTO-PWN device N.")
    return "\n".join(lines), devices


def format_history() -> tuple[str, list[str]]:
    db_dir = os.path.join(project_root(), "db")
    if not os.path.isdir(db_dir):
        return "No previous targets (db/ empty).", []

    ips: list[str] = []
    lines = ["📂 Previous targets:", ""]
    for i, name in enumerate(sorted(f for f in os.listdir(db_dir) if f.endswith(".json")), 1):
        path = os.path.join(db_dir, name)
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            ip = data.get("ip", name.replace(".json", ""))
            status = data.get("status", "UNKNOWN")
            ips.append(ip)
            lines.append(f"  [{i}] {ip:<15} | {status}")
        except OSError:
            continue

    if not ips:
        return "No valid history entries.", []
    lines.append("\nSend IP/URL or use scan modes on any listed target.")
    return "\n".join(lines), ips


def run_poc_scraper() -> str:
    from engines.zero_day_scraper import ZeroDayScraper

    scraper = ZeroDayScraper()
    found = scraper.search_and_download()
    if found:
        names = [r.get("name", "?") for r in found[:15]]
        body = "\n".join(f"  • {n}" for n in names)
        extra = f"\n  ... +{len(found) - 15} more" if len(found) > 15 else ""
        return f"✅ PoC Scraper: {len(found)} repo(s)\n{body}{extra}"
    return "✓ PoC Scraper finished — no new repos matched."


def run_framework_update() -> str:
    from engines.updater import run_startup_update

    run_startup_update(update_project=True, update_tools=True, update_templates=True)
    return "✅ Framework & tools update check completed."


def run_decepticon(target: str) -> str:
    from engines.decepticon_core import DecepticonCore

    core = DecepticonCore(target)
    core.run_autonomous_mode()
    report = os.path.join(core.output_dir, "DECEPTICON_REPORT.txt")
    if os.path.isfile(report):
        with open(report, encoding="utf-8", errors="ignore") as fh:
            return _truncate(f"🤖 Decepticon finished\n\n{fh.read()}")
    return f"🤖 Decepticon finished for {target}. Output: {core.output_dir}"


def run_device_engine(target: str, manual_mode: bool = False) -> str:
    from engines.auto_pwn_main import main as engine_main

    if not target.startswith("http"):
        target = "http://" + target
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            engine_main(target, manual_mode=manual_mode)
    except Exception as exc:
        return f"❌ Device Engine error: {exc}"
    out = buf.getvalue().strip()
    return _truncate(out or f"✅ Device Engine completed for {target}")


def run_task_async(callback, on_done, *args, **kwargs):
    """Run blocking work in a daemon thread; on_done(text) on completion."""

    def worker():
        try:
            result = callback(*args, **kwargs)
            on_done(result if isinstance(result, str) else str(result))
        except Exception as exc:
            on_done(f"❌ {exc}")

    threading.Thread(target=worker, daemon=True).start()


def detect_osint_message(text: str) -> tuple[str, str] | None:
    """Auto-detect osint:email@x.com or plain email/phone if not a scan target."""
    raw = (text or "").strip()
    lower = raw.lower()

    for prefix in ("osint:", "intel:"):
        if lower.startswith(prefix):
            rest = raw[len(prefix):].strip()
            parts = rest.split(None, 1)
            if len(parts) == 2:
                return parts[0], parts[1]
            if EMAIL_RE.match(rest):
                return "email", rest
            return "user", rest

    if EMAIL_RE.match(raw):
        return "email", raw
    if PHONE_RE.match(raw.replace(" ", "")):
        return "phone", raw.replace(" ", "")
    return None
