"""Unified workspace view for GUI Results panel and Telegram mirror."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from gui.navigation import NAV_ITEMS, PAGE_SPECS

# GUI sidebar label → page_id (for "go to tool" buttons)
PAGE_ID_BY_TITLE: dict[str, str] = {spec["title"]: pid for pid, spec in PAGE_SPECS.items()}
PAGE_ID_BY_TITLE.update({label: pid for pid, label, _ in NAV_ITEMS})
PAGE_ID_BY_TITLE.update({
    "AUTO-PWN Target": "engine_autopwn",
    "Device AUTO-PWN": "engine_autopwn",
    "Device Engine": "engine_autopwn",
    "Comprehensive Scan": "comprehensive",
    "AI Guided Scan": "ai_guided",
    "Test Hikvision": "util_hik_test",
    "Test Router": "util_router_test",
    "Router Deep Harvest": "util_router_harvest",
    "CVE Report": "util_cve_test",
    "Direct Camera": "util_direct_cam",
    "LAN Discovery": "recon_lan",
    "Nmap Vuln Scripts": "recon_nmap_vuln",
})

IMPORTANT_FILES = (
    ("AI_COMPREHENSIVE_REPORT.txt", "AI comprehensive report"),
    ("AI_WORKSPACE_STATE.json", "AI workspace state"),
    ("AI_ORCHESTRATOR_LOG.jsonl", "AI orchestrator log"),
    ("ROUTER_HARVEST.txt", "Router harvest"),
    ("ROUTER_HARVEST.json", "Router harvest (JSON)"),
    ("ROUTER_ACCESS.txt", "Router login"),
    ("nmap_scan.txt", "Nmap"),
    ("ingram_scan.txt", "Ingram log"),
    ("workflow_recommendations.json", "Next tools"),
    ("hikvision_test_report.json", "Hikvision test"),
    ("recon_summary.json", "Recon summary"),
    ("target_profile.json", "Target profile"),
    ("hydra_success.txt", "Hydra hits"),
    ("hydra_web_success.txt", "Hydra web"),
    ("credentials.txt", "Credentials"),
    ("loot_summary.txt", "Loot"),
    ("RESULTS_SUMMARY.txt", "Full report"),
    ("SCAN_TRANSCRIPT.txt", "Scan timeline"),
)


def page_id_for_tool_name(gui_name: str) -> str | None:
    if not gui_name:
        return None
    if gui_name in PAGE_ID_BY_TITLE:
        return PAGE_ID_BY_TITLE[gui_name]
    low = gui_name.lower()
    for title, pid in PAGE_ID_BY_TITLE.items():
        if title.lower() == low:
            return pid
    return None


def _read_text(path: str, limit: int = 12000) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return ""


def _load_json(path: str) -> Any:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def _find_credentials(target_dir: str) -> list[str]:
    found: list[str] = []
    if not target_dir:
        return found

    hik = _load_json(os.path.join(target_dir, "hikvision_test_report.json"))
    if isinstance(hik, dict):
        if hik.get("digest_valid") and hik.get("digest_password"):
            found.append(f"Hikvision (ISAPI): admin:{hik['digest_password']}")
        if hik.get("backdoor_confirmed"):
            found.append("Hikvision backdoor: admin:11 bypass (not real web password)")

    harvest = _load_json(os.path.join(target_dir, "ROUTER_HARVEST.json"))
    if isinstance(harvest, dict) and harvest.get("username"):
        found.append(
            f"Router web: {harvest['username']}:{harvest.get('password', '')} "
            f"({harvest.get('auth_method', 'harvest')})"
        )
        w = harvest.get("wireless") or {}
        ssid, key = w.get("ssid", ""), w.get("key", "")
        if ssid and ssid.lower() not in ("type", "type="):
            found.append(f"Wi-Fi SSID: {ssid}")
        if key and key.lower() not in ("type", "type=", "password") and len(key) > 3:
            found.append(f"Wi-Fi key: {key}")
        for s in (harvest.get("form_secrets") or [])[:6]:
            found.append(f"Form [{s.get('page', '?')}]: {s.get('field')}={s.get('value')}")
        for c in (harvest.get("connected_clients") or [])[:12]:
            if not c.get("mac") and not c.get("ip"):
                continue
            if c.get("ip", "").endswith(".1") and not c.get("mac"):
                continue
            found.append(
                f"LAN: ip={c.get('ip', '—')} mac={c.get('mac', '—')} "
                f"name={c.get('hostname', '—')}"
            )

    for name in ("hydra_success.txt", "hydra_web_success.txt", "credentials.txt", "loot_summary.txt"):
        text = _read_text(os.path.join(target_dir, name), 4000)
        if not text:
            continue
        for m in re.finditer(r"\b(admin|root|guest):(\S+)", text, re.I):
            line = f"{m.group(1)}:{m.group(2)} ({name})"
            if line not in found:
                found.append(line)

    ingram_dir = os.path.join(target_dir, "ingram_results")
    if os.path.isdir(ingram_dir):
        for path in Path(ingram_dir).rglob("*"):
            if path.suffix.lower() not in (".txt", ".csv", ".log"):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+)[:\s]+(\S+):(\S+)", text):
                line = f"Ingram: {m.group(2)}:{m.group(3)}"
                if line not in found:
                    found.append(line)

    return found[:12]


def _list_workspace_files(target_dir: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    if not target_dir or not os.path.isdir(target_dir):
        return rows
    root = Path(target_dir)
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            continue
        if path.stat().st_size > 8_000_000:
            continue
        rows.append({"rel": rel, "path": str(path), "size": str(path.stat().st_size)})
    return rows


def collect_workspace_view(target_dir: str, host: str = "") -> dict[str, Any]:
    from gui.workspace_context import summarize_workspace

    view: dict[str, Any] = {
        "host": host,
        "target_dir": target_dir,
        "exists": bool(target_dir and os.path.isdir(target_dir)),
        "open_ports": [],
        "credentials": [],
        "next_tools": [],
        "highlights": [],
        "files": [],
    }
    if not view["exists"]:
        return view

    summary = summarize_workspace(target_dir)
    view["open_ports"] = summary.get("open_ports") or []
    view["artifacts"] = summary.get("artifacts") or []
    view["hints"] = summary.get("hints") or []

    wf = os.path.join(target_dir, "workflow_recommendations.json")
    data = _load_json(wf)
    if isinstance(data, dict) and data.get("next_tools"):
        view["next_tools"] = data["next_tools"]
    else:
        try:
            from core.workflow_recommendations import build_tool_recommendations

            steps = build_tool_recommendations(target_dir, host or "")
            view["next_tools"] = [
                {
                    "priority": s.priority,
                    "gui_name": s.gui_name,
                    "nav_hint": s.nav_hint,
                    "reason": s.reason,
                    "page_id": page_id_for_tool_name(s.gui_name),
                }
                for s in steps
            ]
        except Exception:
            pass

    view["credentials"] = _find_credentials(target_dir)
    view["ingram_note"] = _ingram_result_note(target_dir)
    view["router_harvest_note"] = _router_harvest_note(target_dir)
    view["files"] = _list_workspace_files(target_dir)

    for fname, label in IMPORTANT_FILES:
        p = os.path.join(target_dir, fname)
        if os.path.isfile(p):
            view["highlights"].append({"file": fname, "label": label, "path": p})

    snap = os.path.join(target_dir, "snapshots")
    if os.path.isdir(snap):
        jpgs = [f for f in os.listdir(snap) if f.lower().endswith((".jpg", ".jpeg", ".png"))]
        if jpgs:
            view["highlights"].append({
                "file": f"snapshots/ ({len(jpgs)} images)",
                "label": "Camera snapshots",
                "path": snap,
            })

    return view


def _router_harvest_note(target_dir: str) -> str:
    data = _load_json(os.path.join(target_dir, "ROUTER_HARVEST.json"))
    if not isinstance(data, dict):
        return ""
    clients = data.get("connected_clients") or []
    with_mac = sum(1 for c in clients if c.get("mac"))
    pages = data.get("pages_fetched", 0)
    cves = len(data.get("cve_assessments") or [])
    w = data.get("wireless") or {}
    wifi = f" SSID={w['ssid']}" if w.get("ssid") and w["ssid"] != "type" else ""
    return (
        f"{data.get('device_type', '?')} {data.get('model', '')} — "
        f"{pages} pages, {with_mac} client(s) w/ MAC, {len(clients)} IP rows, "
        f"{cves} CVE notes{wifi}"
    )


def _ingram_result_note(target_dir: str) -> str:
    path = os.path.join(target_dir, "ingram_scan.txt")
    text = _read_text(path, 12000).lower()
    if not text:
        return "Ingram: no ingram_scan.txt in workspace."
    if "vulnerable" in text or "successfully exploited" in text:
        return "Ingram: possible hit — read ingram_scan.txt and ingram_results/"
    if "ingram results saved" in text or os.path.isdir(os.path.join(target_dir, "ingram_results")):
        csv = os.path.join(target_dir, "ingram_results", "results.csv")
        if os.path.isfile(csv):
            return f"Ingram: finished — open ingram_results/results.csv (preview in Results tab)"
        return "Ingram: finished — open ingram_results/ folder"
    return "Ingram: finished quickly — likely no default camera creds on this IP (ZyXEL/hik-connect mix)."


def format_results_summary(view: dict[str, Any], *, finished_tool: str = "") -> str:
    lines = ["═══ نتائج الهدف ═══"]
    if view.get("host"):
        lines.append(f"الهدف: {view['host']}")
    if finished_tool:
        lines.append(f"آخر أداة: {finished_tool}")
    if view.get("target_dir"):
        lines.append(f"المجلد: {view['target_dir']}")

    ports = view.get("open_ports") or []
    if ports:
        lines.append(f"منافذ: {', '.join(ports[:10])}")

    creds = view.get("credentials") or []
    if creds:
        lines.append("— حسابات / creds —")
        lines.extend(f"  • {c}" for c in creds)
    else:
        lines.append("— لا creds مؤكدة في workspace —")

    ingram_note = view.get("ingram_note")
    if ingram_note:
        lines.append(f"— Ingram —\n  • {ingram_note}")

    harvest_note = view.get("router_harvest_note")
    if harvest_note:
        lines.append(f"— Router harvest —\n  • {harvest_note}")

    comp = os.path.join(target_dir, "AI_COMPREHENSIVE_REPORT.txt")
    if os.path.isfile(comp):
        lines.append("— AI comprehensive report —\n  • AI_COMPREHENSIVE_REPORT.txt (full Arabic report)")

    tools = view.get("next_tools") or []
    if tools:
        lines.append("— التالي في GUI —")
        for t in tools[:6]:
            name = t.get("gui_name", "?")
            reason = (t.get("reason") or "")[:80]
            lines.append(f"  [{t.get('priority', '?')}] {name}: {reason}")

    hi = view.get("highlights") or []
    if hi:
        lines.append("— ملفات مهمة —")
        for h in hi[:8]:
            lines.append(f"  • {h.get('label')}: {h.get('file')}")

    return "\n".join(lines)


def build_telegram_digest(
    target_dir: str,
    host: str,
    *,
    finished_tool: str = "",
    exploited: bool = False,
) -> str:
    view = collect_workspace_view(target_dir, host)
    body = format_results_summary(view, finished_tool=finished_tool)
    if exploited:
        body += "\n\n⚠ إشارة استغلال/نتائج في التشغيل الأخير."
    return body
