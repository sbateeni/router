"""
Structured workspace snapshot for AI orchestrator and final reports.
Single source of truth built from artifacts on disk (no GUI dependency).
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from core.report.parsers import load_target_hints, parse_nmap_summary
from core.target_auth import creds_from_router_access, parse_target_auth
from core.workspace_ports import load_open_ports_from_workspace, open_port_numbers

STATE_FILE = "AI_WORKSPACE_STATE.json"
ORCHESTRATOR_LOG = "AI_ORCHESTRATOR_LOG.jsonl"
STEP_NOTES = "AI_STEP_NOTES.jsonl"

ALLOWED_TOOLS: dict[str, dict[str, Any]] = {
    "nmap": {"selection": 2, "label": "Nmap"},
    "nuclei": {"selection": 3, "label": "Nuclei"},
    "dirsearch": {"selection": 4, "label": "Dirsearch"},
    "sqlmap": {"selection": 5, "label": "SQLMap"},
    "routersploit": {"selection": 6, "label": "RouterSploit"},
    "ingram": {"selection": 7, "label": "Ingram"},
    "hydra": {"selection": 8, "label": "Hydra"},
    "ffuf": {"selection": 9, "label": "FFUF"},
    "whatweb": {"selection": 18, "label": "WhatWeb"},
    "nikto": {"selection": 17, "label": "Nikto"},
    "nmap_vuln": {"selection": 19, "label": "Nmap Vuln Scripts"},
    "router_harvest": {"custom": True, "label": "Router Deep Harvest"},
    "test_hikvision": {"custom": True, "label": "Test Hikvision"},
    "test_router": {"custom": True, "label": "Test Router"},
    "autopwn_engine": {"selection": 21, "label": "AUTO-PWN Engine"},
}


def _load_json(path: str) -> Any:
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def _read_tail(path: str, limit: int = 4000) -> str:
    if not os.path.isfile(path):
        return ""
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            data = fh.read()
        return data[-limit:] if len(data) > limit else data
    except OSError:
        return ""


def _collect_credentials(target_dir: str) -> list[dict[str, str]]:
    creds: list[dict[str, str]] = []
    harvest = _load_json(os.path.join(target_dir, "ROUTER_HARVEST.json"))
    if isinstance(harvest, dict) and harvest.get("username"):
        creds.append({
            "source": "router_harvest",
            "username": harvest["username"],
            "password": harvest.get("password", ""),
            "auth_method": harvest.get("auth_method", ""),
        })
        w = harvest.get("wireless") or {}
        if w.get("ssid"):
            creds.append({"source": "wifi", "ssid": w["ssid"], "password": w.get("key", "")})

    hik = _load_json(os.path.join(target_dir, "hikvision_test_report.json"))
    if isinstance(hik, dict) and hik.get("digest_valid") and hik.get("digest_password"):
        creds.append({
            "source": "hikvision",
            "username": "admin",
            "password": hik["digest_password"],
        })

    loot = _load_json(os.path.join(target_dir, "ENGINE_LOOT.json"))
    if isinstance(loot, dict):
        for entry in (loot.get("loot") or {}).get("entries") or []:
            u, p = entry.get("username"), entry.get("password")
            if u and p:
                creds.append({
                    "source": "engine_loot",
                    "username": u,
                    "password": p,
                    "device_type": entry.get("device_type", ""),
                })

    access = creds_from_router_access(target_dir)
    if access:
        creds.append({
            "source": "router_access",
            "username": access[0],
            "password": access[1],
        })

    for name in ("hydra_success.txt", "hydra_web_success.txt", "credentials.txt"):
        text = _read_tail(os.path.join(target_dir, name), 2000)
        for m in re.finditer(r"\b(\w+):(\S+)", text):
            creds.append({"source": name, "username": m.group(1), "password": m.group(2)})

    for scan_name in ("routersploit_scan.txt", "LIVE_SCAN.log", "scan_transcript.txt"):
        text = _read_tail(os.path.join(target_dir, scan_name), 8000)
        for pat in (
            r"VALID NETIS LOGIN:\s*(\w+):(\S+)",
            r"CREDENTIALS:\s*(\w+):(\S+)",
            r"\[\$\$\$\]\s*VALID NETIS LOGIN:\s*(\w+):(\S+)",
        ):
            for m in re.finditer(pat, text, re.IGNORECASE):
                creds.append({
                    "source": "test_router",
                    "username": m.group(1),
                    "password": m.group(2),
                })

    seen: set[tuple[str, str]] = set()
    unique: list[dict[str, str]] = []
    for c in creds:
        key = (c.get("username", ""), c.get("password", ""))
        if key in seen or not key[0]:
            continue
        seen.add(key)
        unique.append(c)
    return unique[:20]


def _lan_clients(target_dir: str) -> list[dict[str, Any]]:
    data = _load_json(os.path.join(target_dir, "ROUTER_LAN_CLIENTS.json"))
    if isinstance(data, dict):
        return list(data.get("clients") or [])[:30]
    harvest = _load_json(os.path.join(target_dir, "ROUTER_HARVEST.json"))
    if isinstance(harvest, dict):
        return list(harvest.get("connected_clients") or [])[:30]
    return []


def _nuclei_summary(target_dir: str) -> dict[str, Any]:
    total = 0
    critical: list[str] = []
    for path in Path(target_dir).glob("nuclei*.jsonl"):
        try:
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                if not line.strip():
                    continue
                total += 1
                if len(critical) < 8:
                    try:
                        row = json.loads(line)
                        tid = row.get("template-id") or row.get("info", {}).get("name", "?")
                        sev = (row.get("info") or {}).get("severity", "")
                        if sev in ("critical", "high"):
                            critical.append(f"{tid} [{sev}]")
                    except json.JSONDecodeError:
                        pass
        except OSError:
            continue
    return {"total_findings": total, "top_critical_high": critical}


def _artifacts_present(target_dir: str) -> dict[str, bool]:
    checks = {
        "nmap_scan.txt": "has_nmap",
        "ROUTER_HARVEST.json": "router_harvest_done",
        "hikvision_test_report.json": "hikvision_test_done",
        "AI_SCAN_PLAN.json": "ai_scan_plan",
        "AI_ORCHESTRATOR_LOG.jsonl": "orchestrator_ran",
        "nuclei_port_80_notags.jsonl": "has_nuclei",
        "ingram_scan.txt": "has_ingram",
        "target_profile.json": "has_target_profile",
        "workflow_recommendations.json": "has_workflow",
    }
    out: dict[str, bool] = {}
    for fname, key in checks.items():
        out[key] = os.path.isfile(os.path.join(target_dir, fname))
    return out


def _device_guess(target_dir: str, ports: list[int], services_blob: str) -> dict[str, str]:
    profile = _load_json(os.path.join(target_dir, "target_profile.json"))
    if isinstance(profile, dict):
        return {
            "type": profile.get("target_type", "unknown"),
            "summary": profile.get("summary", ""),
            "confidence": profile.get("confidence", ""),
        }
    blob = services_blob.lower()
    if any(x in blob for x in ("hikvision", "hik-connect", "rtsp")) or 8000 in ports or 554 in ports:
        return {"type": "camera", "summary": "Likely IP camera / NVR", "confidence": "medium"}
    if any(x in blob for x in ("netis", "zyxel", "router", "virtual web")) or 80 in ports:
        return {"type": "router", "summary": "Likely router/gateway", "confidence": "medium"}
    return {"type": "unknown", "summary": "Unknown device class", "confidence": "low"}


def build_workspace_state(
    target_dir: str,
    ip: str,
    *,
    raw_target: str = "",
    executed_tools: list[str] | None = None,
) -> dict[str, Any]:
    """Compact JSON-safe state for LLM orchestration (no raw HTML dumps)."""
    hints = load_target_hints(target_dir) or {}
    auth = parse_target_auth(raw_target) or {}
    if not auth.get("username") and hints.get("auth_username"):
        auth = {
            "username": hints["auth_username"],
            "password": hints.get("auth_password", ""),
            "authenticated_url": hints.get("raw") or raw_target,
        }

    credentials = _collect_credentials(target_dir)
    if not auth.get("username"):
        for c in credentials:
            u, p = c.get("username"), c.get("password")
            if u and p and c.get("source") in (
                "router_access", "test_router", "router_harvest", "engine_loot",
            ):
                scheme = "http"
                auth = {
                    "username": u,
                    "password": p,
                    "authenticated_url": f"{scheme}://{u}:{p}@{ip}/",
                }
                break

    nmap = parse_nmap_summary(target_dir)
    ports = open_port_numbers(load_open_ports_from_workspace(target_dir)) or [
        p.get("port") for p in (nmap.get("ports") or []) if p.get("port")
    ]
    services_blob = " ".join(
        f"{p.get('service', '')} {p.get('product', '')}" for p in (nmap.get("ports") or [])
    )

    artifacts = _artifacts_present(target_dir)
    device = _device_guess(target_dir, ports, services_blob)
    harvest = _load_json(os.path.join(target_dir, "ROUTER_HARVEST.json")) or {}

    state: dict[str, Any] = {
        "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target_ip": ip,
        "raw_target": raw_target or hints.get("raw", ""),
        "open_ports": ports[:25],
        "services_summary": services_blob[:500],
        "device": device,
        "artifacts": artifacts,
        "has_nmap": artifacts.get("has_nmap", False),
        "credentials": credentials,
        "auth_password": auth.get("password"),
        "has_router_web_creds": bool(auth.get("username")),
        "lan_clients": _lan_clients(target_dir),
        "lan_gateway": harvest.get("lan_gateway"),
        "wireless": harvest.get("wireless"),
        "wan_status": harvest.get("wan_status"),
        "router_harvest_pages": harvest.get("pages_fetched", 0),
        "nuclei": _nuclei_summary(target_dir),
        "cve_notes": [
            f"{a.get('cve_id')} [{a.get('severity')}] {a.get('status')}"
            for a in (harvest.get("cve_assessments") or [])[:8]
        ],
        "auth_url": auth.get("authenticated_url") if auth.get("username") else None,
        "auth_username": auth.get("username"),
        "executed_tools": list(executed_tools or []),
        "allowed_next_tools": [
            k for k in ALLOWED_TOOLS if k not in (executed_tools or [])
        ],
    }

    try:
        from core.workflow_recommendations import build_tool_recommendations

        steps = build_tool_recommendations(target_dir, ip)[:6]
        state["recommended_tools"] = [
            {"name": s.gui_name, "reason": s.reason[:120]} for s in steps
        ]
    except Exception:
        state["recommended_tools"] = []

    orch = _load_json(os.path.join(target_dir, "AI_ORCHESTRATOR_STATE.json"))
    if isinstance(orch, dict):
        state["orchestrator_step"] = orch.get("step", 0)
        state["orchestrator_notes"] = orch.get("last_reason", "")

    return state


def save_workspace_state(target_dir: str, state: dict[str, Any]) -> str:
    path = os.path.join(target_dir, STATE_FILE)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2, ensure_ascii=False)
    return path


def append_orchestrator_log(target_dir: str, entry: dict[str, Any]) -> None:
    path = os.path.join(target_dir, ORCHESTRATOR_LOG)
    entry["ts"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def append_step_note(target_dir: str, step: int, note: str, *, provider: str = "") -> None:
    path = os.path.join(target_dir, STEP_NOTES)
    row = {
        "step": step,
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "provider": provider,
        "note": note[:2000],
    }
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")
