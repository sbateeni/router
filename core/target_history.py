"""Target session history — save/restore GUI and engine workspaces."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

from core.paths import project_root

HISTORY_INDEX = "sessions_index.json"
LEGACY_DB_DIR = "db"


def _history_path() -> str:
    root = project_root()
    db_dir = os.path.join(root, LEGACY_DB_DIR)
    os.makedirs(db_dir, exist_ok=True)
    return os.path.join(db_dir, HISTORY_INDEX)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _load_index() -> dict[str, Any]:
    path = _history_path()
    if not os.path.isfile(path):
        return {"version": 1, "sessions": []}
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and isinstance(data.get("sessions"), list):
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return {"version": 1, "sessions": []}


def _save_index(data: dict[str, Any]) -> None:
    path = _history_path()
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)


def _session_key(scan_host: str, workspace_name: str) -> str:
    return (workspace_name or scan_host or "").strip().lower()


def _artifact_count(target_dir: str) -> int:
    if not target_dir or not os.path.isdir(target_dir):
        return 0
    try:
        return sum(1 for n in os.listdir(target_dir) if os.path.isfile(os.path.join(target_dir, n)))
    except OSError:
        return 0


def _legacy_status(ip: str) -> str | None:
    path = os.path.join(project_root(), LEGACY_DB_DIR, f"{ip}.json")
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return str(data.get("status", "")) or None
    except (OSError, json.JSONDecodeError):
        return None


def record_session(
    *,
    target: str,
    scan_host: str,
    workspace_name: str,
    target_dir: str,
    profile: str = "normal",
    status: str | None = None,
    note: str = "",
) -> dict[str, Any]:
    """Upsert a history entry (called on Apply target and after scans)."""
    if not (scan_host or target or workspace_name):
        return {}

    key = _session_key(scan_host, workspace_name)
    legacy = _legacy_status(scan_host) if scan_host else None
    if status is None:
        status = legacy or ("PWNED" if legacy == "PWNED" else "ACTIVE")

    entry = {
        "key": key,
        "target": target.strip() or scan_host,
        "scan_host": scan_host,
        "workspace_name": workspace_name,
        "target_dir": target_dir,
        "profile": profile,
        "status": status,
        "last_seen": _now_iso(),
        "artifact_count": _artifact_count(target_dir),
        "note": note,
    }

    data = _load_index()
    sessions: list[dict] = data.setdefault("sessions", [])
    replaced = False
    for i, s in enumerate(sessions):
        if s.get("key") == key:
            entry["first_seen"] = s.get("first_seen") or entry["last_seen"]
            sessions[i] = {**s, **entry}
            replaced = True
            break
    if not replaced:
        entry["first_seen"] = entry["last_seen"]
        sessions.append(entry)

    sessions.sort(key=lambda x: x.get("last_seen", ""), reverse=True)
    _save_index(data)
    return entry


def mark_pwned(ip: str, service: str, credentials: str) -> None:
    """Sync engine save_success into history index."""
    root = project_root()
    target_dir = os.path.join(root, "targets", ip)
    record_session(
        target=ip,
        scan_host=ip,
        workspace_name=ip,
        target_dir=target_dir if os.path.isdir(target_dir) else os.path.join(root, "targets", ip),
        status="PWNED",
        note=f"{service}: {credentials}",
    )


def _discover_workspaces() -> list[dict[str, Any]]:
    """Include targets/ folders not yet in the index."""
    root = project_root()
    targets_root = os.path.join(root, "targets")
    found: list[dict[str, Any]] = []
    if not os.path.isdir(targets_root):
        return found
    for name in sorted(os.listdir(targets_root)):
        path = os.path.join(targets_root, name)
        if not os.path.isdir(path):
            continue
        found.append(
            {
                "key": _session_key(name, name),
                "target": name,
                "scan_host": name,
                "workspace_name": name,
                "target_dir": path,
                "profile": "?",
                "status": "WORKSPACE",
                "last_seen": "",
                "artifact_count": _artifact_count(path),
                "note": "discovered from targets/",
            }
        )
    return found


def list_sessions(*, merge_workspaces: bool = True) -> list[dict[str, Any]]:
    """All sessions for GUI / Telegram history."""
    data = _load_index()
    by_key: dict[str, dict] = {}

    for s in data.get("sessions") or []:
        key = s.get("key") or _session_key(s.get("scan_host", ""), s.get("workspace_name", ""))
        if key:
            s = dict(s)
            s["key"] = key
            s["artifact_count"] = _artifact_count(s.get("target_dir", ""))
            by_key[key] = s

    # Legacy db/*.json (per-IP engine DB)
    db_dir = os.path.join(project_root(), LEGACY_DB_DIR)
    if os.path.isdir(db_dir):
        for name in os.listdir(db_dir):
            if not name.endswith(".json") or name == HISTORY_INDEX:
                continue
            ip = name.replace(".json", "")
            key = _session_key(ip, ip)
            if key in by_key:
                st = _legacy_status(ip)
                if st:
                    by_key[key]["status"] = st
                continue
            try:
                with open(os.path.join(db_dir, name), encoding="utf-8") as fh:
                    legacy = json.load(fh)
            except (OSError, json.JSONDecodeError):
                legacy = {}
            target_dir = os.path.join(project_root(), "targets", ip)
            by_key[key] = {
                "key": key,
                "target": legacy.get("ip", ip),
                "scan_host": ip,
                "workspace_name": ip,
                "target_dir": target_dir,
                "profile": "?",
                "status": legacy.get("status", "LEGACY"),
                "last_seen": "",
                "artifact_count": _artifact_count(target_dir),
                "note": "legacy db entry",
            }

    if merge_workspaces:
        for ws in _discover_workspaces():
            key = ws["key"]
            if key in by_key:
                if not by_key[key].get("artifact_count"):
                    by_key[key]["artifact_count"] = ws["artifact_count"]
                if not os.path.isdir(by_key[key].get("target_dir", "")):
                    by_key[key]["target_dir"] = ws["target_dir"]
            else:
                by_key[key] = ws

    sessions = list(by_key.values())
    sessions.sort(
        key=lambda x: (x.get("last_seen") or "", x.get("target", "")),
        reverse=True,
    )
    return sessions


def get_session(key_or_host: str) -> dict[str, Any] | None:
    key = key_or_host.strip().lower()
    for s in list_sessions():
        if s.get("key") == key or s.get("scan_host") == key or s.get("target") == key:
            return s
    return None
