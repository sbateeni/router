"""Shared target workspace setup for CLI and PyQt6 GUI."""

from __future__ import annotations

import os
from typing import Any

from core.paths import project_root
from core.report.parsers import parse_target_input, save_target_hints, target_scan_host, target_workspace_name
from core.utils import reset_target_workspace


def prepare_target_workspace(
    raw_target: str,
    *,
    keep_artifacts: bool = False,
    base_dir: str | None = None,
) -> dict[str, Any]:
    """
    Resolve target, create targets/<workspace>/, optionally clear prior artifacts.

    Returns dict with keys: parsed, scan_host, workspace_name, target_dir, display.
    """
    base = base_dir or project_root()
    parsed = parse_target_input(raw_target.strip()) if raw_target.strip() else None
    scan_host = target_scan_host(parsed) if parsed else raw_target.strip()
    workspace_name = target_workspace_name(parsed, fallback=scan_host or "unknown")
    display = (parsed.get("raw") if parsed else None) or raw_target.strip()

    target_dir = os.path.join(base, "targets", workspace_name)
    os.makedirs(target_dir, exist_ok=True)
    try:
        os.chmod(target_dir, 0o755)
    except (PermissionError, OSError):
        pass

    if not keep_artifacts:
        reset_target_workspace(target_dir)

    if parsed and (
        parsed.get("login_path")
        or parsed.get("seed_url")
        or parsed.get("query_string")
    ):
        save_target_hints(
            target_dir,
            {
                "host": parsed.get("host"),
                "login_path": parsed.get("login_path"),
                "seed_url": parsed.get("seed_url"),
                "query_string": parsed.get("query_string"),
                "port": parsed.get("port"),
                "scheme": parsed.get("scheme"),
                "resolved_ip": parsed.get("resolved_ip"),
                "is_domain": parsed.get("is_domain"),
                "raw": parsed.get("raw"),
            },
        )

    return {
        "parsed": parsed,
        "scan_host": scan_host,
        "workspace_name": workspace_name,
        "target_dir": target_dir,
        "display": display,
    }
