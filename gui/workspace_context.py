"""Read target workspace artifacts for GUI tool chaining display."""

from __future__ import annotations

import json
import os
from typing import Any


CHAIN_FILES = (
    ("nmap_scan.txt", "Nmap port scan"),
    ("nmap_deep_scan.txt", "Nmap deep scan"),
    ("recon_summary.json", "Recon summary"),
    ("CONNECTIVITY.json", "Curl preflight"),
    ("MASSCAN_PORTS.json", "Masscan ports"),
    ("NMAP_OPEN_PORTS.json", "Open ports (JSON)"),
    ("target_profile.json", "Target profile / tool plan"),
    ("hydra_iot_passwords.txt", "Hydra IoT wordlist"),
    ("CHANGEME_HITS.json", "Default credentials"),
    ("nuclei_*.json", "Nuclei results"),
)


def _load_json(path: str) -> dict | list | None:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def summarize_workspace(target_dir: str) -> dict[str, Any]:
    """Build a short summary for the GUI context panel."""
    out: dict[str, Any] = {
        "target_dir": target_dir,
        "exists": bool(target_dir and os.path.isdir(target_dir)),
        "open_ports": [],
        "artifacts": [],
        "hints": [],
        "ready_for": [],
    }
    if not out["exists"]:
        out["hints"].append("Apply a target above — all tools use the same workspace folder.")
        return out

    names = set(os.listdir(target_dir))
    for pattern, label in CHAIN_FILES:
        if "*" in pattern:
            prefix = pattern.split("*", 1)[0]
            matched = sorted(n for n in names if n.startswith(prefix) and n.endswith(".json"))
            if matched:
                out["artifacts"].append({"file": matched[-1], "label": label})
            continue
        if pattern in names:
            out["artifacts"].append({"file": pattern, "label": label})

    summary_path = os.path.join(target_dir, "recon_summary.json")
    summary = _load_json(summary_path)
    if isinstance(summary, dict):
        for entry in summary.get("open_ports") or []:
            if isinstance(entry, dict) and entry.get("port"):
                p = entry["port"]
                if isinstance(p, int) and p > 0:
                    svc = entry.get("service", "")
                    out["open_ports"].append(f"{p}/{svc}".strip("/"))

    profile_path = os.path.join(target_dir, "target_profile.json")
    profile = _load_json(profile_path)
    if isinstance(profile, dict):
        plan = profile.get("tool_plan") or {}
        run_tools = [k for k, v in plan.items() if isinstance(v, dict) and v.get("run")]
        if run_tools:
            out["hints"].append(f"Profile suggests next: {', '.join(run_tools[:6])}")

    if out["open_ports"]:
        ports = out["open_ports"][:8]
        out["hints"].append(f"Open ports: {', '.join(ports)}")
        webish = any("80" in p or "443" in p or "8080" in p for p in ports)
        if webish:
            out["ready_for"].extend(["Nuclei", "Dirsearch", "Nikto", "Hydra"])
        out["ready_for"].extend(["RouterSploit", "Device Engine"])

    if any(a["file"] == "hydra_iot_passwords.txt" for a in out["artifacts"]):
        out["ready_for"].append("Hydra (IoT wordlist ready)")
    if not out["open_ports"] and not out["artifacts"]:
        out["hints"].append("No scan artifacts yet — run Nmap or Comprehensive scan first.")
    elif out["artifacts"] and not out["open_ports"]:
        out["hints"].append("Artifacts present — downstream tools will load them automatically.")

    out["ready_for"] = list(dict.fromkeys(out["ready_for"]))[:8]
    return out
