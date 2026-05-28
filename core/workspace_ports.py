"""Reuse Nmap results from target workspace — avoid re-scanning when artifacts exist."""

from __future__ import annotations

import json
import os

from core.scanner import parse_nmap


def load_open_ports_from_workspace(target_dir: str) -> list[dict]:
    """Load open ports from recon_summary.json or nmap_scan.txt if present."""
    if not target_dir or not os.path.isdir(target_dir):
        return []

    summary_path = os.path.join(target_dir, "recon_summary.json")
    if os.path.isfile(summary_path):
        try:
            with open(summary_path, encoding="utf-8") as fh:
                data = json.load(fh)
            ports = data.get("open_ports") or []
            if ports:
                return ports
        except (OSError, json.JSONDecodeError):
            pass

    for name in ("nmap_scan.txt", "nmap_deep_scan.txt"):
        log_path = os.path.join(target_dir, name)
        if not os.path.isfile(log_path):
            continue
        try:
            with open(log_path, encoding="utf-8", errors="replace") as fh:
                parsed = parse_nmap(fh.read())
            if parsed:
                return parsed
        except OSError:
            pass
    return []


def open_port_numbers(open_ports: list[dict]) -> list[int]:
    nums: list[int] = []
    for entry in open_ports or []:
        if not isinstance(entry, dict):
            continue
        pn = entry.get("port")
        if isinstance(pn, int) and pn > 0 and pn not in nums:
            nums.append(pn)
    return nums


def prefer_hikvision_http_ports(open_ports: list[dict] | None) -> list[int]:
    """8000 (hik-connect) before 80 when both open; deprioritize non-Hik HTTP frontends."""
    if not open_ports:
        return [8000, 80]

    nums = open_port_numbers(open_ports)
    scored: list[tuple[int, int]] = []
    for entry in open_ports:
        if not isinstance(entry, dict):
            continue
        pn = entry.get("port")
        if not isinstance(pn, int) or pn <= 0:
            continue
        svc = f"{entry.get('service', '')} {entry.get('product', '')}".lower()
        score = 0
        if pn == 8000:
            score += 30
        if any(x in svc for x in ("hikvision", "hik-connect", "hik")):
            score += 40
        if pn == 80:
            score += 10
        if any(x in svc for x in ("zyxel", "virtual web", "apache", "router")):
            score -= 25
        scored.append((score, pn))

    if scored:
        ordered: list[int] = []
        for _, pn in sorted(scored, key=lambda x: (-x[0], x[1])):
            if pn not in ordered:
                ordered.append(pn)
        return ordered

    if 8000 in nums and 80 in nums:
        return [8000, 80] + [p for p in nums if p not in (8000, 80)]
    return prefer_web_ports(open_ports, camera_first=True)


def prefer_web_ports(open_ports: list[dict], *, camera_first: bool = False) -> list[int]:
    """Order ports for web/camera tools (80, 8000, 554 RTSP skipped for HTTP)."""
    nums = open_port_numbers(open_ports)
    if not nums:
        return [80]

    order = (
        [8000, 80, 443, 8080, 8443, 81, 8001, 8081, 9000, 37777]
        if camera_first
        else [80, 8000, 443, 8080, 8443, 81, 8001, 8081, 9000, 37777]
    )
    ordered: list[int] = []
    for p in order:
        if p in nums:
            ordered.append(p)
    for p in nums:
        if p not in ordered and p not in (554, 22, 23):
            ordered.append(p)
    return ordered
