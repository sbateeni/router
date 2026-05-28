"""
Post-tool workflow hints — after ANY scan/tool finishes, suggest next GUI tools.

Used by GUI ScanWorker, CLI runner, and Hikvision test workflow.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from core.report.enrichment import build_scan_enrichment
from core.report.parsers import count_nuclei_findings, parse_nmap_summary, significant_nuclei_findings
from core.workspace_ports import load_open_ports_from_workspace, open_port_numbers, prefer_web_ports

# selection id → (GUI sidebar label, navigation path)
TOOL_BY_SELECTION: dict[int, tuple[str, str]] = {
    1: ("Comprehensive Scan", "Dashboard → Comprehensive Scan"),
    2: ("Nmap", "Master PWN — Classic → Nmap"),
    3: ("Nuclei", "Master PWN — Classic → Nuclei"),
    4: ("Dirsearch", "Master PWN — Classic → Dirsearch"),
    5: ("SQLMap", "Master PWN — Classic → SQLMap"),
    6: ("RouterSploit", "Master PWN — Classic → RouterSploit"),
    7: ("Ingram", "Master PWN — Classic → Ingram"),
    8: ("Hydra", "Master PWN — Classic → Hydra"),
    9: ("FFUF", "Master PWN — Classic → FFUF"),
    10: ("GAU", "Master PWN — Classic → GAU"),
    11: ("AI Scan Plan", "Master PWN — AI → AI Scan Plan"),
    12: ("AI Hydra Plan", "Master PWN — AI → AI Hydra Plan"),
    13: ("AI RouterSploit", "Master PWN — AI → AI RouterSploit"),
    14: ("AI Final Report", "Master PWN — AI → AI Final Report"),
    16: ("LAN Discovery", "Master PWN — Recon → LAN Discovery"),
    17: ("Nikto", "Master PWN — Recon → Nikto"),
    18: ("WhatWeb", "Master PWN — Recon → WhatWeb"),
    19: ("Nmap Vuln Scripts", "Master PWN — Recon → Nmap Vuln Scripts"),
    21: ("AUTO-PWN Target", "Device Engine → AUTO-PWN Target"),
}

UTIL_LABELS: dict[str, tuple[str, str]] = {
    "router-harvest": ("Router Deep Harvest", "Utilities → Router Deep Harvest"),
    "test-hikvision": ("Test Hikvision", "Utilities → Test Hikvision"),
    "test-router": ("Test Router", "Utilities → Test Router"),
    "test-cve": ("CVE Report", "Utilities → CVE Report"),
    "direct-camera": ("Direct Camera", "Utilities → Direct Camera"),
    "osint": ("Social OSINT", "Device Engine → Social OSINT"),
    "decepticon": ("Decepticon", "Device Engine → Decepticon"),
    "poc-scraper": ("PoC Scraper", "Device Engine → PoC Scraper"),
    "update": ("Framework Update", "Device Engine → Framework Update"),
    "update-tools": ("Update Tools", "Utilities → Update Tools"),
}

HIKVISION_MARKERS = ("hikvision", "hik-connect", "dahua", "ipcam", "rtsp", "onvif")
ROUTER_MARKERS = ("router", "gateway", "modem", "netis", "tplink", "zyxel", "fiberhome", "mikrotik")


@dataclass
class ToolRecommendation:
    priority: int
    gui_name: str
    nav_hint: str
    reason: str


@dataclass
class WorkspaceProfile:
    ip: str = ""
    open_ports: list[int] = field(default_factory=list)
    web_ports: list[int] = field(default_factory=list)
    services_blob: str = ""
    is_hikvision: bool = False
    is_router_like: bool = False
    has_nmap: bool = False
    nuclei_critical: int = 0
    nuclei_total: int = 0
    dirsearch_hits: int = 0
    ffuf_paths: int = 0
    connectivity_issues: bool = False
    hikvision_creds: bool = False
    hikvision_backdoor: bool = False
    snapshots: bool = False
    hydra_hits: bool = False
    target_class: str = "unknown"
    router_auth_url: bool = False
    router_harvest_done: bool = False


def _tool_ref(gui_name: str, nav_hint: str) -> tuple[str, str]:
    return gui_name, nav_hint


def _load_workspace_profile(target_dir: str, ip: str) -> WorkspaceProfile:
    prof = WorkspaceProfile(ip=ip or "")
    if not target_dir or not os.path.isdir(target_dir):
        return prof

    nmap = parse_nmap_summary(target_dir)
    prof.has_nmap = bool(nmap.get("ports"))
    cached = load_open_ports_from_workspace(target_dir)
    prof.open_ports = open_port_numbers(cached) or [p.get("port") for p in nmap.get("ports", []) if p.get("port")]
    prof.services_blob = " ".join(
        f"{p.get('service', '')} {p.get('product', '')}" for p in (nmap.get("ports") or [])
    ).lower()
    if not prof.services_blob and cached:
        prof.services_blob = " ".join(str(p.get("service", "")) for p in cached).lower()

    prof.web_ports = prefer_web_ports(cached or nmap.get("ports") or [], camera_first=False)
    prof.is_hikvision = any(m in prof.services_blob for m in HIKVISION_MARKERS) or 8000 in prof.open_ports or 554 in prof.open_ports
    prof.is_router_like = any(m in prof.services_blob for m in ROUTER_MARKERS) or (
        80 in prof.open_ports and not prof.is_hikvision
    )

    findings = count_nuclei_findings(target_dir)
    prof.nuclei_total = len(findings)
    prof.nuclei_critical = len(significant_nuclei_findings(findings))

    enrich = build_scan_enrichment(target_dir, ip=ip)
    prof.dirsearch_hits = len(enrich.get("dirsearch_interesting") or [])
    prof.ffuf_paths = enrich.get("ffuf_paths") or 0
    prof.connectivity_issues = bool(enrich.get("connectivity_issues"))
    prof.target_class = enrich.get("target_class") or "unknown"

    hik_report = os.path.join(target_dir, "hikvision_test_report.json")
    if os.path.isfile(hik_report):
        try:
            with open(hik_report, encoding="utf-8") as fh:
                hr = json.load(fh)
            prof.hikvision_creds = bool(hr.get("digest_valid") or hr.get("digest_password"))
            prof.hikvision_backdoor = bool(hr.get("backdoor_confirmed"))
            prof.snapshots = bool(hr.get("snapshots"))
        except (OSError, json.JSONDecodeError):
            pass

    snap_dir = os.path.join(target_dir, "snapshots")
    if os.path.isdir(snap_dir) and any(f.lower().endswith(".jpg") for f in os.listdir(snap_dir)):
        prof.snapshots = True

    hints_path = os.path.join(target_dir, "target_hints.json")
    if os.path.isfile(hints_path):
        try:
            with open(hints_path, encoding="utf-8") as fh:
                hints = json.load(fh)
            prof.router_auth_url = bool(hints.get("authenticated") or hints.get("auth_username"))
        except (OSError, json.JSONDecodeError):
            pass
    prof.router_harvest_done = os.path.isfile(os.path.join(target_dir, "ROUTER_HARVEST.json"))

    for name in ("hydra_success.txt", "hydra_web_success.txt", "credentials.txt", "loot_summary.txt"):
        if os.path.isfile(os.path.join(target_dir, name)):
            prof.hydra_hits = True
            break
    hydra_out = os.path.join(target_dir, "hydra_stdout.txt")
    if os.path.isfile(hydra_out):
        text = open(hydra_out, encoding="utf-8", errors="ignore").read(8000).lower()
        if "login:" in text or "host:" in text and "password" in text:
            prof.hydra_hits = True

    return prof


def _finished_label(finished_tool: str | int | None) -> str:
    if finished_tool is None:
        return ""
    if isinstance(finished_tool, int):
        ref = TOOL_BY_SELECTION.get(finished_tool)
        return ref[0] if ref else f"tool-{finished_tool}"
    return str(finished_tool).strip().lower()


def _add(
    steps: list[ToolRecommendation],
    seen: set[str],
    gui_name: str,
    nav_hint: str,
    reason: str,
    *,
    skip_if_finished: str = "",
    finished_name: str = "",
) -> None:
    if gui_name in seen:
        return
    if skip_if_finished and finished_name and gui_name.lower() == skip_if_finished.lower():
        return
    seen.add(gui_name)
    steps.append(
        ToolRecommendation(len(seen), gui_name, nav_hint, reason),
    )


def build_tool_recommendations(
    target_dir: str,
    ip: str,
    *,
    finished_tool: str | int | None = None,
    job_kind: str = "",
    exploited: bool = False,
) -> list[ToolRecommendation]:
    """Build ordered next-tool list from workspace artifacts + tool that just ran."""
    prof = _load_workspace_profile(target_dir, ip)
    steps: list[ToolRecommendation] = []
    seen: set[str] = set()

    fin_key = finished_tool if isinstance(finished_tool, int) else None
    fin_label = _finished_label(finished_tool)
    fin_gui = TOOL_BY_SELECTION.get(fin_key, (fin_label, ""))[0] if fin_key else fin_label

    # --- Always useful when workspace is empty ---
    if not prof.has_nmap and not prof.open_ports and not prof.router_harvest_done:
        _add(
            steps, seen, "Nmap", "Master PWN — Classic → Nmap",
            "No port scan in workspace yet — run Nmap first.",
            skip_if_finished=fin_gui, finished_name=fin_gui,
        )
        return _dedupe_priority(steps)

    if prof.router_harvest_done and not prof.has_nmap:
        _add(
            steps, seen, "Nuclei", "Master PWN — Classic → Nuclei",
            "Router harvested — run CVE templates on HTTP port.",
            skip_if_finished=fin_gui, finished_name=fin_gui,
        )
        _add(
            steps, seen, "RouterSploit", "Master PWN — Classic → RouterSploit",
            "Match exploit modules to harvested device type.",
            skip_if_finished=fin_gui, finished_name=fin_gui,
        )

    if prof.connectivity_issues:
        _add(
            steps, seen, "Nmap", "Master PWN — Classic → Nmap",
            "Target had connectivity/timeouts — confirm host is still up.",
        )

    # --- Hikvision / camera path ---
    if prof.is_hikvision or prof.hikvision_creds or prof.hikvision_backdoor:
        if not prof.hikvision_creds and not prof.hikvision_backdoor:
            _add(
                steps, seen, "Test Hikvision", "Utilities → Test Hikvision",
                "Camera ports/services detected — test CVE-2017-7921 and Digest login.",
                skip_if_finished=fin_gui, finished_name=fin_gui,
            )
        if prof.hikvision_backdoor or prof.hikvision_creds:
            _add(
                steps, seen, "AUTO-PWN Target", "Device Engine → AUTO-PWN Target",
                "Hikvision access confirmed — full device engine (config, creds, PoCs).",
            )
            if not prof.snapshots:
                _add(
                    steps, seen, "Direct Camera", "Utilities → Direct Camera",
                    "Capture snapshots / RTSP (VLC) on this target.",
                )
        if prof.is_hikvision or prof.hikvision_creds:
            _add(
                steps, seen, "Nuclei", "Master PWN — Classic → Nuclei",
                "Run Hikvision CVE templates on open HTTP port(s).",
                skip_if_finished=fin_gui, finished_name=fin_gui,
            )
            _add(
                steps, seen, "Ingram", "Master PWN — Classic → Ingram",
                "IP camera vulnerability scanner.",
                skip_if_finished=fin_gui, finished_name=fin_gui,
            )

    # --- Router path ---
    if prof.router_auth_url and not prof.router_harvest_done:
        _add(
            steps, seen, "Router Deep Harvest", "Utilities → Router Deep Harvest",
            "Target URL includes login — crawl admin pages for clients, Wi‑Fi, CVEs.",
            skip_if_finished=fin_gui, finished_name=fin_gui,
        )
    if prof.is_router_like and not prof.is_hikvision:
        _add(
            steps, seen, "Test Router", "Utilities → Test Router",
            "Router/gateway detected — test default creds and known router bugs.",
            skip_if_finished=fin_gui, finished_name=fin_gui,
        )
        _add(
            steps, seen, "RouterSploit", "Master PWN — Classic → RouterSploit",
            "Router/IoT exploit modules for this vendor.",
            skip_if_finished=fin_gui, finished_name=fin_gui,
        )

    # --- Per finished tool: logical next step ---
    if fin_key == 2 or fin_label == "nmap":
        if prof.web_ports:
            _add(steps, seen, "Nuclei", "Master PWN — Classic → Nuclei", f"Web ports open: {prof.web_ports[:5]}")
            _add(steps, seen, "Dirsearch", "Master PWN — Classic → Dirsearch", "Enumerate paths on HTTP service.")
            _add(steps, seen, "WhatWeb", "Master PWN — Recon → WhatWeb", "Fingerprint web stack before deep exploits.")
        if prof.is_hikvision:
            _add(steps, seen, "Test Hikvision", "Utilities → Test Hikvision", "hik-connect / RTSP — verify camera CVEs.")
        if 22 in prof.open_ports or 23 in prof.open_ports or 21 in prof.open_ports:
            _add(steps, seen, "Hydra", "Master PWN — Classic → Hydra", "Login services detected on Nmap.")

    elif fin_key in (3, 17, 19) or fin_label in ("nuclei", "nikto", "nmap vuln scripts"):
        if prof.nuclei_critical:
            _add(
                steps, seen, "SQLMap", "Master PWN — Classic → SQLMap",
                f"{prof.nuclei_critical} significant Nuclei finding(s) — test injection on URLs.",
            )
        if prof.is_hikvision:
            _add(steps, seen, "AUTO-PWN Target", "Device Engine → AUTO-PWN Target", "Exploit chain for confirmed camera CVEs.")
        elif prof.is_router_like:
            _add(steps, seen, "RouterSploit", "Master PWN — Classic → RouterSploit", "Follow up web vulns with router modules.")

    elif fin_key == 4 or fin_label == "dirsearch":
        if prof.dirsearch_hits:
            _add(
                steps, seen, "SQLMap", "Master PWN — Classic → SQLMap",
                f"{prof.dirsearch_hits} interesting path(s) — test parameters.",
            )
        _add(steps, seen, "Nuclei", "Master PWN — Classic → Nuclei", "Template scan on discovered base URL.")

    elif fin_key in (9, 10) or fin_label in ("ffuf", "gau"):
        _add(steps, seen, "Nuclei", "Master PWN — Classic → Nuclei", "Scan fuzzed/discovered URLs.")
        if prof.ffuf_paths or prof.dirsearch_hits:
            _add(steps, seen, "SQLMap", "Master PWN — Classic → SQLMap", "Test interesting paths for SQLi.")

    elif fin_key == 8 or fin_label == "hydra":
        if prof.hydra_hits:
            _add(steps, seen, "Nuclei", "Master PWN — Classic → Nuclei", "Credentials found — re-scan with authenticated templates.")
            _add(steps, seen, "AUTO-PWN Target", "Device Engine → AUTO-PWN Target", "Use recovered creds in full engine.")
        else:
            _add(steps, seen, "Test Router", "Utilities → Test Router", "Hydra inconclusive — try vendor-specific router tests.")

    elif fin_key == 7 or fin_label == "ingram":
        _add(steps, seen, "Test Hikvision", "Utilities → Test Hikvision", "Validate Ingram hits with Digest/backdoor tests.")
        _add(steps, seen, "Direct Camera", "Utilities → Direct Camera", "View streams if creds work.")

    elif fin_key == 6 or fin_label == "routersploit":
        _add(steps, seen, "Hydra", "Master PWN — Classic → Hydra", "Brute remaining login services.")
        _add(steps, seen, "Nuclei", "Master PWN — Classic → Nuclei", "Cover web CVEs RouterSploit may have missed.")

    elif fin_key == 5 or fin_label == "sqlmap":
        _add(steps, seen, "AI Final Report", "Master PWN — AI → AI Final Report", "Summarize workspace after SQLMap phase.")

    elif fin_key == 18 or fin_label == "whatweb":
        _add(steps, seen, "Nuclei", "Master PWN — Classic → Nuclei", "Run CVE templates matching fingerprint.")
        _add(steps, seen, "Dirsearch", "Master PWN — Classic → Dirsearch", "Enumerate admin/config paths.")

    elif fin_key == 1 or job_kind == "comprehensive" or str(fin_label).startswith("comprehensive"):
        _add(
            steps, seen, "AI Final Report", "Master PWN — AI → AI Final Report",
            "Full scan done — generate consolidated report.",
        )

    elif job_kind == "engine" or fin_key == 21 or fin_label in ("device-engine", "engine"):
        _add(
            steps, seen, "AI Final Report", "Master PWN — AI → AI Final Report",
            "Review engine loot under targets/ then generate AI report.",
        )
        if prof.snapshots:
            _add(steps, seen, "Direct Camera", "Utilities → Direct Camera", "Open RTSP playlist in VLC.")

    elif fin_label in ("test-hikvision", "test hikvision"):
        pass  # Hikvision test already prints detailed steps; general rules above still apply

    elif fin_label in ("test-router", "test router"):
        _add(steps, seen, "CVE Report", "Utilities → CVE Report", "CVE map for router vendor/firmware.")
        _add(steps, seen, "Nuclei", "Master PWN — Classic → Nuclei", "Router CVE templates.")

    # --- Generic gaps (don't recommend tool user just ran) ---
    if prof.nuclei_critical and fin_key != 5:
        _add(
            steps, seen, "SQLMap", "Master PWN — Classic → SQLMap",
            "High/critical Nuclei hits present in workspace.",
            skip_if_finished=fin_gui, finished_name=fin_gui,
        )

    if prof.web_ports and prof.nuclei_total == 0 and fin_key != 3:
        _add(
            steps, seen, "Nuclei", "Master PWN — Classic → Nuclei",
            "No Nuclei results in workspace yet.",
            skip_if_finished=fin_gui, finished_name=fin_gui,
        )

    if prof.web_ports and prof.dirsearch_hits == 0 and fin_key != 4:
        _add(
            steps, seen, "Dirsearch", "Master PWN — Classic → Dirsearch",
            "Web port open but few enumerated paths.",
            skip_if_finished=fin_gui, finished_name=fin_gui,
        )

    if prof.open_ports and not prof.hydra_hits and fin_key != 8:
        login_ports = [p for p in prof.open_ports if p in (22, 23, 21, 80, 443, 8080, 8443)]
        if login_ports:
            _add(
                steps, seen, "Hydra", "Master PWN — Classic → Hydra",
                f"Try default creds on ports {login_ports[:4]}.",
                skip_if_finished=fin_gui, finished_name=fin_gui,
            )

    if exploited:
        _add(
            steps, seen, "AI Final Report", "Master PWN — AI → AI Final Report",
            "Exploitation signal detected — document in final report.",
        )

    _add(
        steps, seen, "CVE Report", "Utilities → CVE Report",
        "Firmware/vendor CVE summary for this target.",
        skip_if_finished=fin_gui, finished_name=fin_gui,
    )

    if not steps:
        _add(
            steps, seen, "Comprehensive Scan", "Dashboard → Comprehensive Scan",
            "Run phased scan or review Artifacts / RESULTS_SUMMARY.txt.",
        )

    return _dedupe_priority(steps)


def _dedupe_priority(steps: list[ToolRecommendation]) -> list[ToolRecommendation]:
    out: list[ToolRecommendation] = []
    seen: set[str] = set()
    for s in steps:
        if s.gui_name in seen:
            continue
        seen.add(s.gui_name)
        out.append(s)
    for i, s in enumerate(out[:10], start=1):
        s.priority = i
    return out[:10]


def merge_recommendations(
    primary: list[ToolRecommendation],
    extra: list[ToolRecommendation],
    *,
    max_items: int = 10,
) -> list[ToolRecommendation]:
    seen = {s.gui_name for s in primary}
    merged = list(primary)
    for s in extra:
        if s.gui_name in seen:
            continue
        seen.add(s.gui_name)
        merged.append(s)
    for i, s in enumerate(merged[:max_items], start=1):
        s.priority = i
    return merged[:max_items]


def print_workflow_recommendations(
    steps: list[ToolRecommendation],
    *,
    finished_tool: str | int | None = None,
) -> None:
    fin = _finished_label(finished_tool)
    header = "NEXT TOOLS — اذهب للأداة التالية في الواجهة"
    if fin:
        header += f" (بعد: {fin})"

    print("\n" + "=" * 70)
    print(f"  {header}")
    print("=" * 70)
    if not steps:
        print("  (لا توجد توصيات — راجع Artifacts في workspace)")
        print("=" * 70 + "\n")
        return
    for s in steps:
        print(f"\n  [{s.priority}] {s.gui_name}")
        print(f"      المسار: {s.nav_hint}")
        print(f"      السبب: {s.reason}")
    print("\n" + "=" * 70 + "\n")


def save_workflow_recommendations(
    target_dir: str,
    payload: dict[str, Any],
) -> str:
    os.makedirs(target_dir, exist_ok=True)
    path = os.path.join(target_dir, "workflow_recommendations.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    return path


def emit_post_tool_recommendations(
    target_dir: str,
    ip: str,
    *,
    finished_tool: str | int | None = None,
    job_kind: str = "",
    exploited: bool = False,
    extra_steps: list[ToolRecommendation] | None = None,
    quiet: bool = False,
) -> list[ToolRecommendation]:
    """
    Analyze workspace and print/save next-tool hints.
    Returns the recommendation list (for tests / GUI).
    """
    if os.environ.get("AUTOPWN_SKIP_RECOMMENDATIONS") == "1":
        return []

    steps = build_tool_recommendations(
        target_dir,
        ip,
        finished_tool=finished_tool,
        job_kind=job_kind,
        exploited=exploited,
    )

    # Hikvision test may have written specialized steps — prefer those first
    hik_path = os.path.join(target_dir, "hikvision_test_report.json")
    if os.path.isfile(hik_path) and _finished_label(finished_tool) in ("test-hikvision", "test hikvision"):
        try:
            with open(hik_path, encoding="utf-8") as fh:
                hr = json.load(fh)
            hik_steps = [
                ToolRecommendation(
                    i + 1,
                    row.get("gui_name", ""),
                    row.get("nav_hint", ""),
                    row.get("reason", ""),
                )
                for i, row in enumerate(hr.get("next_tools") or [])
                if row.get("gui_name")
            ]
            if hik_steps:
                steps = merge_recommendations(hik_steps, steps)
        except (OSError, json.JSONDecodeError):
            pass

    if extra_steps:
        steps = merge_recommendations(extra_steps, steps)

    if not quiet:
        print_workflow_recommendations(steps, finished_tool=finished_tool)

    payload = {
        "host": ip,
        "finished_tool": finished_tool,
        "job_kind": job_kind,
        "exploited": exploited,
        "next_tools": [asdict(s) for s in steps],
    }
    path = save_workflow_recommendations(target_dir, payload)
    if not quiet:
        print(f"[*] Workflow hints saved: {path}")

    return steps
