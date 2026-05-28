"""Route menu selections to classic, AI, or recon runners — no cross-mixing."""

from core.ai.individual import run_ai_hydra_plan_only, run_ai_report_only, run_ai_scan_plan_only
from core.ai.routersploit import run_routersploit_with_ai_followup
from core.classic.full_scan import run_all_classic_tools
from core.classic.individual import (
    run_dirsearch_only,
    run_ffuf_only,
    run_gau_only,
    run_hydra_only,
    run_ingram_only,
    run_nmap_only,
    run_nuclei_only,
    run_routersploit_only,
    run_sqlmap_only,
)
from core.menu import AI_CHOICES, CLASSIC_CHOICES, ENGINE_CHOICES, RECON_CHOICES, select_tool_menu
from core.recon.runner import (
    run_lan_discovery_only,
    run_nikto_tool,
    run_nmap_vuln_tool,
    run_whatweb_tool,
)
from core.scan_config import set_scan_profile


def run_device_engine_only(ip, target_dir, manual_mode=False):
    """Full device AUTO-PWN engine (cameras, routers, OSINT, PoCs)."""
    import json
    import os

    from engines.auto_pwn_main import main as engine_main

    target = ip if str(ip).startswith("http") else f"http://{ip}"
    hints_path = os.path.join(target_dir, "target_hints.json")
    if os.path.isfile(hints_path):
        try:
            with open(hints_path, encoding="utf-8") as fh:
                hints = json.load(fh)
            if hints.get("seed_url"):
                target = hints["seed_url"]
            elif hints.get("raw") and str(hints["raw"]).startswith("http"):
                target = hints["raw"]
        except Exception:
            pass
    engine_main(target, manual_mode=manual_mode)
    return True


def run_selected_tool(selection, ip, target_dir, profile="normal", subnet=None):
    import os

    from core.scan_cancel import ScanCancelled, check_cancelled

    set_scan_profile(profile)
    source = os.environ.get("AUTOPWN_SCAN_SOURCE", "cli")
    os.environ["AUTOPWN_SCAN_SOURCE"] = source

    check_cancelled()

    from core.live_scan_log import begin as live_begin, end as live_end, mirror_stdout
    from core.phase_log import reset_phase_windows
    from core.scan_transcript import begin as transcript_begin, end as transcript_end

    reset_phase_windows()
    live_begin(f"{ip} | selection={selection} | profile={profile}", source=source)
    if selection != 1:
        transcript_begin(
            target_dir,
            header=f"Selection: {selection} | profile: {profile}",
            live_source=source,
        )
    exploited = False
    try:
        with mirror_stdout():
            check_cancelled()
            if selection in ENGINE_CHOICES:
                exploited = bool(run_device_engine_only(ip, target_dir))
            elif selection in CLASSIC_CHOICES:
                exploited = bool(_run_classic(selection, ip, target_dir))
            elif selection in AI_CHOICES:
                exploited = bool(_run_ai(selection, ip, target_dir))
            elif selection in RECON_CHOICES:
                exploited = bool(_run_recon(selection, ip, target_dir, subnet=subnet))
            else:
                print(f"[-] Unknown selection: {selection}")
                exploited = False
    except ScanCancelled:
        print("[!] Scan cancelled by user")
        raise
    finally:
        if selection != 1:
            transcript_end()
        live_end()
        if os.environ.get("AUTOPWN_GUI") != "1":
            try:
                from core.workflow_recommendations import emit_post_tool_recommendations

                emit_post_tool_recommendations(
                    target_dir,
                    ip,
                    finished_tool=selection,
                    job_kind="tool",
                    exploited=exploited,
                )
            except Exception as exc:
                print(f"[!] Workflow recommendations skipped: {exc}")
    return exploited


def _run_classic(selection, ip, target_dir):
    if selection == 1:
        return run_all_classic_tools(ip, target_dir, selection=selection)
    if selection == 2:
        return run_nmap_only(ip, target_dir)
    if selection == 3:
        return run_nuclei_only(ip, target_dir)
    if selection == 4:
        return run_dirsearch_only(ip, target_dir)
    if selection == 5:
        return run_sqlmap_only(ip, target_dir)
    if selection == 6:
        return run_routersploit_only(ip, target_dir)
    if selection == 7:
        return run_ingram_only(ip, target_dir)
    if selection == 8:
        return run_hydra_only(ip, target_dir)
    if selection == 9:
        return run_ffuf_only(ip, target_dir)
    if selection == 10:
        return run_gau_only(ip, target_dir)
    return False


def _run_ai(selection, ip, target_dir):
    if selection == 11:
        return run_ai_scan_plan_only(ip, target_dir)
    if selection == 12:
        return run_ai_hydra_plan_only(ip, target_dir)
    if selection == 13:
        return run_routersploit_with_ai_followup(ip, target_dir)
    if selection == 14:
        run_ai_report_only(ip, target_dir)
        return False
    return False


def _run_recon(selection, ip, target_dir, subnet=None):
    if selection == 16:
        return run_lan_discovery_only(target_dir, subnet=subnet)
    if selection == 17:
        return run_nikto_tool(ip, target_dir)
    if selection == 18:
        return run_whatweb_tool(ip, target_dir)
    if selection == 19:
        return run_nmap_vuln_tool(ip, target_dir)
    return False


__all__ = [
    "run_device_engine_only",
    "run_lan_discovery_only",
    "run_selected_tool",
    "select_tool_menu",
]
