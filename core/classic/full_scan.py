import os
import re
import time

from core.bruteforce import run_hydra, run_web_hydra
from core.classic.context import (
    ScanContext,
    apply_target_hints,
    get_login_ports,
    get_web_ports,
)
from core.classic.helpers import (
    handle_keyboard_interrupt,
    refresh_report,
)
from core.report.parsers import hydra_form_for_path, load_target_hints
from core.scan_config import get_profile_name, get_scan_profile
from core.scanner import run_nmap
from core.recon.target_profile import (
    build_target_profile,
    get_tool_config,
    print_target_profile,
    save_target_profile,
    should_run_tool,
)


def _phase_delay():
    try:
        from core.scan_cancel import check_cancelled
        check_cancelled()
    except Exception:
        pass
    time.sleep(get_scan_profile().get("phase_delay_seconds", 5))


def _merge_profile_into_context(profile, context):
    """Feed artifact summary back into scan context (deep scan chaining)."""
    for url in profile.get("priority_urls") or []:
        if url and url not in context.discovered_urls:
            context.discovered_urls.append(url)
        if url and url not in context.discovered_paths:
            context.discovered_paths.append(url)
    for path in profile.get("login_paths") or []:
        if path and path not in context.login_paths:
            context.login_paths.append(path)
    for port in profile.get("web_ports") or []:
        try:
            p = int(port)
            if p not in context.web_ports:
                context.web_ports.append(p)
        except (TypeError, ValueError):
            pass


def _sync_profile(ip, target_dir, context, phase_label, deep=False):
    """Rebuild profile from all artifacts so far and persist routing plan."""
    from core.scan_transcript import event as transcript_event

    profile = build_target_profile(ip, target_dir, context=context)
    save_target_profile(target_dir, profile)
    if deep:
        _merge_profile_into_context(profile, context)
    msg = f"[*] Target profile updated ({phase_label}) → {os.path.join(target_dir, 'target_profile.json')}"
    print(f"\n{msg}")
    transcript_event(msg)
    lines = [
        f"  Type: {profile.get('target_type')} ({profile.get('confidence')}) — {profile.get('summary')}",
    ]
    if profile.get("login_paths"):
        lines.append(f"  Login paths: {', '.join(profile['login_paths'][:5])}")
    for name, cfg in (profile.get("tool_plan") or {}).items():
        flag = "RUN" if cfg.get("run") else "SKIP"
        lines.append(f"  [{flag}] {name}")
    transcript_event("\n".join(lines))
    print_target_profile(profile)
    return profile


def _is_deep_scan():
    return get_profile_name() == "deep"


def run_all_classic_tools(ip, target_dir, selection=1):
    """Full classic scan — tools chosen from live target profile after each phase."""
    from core.scan_transcript import begin as transcript_begin, end as transcript_end, event as transcript_event, phase as transcript_phase
    from core.telegram.phase_notify import notify_phase_complete

    def _phase_done(phase_id, title, profile_obj=None, skipped=False, skip_reason=""):
        try:
            notify_phase_complete(
                phase_id, title, ip, target_dir,
                profile=profile_obj or profile,
                context=context,
                skipped=skipped,
                skip_reason=skip_reason,
            )
        except Exception as exc:
            print(f"[!] Telegram phase notify failed: {exc}")

    context = ScanContext()
    profile = {}
    hints = load_target_hints(target_dir)
    hint_line = hints.get("raw") or hints.get("seed_url") or ip
    deep = _is_deep_scan()
    live_src = "telegram" if os.environ.get("AUTOPWN_SCAN_SOURCE") == "telegram" else "cli"
    transcript_begin(
        target_dir,
        header=f"Target: {hint_line} | profile: {get_profile_name()}"
        + (" | FULL TOOL MERGE" if deep else ""),
        live_source=live_src,
    )

    if hints:
        apply_target_hints(context, hints)
        print(f"[*] Target hints: {hints.get('raw') or hints.get('seed_url')}")
        transcript_event(f"[*] Target hints: {hints.get('raw') or hints.get('seed_url')}")

    if get_scan_profile().get("preflight_enabled", True):
        try:
            from core.recon.preflight import run_connectivity_preflight

            run_connectivity_preflight(ip, target_dir, hints)
        except Exception as exc:
            print(f"[!] Connectivity preflight error: {exc}")

    if deep:
        print("\n>>> PHASE 0: Deep OSINT & recon (Social, domain tools)")
        print("[*] Deep mode: ALL tools will run — results feed the next phase")
        transcript_phase("PHASE 0: Deep OSINT & recon")
        from core.phase_progress import track_phase

        try:
            with track_phase(
                "0", "Deep OSINT & recon",
                timeout=get_scan_profile().get("phase0_main_timeout", 900),
                target_dir=target_dir,
            ) as prog:
                prog.set_status("social + domain recon")
                from engines.deep_scan_extras import run_deep_domain_recon, run_deep_osint_phase

                run_deep_osint_phase(ip, target_dir, hints)
                prog.set_status("domain recon")
                run_deep_domain_recon(ip, target_dir, hints)
        except Exception as exc:
            print(f"[!] Deep Phase 0 error: {exc}")
        _phase_delay()
        _phase_done("0", "PHASE 0: Deep OSINT & recon")

    transcript_phase(f"PHASE 1: Scanning & Reconnaissance [{get_profile_name()}]")
    print(f"\n>>> PHASE 1: Scanning & Reconnaissance [{get_profile_name()}]")
    from core.phase_progress import track_phase

    try:
        with track_phase(
            "1", f"Scanning & Recon [{get_profile_name()}]",
            timeout=get_scan_profile().get("phase1_main_timeout", 2400),
            target_dir=target_dir,
        ) as prog:
            if get_scan_profile().get("local_net_snapshot"):
                try:
                    from core.recon.local_net import snapshot_local_connections

                    prog.set_status("local connection snapshot (ss/netstat)")
                    snapshot_local_connections(target_dir)
                except Exception as exc:
                    print(f"[!] Local net snapshot: {exc}")

            prog.set_status("Nmap port scan")
            try:
                context.open_ports = run_nmap(ip, target_dir)
            except KeyboardInterrupt:
                handle_keyboard_interrupt()
                context.open_ports = []

            if not context.open_ports:
                print(f"[-] No open ports found on {ip}.")
                context.web_ports = []
                context.login_ports = []
            else:
                context.web_ports = get_web_ports(context.open_ports)
                context.login_ports = get_login_ports(context.open_ports)
                if hints.get("port") and hints["port"] not in context.web_ports:
                    context.web_ports.insert(0, hints["port"])
                apply_target_hints(context, hints)

            profile = _sync_profile(ip, target_dir, context, "after Nmap", deep=deep)

            prog.set_status("IoT toolkit (UPnP, creds, wordlists)")
            try:
                from core.recon.iot_toolkit import run_phase1_iot_recon

                iot_p1 = run_phase1_iot_recon(ip, target_dir, context.open_ports)
                if iot_p1.get("default_creds"):
                    context.exploited = context.exploited or bool(iot_p1["default_creds"])
            except Exception as exc:
                print(f"[!] IoT Phase-1 extras (UPnP/changeme): {exc}")

            prog.set_status("parallel recon (whatweb, nikto, searchsploit)")
            try:
                from core.classic.parallel_phases import run_phase1_recon_parallel

                run_phase1_recon_parallel(ip, target_dir, profile, context, deep=deep)
            except Exception as exc:
                print(f"[!] Phase 1 parallel recon error: {exc}")
    except KeyboardInterrupt:
        handle_keyboard_interrupt()

    refresh_report(ip, target_dir, selection, context.exploited, context, "Phase 1 - Reconnaissance")
    profile = _sync_profile(ip, target_dir, context, "after Phase 1", deep=deep)
    _phase_done("1", f"PHASE 1: Scanning & Recon [{get_profile_name()}]")
    _phase_delay()

    web_ports = profile.get("web_ports") or context.web_ports
    if web_ports:
        print("\n======================================================")
        print(">>> PHASE 2: Web Enumeration (profile-driven)")
        print("======================================================")
        transcript_phase("PHASE 2: Web Enumeration (profile-driven)")
        try:
            with track_phase(
                "2", "Web Enumeration",
                timeout=get_scan_profile().get("phase2_main_timeout", 3600),
                target_dir=target_dir,
            ) as prog:
                from core.classic.parallel_phases import run_phase2_web_parallel

                def _sync(label):
                    nonlocal profile
                    prog.set_status(label)
                    profile = _sync_profile(ip, target_dir, context, label, deep=deep)
                    return profile

                p2 = run_phase2_web_parallel(
                    ip, target_dir, profile, context,
                    sync_profile_fn=_sync,
                    deep=deep,
                )
                if p2.get("nuclei_exploited"):
                    context.exploited = True
                if p2.get("sqlmap_exploited"):
                    context.exploited = True
                if p2.get("genzai_findings"):
                    transcript_event(f"[+] Genzai: {p2['genzai_findings']} IoT panel(s)")
        except KeyboardInterrupt:
            handle_keyboard_interrupt()

        refresh_report(ip, target_dir, selection, context.exploited, context, "Phase 2 - Web Enumeration")
        profile = _sync_profile(ip, target_dir, context, "after Phase 2", deep=deep)
        _phase_done("2", "PHASE 2: Web Enumeration")
    else:
        _phase_done(
            "2", "PHASE 2: Web Enumeration",
            skipped=True, skip_reason="لا منافذ ويب — تم تخطي enumeration",
        )
    _phase_delay()

    print("\n======================================================")
    print(">>> PHASE 3: Exploitation (profile-driven)")
    print("======================================================")
    transcript_phase("PHASE 3: Exploitation (profile-driven)")
    try:
        with track_phase(
            "3", "Exploitation",
            timeout=get_scan_profile().get("phase3_main_timeout", 3600),
            target_dir=target_dir,
        ) as prog:
            if deep:
                prog.set_status("deep device engine")
                print("\n[+] Deep Device Engine (full merge — all engine modules)...")
                try:
                    from engines.deep_scan_extras import run_full_device_engine

                    engine_result = run_full_device_engine(
                        ip,
                        target_dir,
                        web_ports=profile.get("web_ports") or context.web_ports,
                        profile=profile,
                        hints=hints,
                    )
                    if engine_result.get("exploited"):
                        context.exploited = True
                    creds = engine_result.get("credentials") or []
                    if creds:
                        print(f"[+] Engine credentials: {', '.join(creds)}")
                except Exception as exc:
                    print(f"[!] Deep device engine error: {exc}")

                prog.set_status("RouterSploit + Ingram")
                print("\n[+] Deep: RouterSploit + Ingram (parallel)...")
                from core.classic.parallel_phases import run_phase3_classic_parallel

                if run_phase3_classic_parallel(ip, target_dir, profile, deep=True):
                    context.exploited = True

                prog.set_status("PoC arsenal")
                print("\n[+] Deep: GitHub PoC arsenal (scripts/new_pocs/)...")
                try:
                    from engines.deep_scan_extras import run_deep_poc_arsenal

                    poc_hits = run_deep_poc_arsenal(
                        ip,
                        target_dir,
                        web_ports=profile.get("web_ports") or context.web_ports,
                        device_type=profile.get("target_type", "UNKNOWN"),
                    )
                    if poc_hits:
                        context.exploited = True
                        print(f"[+] PoC arsenal: {len(poc_hits)} script(s) reported success")
                except Exception as exc:
                    print(f"[!] PoC arsenal error: {exc}")
            else:
                prog.set_status("device exploit engine")
                print("\n[+] Device Exploit Engine (Hikvision / Netis / CVE / creds)...")
                try:
                    from engines.integration import run_device_exploit_engine

                    engine_result = run_device_exploit_engine(
                        ip, target_dir, web_ports=profile.get("web_ports") or context.web_ports, profile=profile,
                    )
                    if engine_result.get("exploited"):
                        context.exploited = True
                    creds = engine_result.get("credentials") or []
                    if creds:
                        print(f"[+] Engine credentials: {', '.join(creds)}")
                except Exception as exc:
                    print(f"[!] Device engine error: {exc}")

                prog.set_status("RouterSploit + Ingram")
                from core.classic.parallel_phases import run_phase3_classic_parallel

                if run_phase3_classic_parallel(ip, target_dir, profile, deep=False):
                    context.exploited = True

            prog.set_status("IoT exploit stack")
            try:
                from engines.iot_exploit_extras import run_phase3_iot_extras

                iot_p3 = run_phase3_iot_extras(
                    ip, target_dir,
                    web_ports=profile.get("web_ports") or context.web_ports,
                )
                if (
                    iot_p3.get("camover")
                    or iot_p3.get("camraptor")
                    or iot_p3.get("rustsploit", {}).get("output")
                    or iot_p3.get("iotscan", {}).get("output")
                    or any(
                        r.get("vulnerable") for r in (iot_p3.get("iotbreaker") or []) if isinstance(r, dict)
                    )
                ):
                    context.exploited = True
            except Exception as exc:
                print(f"[!] IoT Phase-3 extras (CamOver/IoTBreaker): {exc}")

            if deep:
                prog.set_status("NetExec lateral")
                try:
                    from engines.lateral_agent import LateralAgent

                    print("\n[+] Deep: NetExec lateral (system nxc)...")
                    lateral = LateralAgent(ip, target_dir)
                    lateral.execute()
                except Exception as exc:
                    print(f"[!] NetExec lateral skipped: {exc}")
    except KeyboardInterrupt:
        handle_keyboard_interrupt()

    refresh_report(ip, target_dir, selection, context.exploited, context, "Phase 3 - Exploitation")
    profile = _sync_profile(ip, target_dir, context, "after Phase 3", deep=deep)
    _phase_done("3", "PHASE 3: Exploitation")
    _phase_delay()

    if (profile.get("login_ports") or context.login_ports or profile.get("login_paths")) and should_run_tool(profile, "hydra"):
        print("\n======================================================")
        print(">>> PHASE 4: Credential Brute-Force (profile-driven)")
        print("======================================================")
        transcript_phase("PHASE 4: Credential Brute-Force (profile-driven)")
        try:
            with track_phase(
                "4", "Credential Brute-Force",
                timeout=get_scan_profile().get("phase4_main_timeout", 1800),
                target_dir=target_dir,
            ) as prog:
                from core.recon.iot_toolkit import build_iot_hydra_wordlists

                prog.set_status("IoT wordlists + Hydra")
                wl = build_iot_hydra_wordlists(target_dir)
                if wl.get("passwords"):
                    print(f"[+] IoT wordlists ready: {wl['passwords']}")
                if context.login_ports and run_hydra(ip, context.login_ports, target_dir):
                    pass
                hydra_cfg = get_tool_config(profile, "hydra")
                login_paths = profile.get("login_paths") or context.login_paths
                forms = None
                if login_paths:
                    forms = [hydra_form_for_path(p) for p in login_paths]
                elif hydra_cfg.get("http_forms"):
                    forms = [hydra_form_for_path(p) for p in hydra_cfg["http_forms"]]
                hydra_plan = {"http_forms": forms, "source": "target_profile"} if forms else None
                prog.set_status("web Hydra forms")
                if context.web_ports and run_web_hydra(ip, context.web_ports, target_dir, hydra_plan=hydra_plan):
                    pass
        except KeyboardInterrupt:
            handle_keyboard_interrupt()
        _phase_done("4", "PHASE 4: Credential Brute-Force")
    else:
        print("[*] Hydra skipped by target profile or no login surface.")
        _phase_done(
            "4", "PHASE 4: Credential Brute-Force",
            skipped=True, skip_reason="Hydra — لا login surface أو مُستبعد بالملف الشخصي",
        )

    _, confirmed = refresh_report(ip, target_dir, selection, context.exploited, context, "Phase 4 - Brute Force")
    _sync_profile(ip, target_dir, context, "final", deep=deep)
    transcript_end(note=f"Confirmed exploit: {'YES' if confirmed else 'NO'}")
    return confirmed
