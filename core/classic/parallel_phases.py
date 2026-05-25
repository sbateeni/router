"""Parallel execution helpers for full_scan phases."""

from __future__ import annotations

import re
import threading
from typing import Callable

from core.classic.context import build_url, extract_query_urls
from core.classic.helpers import is_tool_available, run_ffuf, run_gau
from core.phase_jobs import PhaseRunner
from core.recon_tools import run_nikto, run_whatweb
from core.scan_config import get_scan_profile
from core.web import run_dirsearch, run_nuclei, run_searchsploit
from core.web.sqlmap import run_sqlmap_phase

_ctx_lock = threading.Lock()


def _nuclei_workers() -> int:
    return int(get_scan_profile().get("parallel_nuclei_workers", 3))


def _extend_locked(target_list: list, items: list) -> None:
    with _ctx_lock:
        target_list.extend(items)


def run_phase1_recon_parallel(
    ip: str,
    target_dir: str,
    profile: dict,
    context,
    *,
    deep: bool = False,
) -> None:
    """whatweb, nikto, searchsploit (+ deep nmap vuln) in parallel."""
    from core.classic.metasploit import run_metasploit_recon
    from core.recon.target_profile import get_tool_config, should_run_tool

    web_ports = profile.get("web_ports") or context.web_ports or []
    runner = PhaseRunner(target_dir, "1-recon", "Phase 1 — parallel recon tools")

    if should_run_tool(profile, "whatweb"):
        for port in web_ports:
            url = build_url(ip, port)
            runner.add(
                f"whatweb-{port}",
                lambda u=url: run_whatweb(u, target_dir),
                timeout=120,
                artifacts=(f"whatweb_port_{port}.txt",),
            )

    if should_run_tool(profile, "searchsploit"):
        queries = (
            get_tool_config(profile, "searchsploit").get("queries")
            or profile.get("searchsploit_queries", [])
        )
        for idx, q in enumerate(queries[:12]):
            runner.add(
                f"searchsploit-{idx}",
                lambda query=q, i=idx: run_searchsploit(query, target_dir, append=i > 0),
                timeout=90,
                artifacts=("searchsploit.txt",),
            )

    if should_run_tool(profile, "nikto"):
        for port in web_ports:
            url = build_url(ip, port)
            runner.add(
                f"nikto-{port}",
                lambda u=url: run_nikto(u, target_dir),
                timeout=300,
                artifacts=(f"nikto_port_{port}.txt",),
            )

    if deep:
        from core.recon_tools import run_nmap_vuln_scripts

        runner.add(
            "nmap-vuln",
            lambda: run_nmap_vuln_scripts(ip, target_dir),
            timeout=600,
            artifacts=("nmap_vuln.txt",),
        )

    if runner.jobs:
        print(f"\n[+] Phase 1 parallel recon: {len(runner.jobs)} job(s)")
        runner.run(group_timeout=get_scan_profile().get("phase1_group_timeout", 1200))

    if should_run_tool(profile, "metasploit"):
        run_metasploit_recon(ip, target_dir, context.open_ports, vendor=profile.get("vendor"))
    else:
        print("[*] Metasploit skipped by target profile.")


def run_phase2_web_parallel(
    ip: str,
    target_dir: str,
    profile: dict,
    context,
    *,
    sync_profile_fn: Callable[[str], dict],
    deep: bool = False,
) -> dict:
    """
    Parallel web enum: dirsearch → sync → gau/ffuf → nuclei parallel → sqlmap → genzai.
    """
    from core.recon.iot_toolkit import merge_genzai_port_results, run_genzai_single_port
    from core.recon.target_profile import get_tool_config, should_run_tool

    out = {"nuclei_exploited": False, "sqlmap_exploited": False, "genzai_findings": 0}
    web_ports = profile.get("web_ports") or context.web_ports or []

    # --- Batch 1: Dirsearch ---
    if should_run_tool(profile, "dirsearch"):
        ds = PhaseRunner(target_dir, "2-dirsearch", "Phase 2 — Dirsearch")
        for port in web_ports:
            url = build_url(ip, port)

            def _ds_job(u=url):
                paths = run_dirsearch(u, target_dir)
                _extend_locked(context.discovered_paths, paths)
                return paths

            ds.add(f"dirsearch-{port}", _ds_job, timeout=600, artifacts=(f"dirsearch_port_{port}.txt",))
        if ds.jobs:
            print(f"\n[+] Phase 2 parallel Dirsearch: {len(ds.jobs)} port(s)")
            ds.run(group_timeout=get_scan_profile().get("phase2_dirsearch_timeout", 900))
        with _ctx_lock:
            context.discovered_paths = list(dict.fromkeys(context.discovered_paths))
    else:
        print("[*] Dirsearch skipped by profile.")

    profile = sync_profile_fn("after Dirsearch")

    from core.classic.metasploit import run_metasploit_recon

    if should_run_tool(profile, "metasploit"):
        import os

        msf_cmds = os.path.join(target_dir, "MSF_EXPLOIT_COMMANDS.txt")
        if not os.path.exists(msf_cmds) or os.path.getsize(msf_cmds) < 80:
            print("\n[+] Metasploit (deferred MSF search)...")
            run_metasploit_recon(ip, target_dir, context.open_ports, vendor=profile.get("vendor"))

    # --- Batch 2: GAU (once) + FFUF (per port) ---
    batch2 = PhaseRunner(target_dir, "2-paths", "Phase 2 — GAU + FFUF")
    if should_run_tool(profile, "gau") and is_tool_available("gau") and web_ports:
        base_url = build_url(ip, web_ports[0])

        def _gau_job():
            urls = run_gau(base_url, target_dir)
            _extend_locked(context.gau_urls, urls)
            return urls

        batch2.add("gau", _gau_job, timeout=180, artifacts=("gau_urls.txt",))

    if should_run_tool(profile, "ffuf") and is_tool_available("ffuf"):
        for port in web_ports:
            url = build_url(ip, port)

            def _ffuf_job(u=url):
                found = run_ffuf(u, target_dir)
                _extend_locked(context.ffuf_candidates, found)
                return found

            batch2.add(f"ffuf-{port}", _ffuf_job, timeout=300)

    if batch2.jobs:
        print(f"\n[+] Phase 2 parallel path discovery: {len(batch2.jobs)} job(s)")
        batch2.run(group_timeout=600)

    with _ctx_lock:
        context.gau_urls = list(dict.fromkeys(context.gau_urls))
        context.ffuf_candidates = list(dict.fromkeys(context.ffuf_candidates))
        context.discovered_paths = list(dict.fromkeys(context.discovered_paths))
        context.discovered_urls = list(dict.fromkeys(
            context.discovered_paths + context.gau_urls + context.ffuf_candidates
        ))

    profile = sync_profile_fn("after path discovery")

    # --- Batch 3: Nuclei (limited workers) ---
    nuclei_cfg = get_tool_config(profile, "nuclei")
    if should_run_tool(profile, "nuclei"):
        tags = nuclei_cfg.get("tags")
        query_urls = extract_query_urls(context.discovered_urls)
        if not query_urls:
            query_urls = [build_url(ip, port) for port in web_ports]
        url_limit = get_scan_profile()["nuclei_url_limit"]
        targets = query_urls[:url_limit]
        cmd_timeout = int(get_scan_profile().get("nuclei_cmd_timeout", 480))
        print(f"\n[+] Phase 2 parallel Nuclei: {len(targets)} URL(s), workers={_nuclei_workers()}")
        nuc = PhaseRunner(target_dir, "2-nuclei", "Phase 2 — Nuclei", max_workers=_nuclei_workers())

        for idx, target_url in enumerate(targets):
            safe = re.sub(r"[^\w.-]", "_", target_url[-40:])

            def _nuclei_job(u=target_url):
                return run_nuclei(u, target_dir, tags=tags)

            nuc.add(f"nuclei-{idx}-{safe}", _nuclei_job, timeout=cmd_timeout + 30)

        if nuc.jobs:
            nuc_results = nuc.run(group_timeout=get_scan_profile().get("phase2_nuclei_timeout", 1800))
            out["nuclei_exploited"] = any(
                r.ok and r.result is True for r in nuc_results.values()
            )
    else:
        print(f"[*] Nuclei skipped: {nuclei_cfg.get('reason', '')}")

    sql_cfg = get_tool_config(profile, "sqlmap")
    if should_run_tool(profile, "sqlmap"):
        print("\n[+] SQLMap (URLs from profile)...")
        out["sqlmap_exploited"] = bool(
            run_sqlmap_phase(ip, web_ports, context.discovered_urls, target_dir)
        )
    else:
        print(f"[*] SQLMap skipped: {sql_cfg.get('reason', '')}")

    # --- Genzai parallel ---
    gz = PhaseRunner(target_dir, "2-genzai", "Phase 2 — Genzai")
    for port in web_ports[:8]:
        gz.add(
            f"genzai-{port}",
            lambda p=port: run_genzai_single_port(ip, target_dir, p),
            timeout=120,
            artifacts=(f"genzai_port_{port}.txt",),
        )
    if gz.jobs:
        print(f"\n[+] Phase 2 parallel Genzai: {len(gz.jobs)} port(s)")
        gz.run(group_timeout=400)
        gdata = merge_genzai_port_results(target_dir)
        out["genzai_findings"] = len(gdata.get("findings") or [])

    return out


def run_phase3_classic_parallel(ip: str, target_dir: str, profile: dict, *, deep: bool = False) -> bool:
    """RouterSploit + Ingram in parallel."""
    from core.exploitation import run_ingram, run_routersploit
    from core.recon.target_profile import get_tool_config, should_run_tool

    runner = PhaseRunner(target_dir, "3-classic", "RouterSploit + Ingram", max_workers=2)
    if deep or should_run_tool(profile, "routersploit"):
        runner.add("routersploit", lambda: run_routersploit(ip, target_dir), timeout=900)
    elif not deep:
        print(f"[*] RouterSploit skipped: {get_tool_config(profile, 'routersploit').get('reason', '')}")

    if deep or should_run_tool(profile, "ingram"):
        runner.add("ingram", lambda: run_ingram(ip, target_dir), timeout=900)
    elif not deep:
        print(f"[*] Ingram skipped: {get_tool_config(profile, 'ingram').get('reason', '')}")

    if not runner.jobs:
        return False
    print(f"\n[+] Phase 3 parallel classic: {len(runner.jobs)} job(s)")
    results = runner.run(group_timeout=get_scan_profile().get("phase3_classic_timeout", 1200))
    exploited = False
    for r in results.values():
        if r.ok and r.result:
            exploited = True
    return exploited
