"""
Build a living target profile from tool outputs and route the next tools accordingly.
"""
import json
import os
import re
from datetime import datetime

from core.classic.context import should_run_ingram
from core.recon.service_intel import (
    build_searchsploit_queries,
    is_likely_router_target,
    should_run_routersploit,
)
from core.report.parsers import (
    detect_connectivity_issues,
    find_files,
    normalize_target_url,
    parse_dirsearch_entries,
    parse_ffuf_entries,
    parse_nmap_summary,
    pick_priority_web_targets,
    read_file,
)

PROFILE_FILE = "target_profile.json"

LOGIN_PATH_HINTS = (
    "login", "signin", "auth", "goform", "cgi-bin/login", "admin",
)


def _parse_stack_from_nmap(ports, vendor=None):
    blob = " ".join(str(p.get("service", "")) for p in ports).lower()
    if vendor:
        blob += " " + vendor.lower()
    stack = {
        "http_server": None,
        "php": None,
        "openssl": None,
        "os": None,
        "fortinet": False,
    }
    apache = re.search(r"apache\s+httpd\s+([\d.]+)", blob, re.I)
    if apache:
        stack["http_server"] = f"Apache {apache.group(1)}"
    nginx = re.search(r"nginx[/\s]([\d.]+)", blob, re.I)
    if nginx:
        stack["http_server"] = f"nginx {nginx.group(1)}"
    php = re.search(r"php[/\s]([\d.]+)", blob, re.I)
    if php:
        stack["php"] = php.group(1)
    ssl = re.search(r"openssl[/\s]([\w.]+)", blob, re.I)
    if ssl:
        stack["openssl"] = ssl.group(1)
    if "win32" in blob or "windows" in blob or "microsoft" in blob:
        stack["os"] = "windows"
    elif "linux" in blob or "ubuntu" in blob or "debian" in blob:
        stack["os"] = "linux"
    if "fortinet" in blob or "reverse-ssl" in blob:
        stack["fortinet"] = True
    return stack


def _parse_whatweb(target_dir):
    tech = []
    for path in find_files(target_dir, "whatweb_port_*.txt"):
        text = read_file(path, 8000)
        for match in re.findall(r"\[([^\]]+)\]", text):
            if match and len(match) < 80:
                tech.append(match.strip())
    return list(dict.fromkeys(tech))[:20]


def _login_paths_from_artifacts(target_dir, dir_entries):
    paths = set()
    for entry in dir_entries:
        url = entry.get("url", "").lower()
        if any(h in url for h in LOGIN_PATH_HINTS):
            paths.add(entry["url"])
    for path in find_files(target_dir, "hydra_web_*_form_*.txt"):
        name = os.path.basename(path)
        m = re.search(r"form_(.+)\.txt$", name)
        if m:
            form_path = m.group(1).replace("_", "/")
            if not form_path.startswith("/"):
                form_path = "/" + form_path
            paths.add(form_path)
    return sorted(paths)


def _classify_target(ports, vendor, stack, dir_entries, login_paths):
    blob = " ".join(str(p.get("service", "")) for p in ports).lower()
    has_apache_php_win = (
        "apache" in blob and "php" in blob and stack.get("os") == "windows"
    )
    has_router_login = bool(login_paths) and any(
        "cgi-bin" in p or "goform" in p for p in login_paths
    )

    if stack.get("fortinet") or any(
        isinstance(p, dict) and p.get("port") in (541, 10443, 8443)
        and "fortinet" in str(p.get("service", "")).lower()
        for p in ports
    ):
        if has_apache_php_win:
            return "hybrid_web_fortinet", "high", (
                "Web server (Apache/PHP) on HTTP + Fortinet SSL service on extra port."
            )
        return "fortinet_gateway", "high", "Fortinet SSL/management service detected."

    if is_likely_router_target(ports, vendor=vendor) or (
        has_router_login and not has_apache_php_win
    ):
        return "router", "high", "Embedded router/CPE web interface patterns."

    if has_apache_php_win or ("apache" in blob and "php" in blob):
        return "web_server", "high", "Generic Apache + PHP application stack."

    if any(p.get("port") in (80, 443, 8080) for p in ports if isinstance(p, dict)):
        return "web_server", "medium", "HTTP service detected; stack not fully identified."

    return "unknown", "low", "Insufficient fingerprint — run more recon."


def _nuclei_tags_for_type(target_type, stack):
    if target_type == "router":
        return "default-logins,cves,misconfiguration,exposed-panel,upnp,rce,zte"
    if target_type in ("fortinet_gateway", "hybrid_web_fortinet"):
        return "cve,fortinet,misconfiguration,exposed-panel,default-logins"
    if stack.get("php"):
        return "cve,apache,php,misconfiguration,exposed-panel,default-logins"
    return "cve,misconfiguration,exposed-panel,default-logins"


def _build_tool_plan(
    ip,
    target_type,
    ports,
    web_ports,
    login_ports,
    vendor,
    stack,
    dir_entries,
    login_paths,
    priority_urls,
    connectivity_issues,
    searchsploit_queries,
):
    run_rs = should_run_routersploit(ports, vendor=vendor)
    has_web = bool(web_ports)
    has_php = bool(stack.get("php")) or any(".php" in e.get("url", "") for e in dir_entries)
    has_query_urls = any("?" in u for u in priority_urls)

    def tool(run, reason, **extra):
        return {"run": run, "reason": reason, **extra}

    plan = {
        "searchsploit": tool(
            bool(searchsploit_queries),
            "Match local exploits to detected stack/vendor.",
            queries=searchsploit_queries,
        ),
        "metasploit": tool(
            target_type in ("router", "fortinet_gateway", "hybrid_web_fortinet")
            or is_likely_router_target(ports, vendor),
            "MSF search for vendor-specific modules (skip generic router list on web apps).",
        ),
        "whatweb": tool(has_web, "Fingerprint CMS/plugins before deep scans."),
        "nikto": tool(has_web and target_type == "web_server", "Web server misconfiguration scan."),
        "dirsearch": tool(has_web, "Discover hidden paths and PHP endpoints."),
        "ffuf": tool(has_web, "Fuzz directories using wordlist."),
        "gau": tool(has_web, "Historical URLs may reveal parameters."),
        "nuclei": tool(
            has_web and not connectivity_issues,
            "Template scan with tags matched to target type."
            if not connectivity_issues
            else "Skipped or cautious — prior connectivity failures detected.",
            tags=_nuclei_tags_for_type(target_type, stack),
        ),
        "sqlmap": tool(
            has_web and (has_php or has_query_urls) and not connectivity_issues,
            "SQLi testing on PHP/query endpoints."
            if has_php
            else "No PHP/query URLs yet — may run on base URL only.",
            urls=priority_urls[:12],
        ),
        "routersploit": tool(
            run_rs,
            "Router exploit modules." if run_rs else "Not a router fingerprint — skip AutoPwn.",
        ),
        "ingram": tool(
            should_run_ingram(ports),
            "Camera/DVR exploit scan." if should_run_ingram(ports) else "No camera services detected.",
        ),
        "hydra": tool(
            bool(login_ports or login_paths or has_web),
            "Brute force only after recon; forms derived from discovered login paths.",
            http_forms=login_paths[:6] if login_paths else None,
        ),
    }
    return plan


def _routing_notes(target_type, stack, plan, priority_urls, connectivity_issues):
    notes = []
    notes.append(f"Target class: {target_type}")
    if stack.get("http_server"):
        notes.append(f"HTTP: {stack['http_server']}")
    if stack.get("php"):
        notes.append(f"PHP: {stack['php']} (EOL — check app-specific CVEs, not generic router exploits)")
    if stack.get("fortinet"):
        notes.append("Fortinet service present — use searchsploit fortinet; do not use Fiberhome/router MSF modules.")
    for name, cfg in plan.items():
        if not cfg.get("run"):
            notes.append(f"SKIP {name}: {cfg.get('reason', '')}")
    if priority_urls:
        notes.append("Priority URLs for manual/SQLMap:")
        for url in priority_urls[:6]:
            notes.append(f"  → {url}")
    if connectivity_issues:
        notes.append("Connectivity issues detected — re-run web tools when curl succeeds.")
    return notes


def build_target_profile(ip, target_dir, context=None):
    """Aggregate all artifact files into one profile + tool routing plan."""
    nmap = parse_nmap_summary(target_dir)
    ports = nmap.get("ports") or []
    vendor = nmap.get("vendor")

    if context:
        web_ports = list(context.web_ports or [])
        login_ports = list(context.login_ports or [])
        discovered = list(context.discovered_urls or context.discovered_paths or [])
    else:
        web_ports = [p["port"] for p in ports if p.get("port") in (80, 443, 8080, 8443)]
        login_ports = []
        discovered = []
        for p in ports:
            svc = str(p.get("service", "")).lower()
            if p.get("port") in (21, 22, 23) or svc.split()[0] in ("ssh", "ftp", "telnet"):
                login_ports.append(p)

    if not web_ports and ports:
        web_ports = [
            p["port"] for p in ports
            if "http" in str(p.get("service", "")).lower() or p.get("port") in (80, 443)
        ]

    dir_entries = parse_dirsearch_entries(target_dir)
    ffuf_entries = parse_ffuf_entries(target_dir)
    for url in [e["url"] for e in ffuf_entries]:
        if url not in discovered:
            discovered.append(url)

    stack = _parse_stack_from_nmap(ports, vendor=vendor)
    whatweb_tech = _parse_whatweb(target_dir)
    login_paths = _login_paths_from_artifacts(target_dir, dir_entries)
    interesting = [e for e in dir_entries if e.get("status") == 200]

    target_type, confidence, type_summary = _classify_target(
        ports, vendor, stack, dir_entries, login_paths,
    )
    connectivity_issues = detect_connectivity_issues(target_dir)
    searchsploit_queries = build_searchsploit_queries(ports, vendor=vendor)
    priority_urls = pick_priority_web_targets(ip, web_ports, [e["url"] for e in dir_entries] + discovered)

    tool_plan = _build_tool_plan(
        ip, target_type, ports, web_ports, login_ports, vendor, stack,
        dir_entries, login_paths, priority_urls, connectivity_issues, searchsploit_queries,
    )

    profile = {
        "ip": ip,
        "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target_type": target_type,
        "confidence": confidence,
        "summary": type_summary,
        "os": stack.get("os"),
        "stack": stack,
        "vendor": vendor,
        "technologies": whatweb_tech,
        "ports": ports,
        "web_ports": web_ports,
        "login_ports": [p.get("port") for p in login_ports if isinstance(p, dict)],
        "login_paths": login_paths,
        "dirsearch_hits_200": interesting[:20],
        "ffuf_count": len(ffuf_entries),
        "priority_urls": priority_urls,
        "searchsploit_queries": searchsploit_queries,
        "connectivity_issues": connectivity_issues,
        "tool_plan": tool_plan,
        "routing_notes": _routing_notes(
            target_type, stack, tool_plan, priority_urls, connectivity_issues,
        ),
    }
    return profile


def save_target_profile(target_dir, profile):
    path = os.path.join(target_dir, PROFILE_FILE)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(profile, fh, indent=2, ensure_ascii=False)
    return path


def load_target_profile(target_dir):
    path = os.path.join(target_dir, PROFILE_FILE)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def print_target_profile(profile):
    print("\n" + "=" * 60)
    print(" TARGET PROFILE (drives tool selection)")
    print("=" * 60)
    print(f"  IP          : {profile.get('ip')}")
    print(f"  Type        : {profile.get('target_type')} ({profile.get('confidence')})")
    print(f"  Summary     : {profile.get('summary')}")
    stack = profile.get("stack") or {}
    if stack.get("http_server"):
        print(f"  HTTP        : {stack['http_server']}")
    if stack.get("php"):
        print(f"  PHP         : {stack['php']}")
    if stack.get("os"):
        print(f"  OS hint     : {stack['os']}")
    if profile.get("web_ports"):
        print(f"  Web ports   : {', '.join(str(p) for p in profile['web_ports'])}")
    if profile.get("login_paths"):
        print(f"  Login paths : {', '.join(profile['login_paths'][:5])}")
    print("\n  Tool routing:")
    for name, cfg in (profile.get("tool_plan") or {}).items():
        flag = "RUN " if cfg.get("run") else "SKIP"
        print(f"    [{flag}] {name}: {cfg.get('reason', '')}")
    print("=" * 60 + "\n")


def should_run_tool(profile, tool_name):
    plan = profile.get("tool_plan") or {}
    entry = plan.get(tool_name) or {}
    return bool(entry.get("run"))


def get_tool_config(profile, tool_name):
    return (profile.get("tool_plan") or {}).get(tool_name) or {}
