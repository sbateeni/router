import json
import os
import re
import shutil

from core.utils import run_cmd

MSF_SEARCH_FILE = "msf_search.txt"
MSF_COMMANDS_FILE = "MSF_EXPLOIT_COMMANDS.txt"
MSF_MODULES_JSON = "msf_modules.json"
MODULE_RE = re.compile(r"^\s*\d+\s+((?:exploit|auxiliary)/\S+)", re.MULTILINE)
GENERIC_SKIP = {"http", "https", "ssl", "tcp", "nginx", "httpd", "unknown"}


def msf_available():
    return shutil.which("msfconsole") is not None


def run_metasploit_search(query, target_dir, append=True):
    if not msf_available():
        print("[!] Metasploit (msfconsole) not found; skipping Metasploit lookup.")
        return False
    q = query.strip()
    if not q or q.lower() in GENERIC_SKIP:
        print(f"[*] Skipping generic Metasploit search for '{query}'.")
        return False

    log_file = os.path.join(target_dir, MSF_SEARCH_FILE)
    header = f"\n{'=' * 60}\nSEARCH: {q}\n{'=' * 60}\n"
    msf_cmd = f"search {q}; exit"
    command = ["msfconsole", "-q", "-x", msf_cmd]
    success, output = run_cmd(command, capture=True)

    try:
        mode = "a" if append and os.path.exists(log_file) else "w"
        with open(log_file, mode, encoding="utf-8") as fh:
            if mode == "a":
                fh.write(header)
            fh.write(output or "")
            fh.write("\n")
    except OSError:
        pass

    if output:
        print(output[:1500] + ("..." if len(output) > 1500 else ""))
    print(f"[+] Metasploit search saved: {log_file} (query: {q})")
    return success or bool(output)


def parse_msf_modules(text):
    modules = []
    seen = set()
    for match in MODULE_RE.finditer(text or ""):
        module = match.group(1).strip()
        if module not in seen:
            seen.add(module)
            modules.append(module)
    return modules


GENERIC_SKIP = {"http", "https", "ssl", "tcp", "nginx", "httpd", "unknown"}
VENDOR_NOISE = {
    "telecommunication", "telecommunications", "technologies", "technology",
    "communication", "communications", "corporation", "corp", "inc", "ltd",
    "limited", "company", "group", "international", "systems", "network",
    "networks", "device", "devices", "electronic", "electronics",
}


def _meaningful_vendor_tokens(vendor):
    if not vendor:
        return []
    tokens = []
    lower = vendor.lower()
    if "fiberhome" in lower:
        tokens.append("fiberhome")
    for token in re.split(r"[\s,/]+", vendor):
        token = token.strip()
        if len(token) <= 3:
            continue
        key = token.lower()
        if key in GENERIC_SKIP or key in VENDOR_NOISE:
            continue
        tokens.append(token)
    return list(dict.fromkeys(tokens))


def build_search_queries(open_ports, vendor=None):
    queries = []
    if vendor:
        queries.extend(_meaningful_vendor_tokens(vendor))
        if "fiberhome" in vendor.lower():
            queries.extend(["fiberhome router"])

    for entry in open_ports or []:
        if not isinstance(entry, dict):
            continue
        svc = (entry.get("service") or "").lower()
        for token in re.split(r"[\s/]+", svc):
            if len(token) > 3 and token not in GENERIC_SKIP and token not in VENDOR_NOISE:
                queries.append(token)

    return list(dict.fromkeys(queries))[:6]


def build_fallback_search_queries(vendor=None):
    """Vendor-only retries — never generic 'router' (matches Cisco/D-Link, not Fiberhome)."""
    if not vendor:
        return []
    queries = []
    lower = vendor.lower()
    if "fiberhome" in lower:
        queries.extend(["fiberhome router", "fiberhome telecom"])
    queries.extend(_meaningful_vendor_tokens(vendor))
    return list(dict.fromkeys(queries))[:4]


def vendor_matches_module(vendor, module):
    if not vendor or not module:
        return True
    vendor_l = vendor.lower()
    module_l = module.lower()
    tokens = [t for t in re.split(r"[\s,_-]+", vendor_l) if len(t) > 4 and t not in GENERIC_SKIP]
    if "fiberhome" in vendor_l:
        return "fiberhome" in module_l
    return any(token in module_l for token in tokens)


def _default_port(module, web_ports, login_ports):
    mod = module.lower()
    if "ssh" in mod and login_ports:
        return login_ports[0].get("port", 22)
    if "ssl" in mod or "https" in mod:
        return 443 if 443 in web_ports else (web_ports[0] if web_ports else 443)
    if "http" in mod or "web" in mod:
        return 80 if 80 in web_ports else (web_ports[0] if web_ports else 80)
    return web_ports[0] if web_ports else 80


def build_msf_one_liner(module, ip, port, use_ssl=False):
    """Copy-paste msfconsole -x one-liner for a real module path."""
    parts = [f"use {module}", f"set RHOSTS {ip}"]
    mod = module.lower()
    if module.startswith("exploit/") or "http" in mod or "browser" in mod:
        parts.append(f"set RPORT {port}")
    if use_ssl or port in (443, 8443):
        parts.append("set SSL true")
    if module.startswith("exploit/"):
        parts.extend(["check", "run"])
    else:
        parts.append("run")
    parts.append("exit")
    return "msfconsole -q -x \"" + "; ".join(parts) + "\""


def build_msf_command_block(module, ip, port, use_ssl=False):
    lines = [
        f"# Module: {module}",
        f"use {module}",
        "show options",
        f"set RHOSTS {ip}",
    ]
    mod = module.lower()
    if module.startswith("exploit/") or "http" in mod or "browser" in mod:
        lines.append(f"set RPORT {port}")
    if use_ssl or port in (443, 8443):
        lines.append("set SSL true")
    if module.startswith("exploit/"):
        lines.extend([
            "check",
            "run",
        ])
    else:
        lines.append("run")
    lines.append("back")
    lines.append("")
    return lines


def generate_msf_exploit_commands(ip, target_dir, modules, web_ports=None, login_ports=None, vendor=None):
    web_ports = web_ports or [80, 443]
    login_ports = login_ports or []
    if vendor:
        modules = [m for m in modules if vendor_matches_module(vendor, m)]
    exploits = [m for m in modules if m.startswith("exploit/")]
    aux = [m for m in modules if m.startswith("auxiliary/")]
    vendor_label = (vendor or "unknown").strip()

    lines = [
        "============================================================",
        " METASPLOIT — suggested commands (review before running)",
        "============================================================",
        f"Target IP: {ip}",
        f"Vendor hint: {vendor_label}",
        f"Web ports: {', '.join(str(p) for p in web_ports)}",
        "",
        "IMPORTANT:",
        "  - Only run modules that match YOUR router vendor/firmware.",
        "  - 'search type:exploit router' lists Cisco/D-Link/Netgear — NOT Fiberhome.",
        "  - Do NOT run unrelated exploits (may crash or brick the device).",
        "  - 'check' and 'run' only work AFTER 'use <real_module>' succeeds.",
        "",
        "Find modules for this vendor:",
        f"  msfconsole -q -x \"search fiberhome; exit\"",
        "",
        "Run interactively (when a matching module exists):",
        "  msfconsole -q",
        "  search fiberhome",
        f"  use exploit/<exact/path/from/search>",
        f"  set RHOSTS {ip}",
        "  set RPORT 80",
        "  show options",
        "  check",
        "  run",
        "",
        "------------------------------------------------------------",
        " READY ONE-LINERS (vendor-matched modules only)",
        "------------------------------------------------------------",
    ]

    if not exploits and not aux:
        lines.extend([
            f"No Metasploit modules matched vendor: {vendor_label}",
            "",
            "Your manual search confirmed:",
            "  search fiberhome  -> No results (expected for Fiberhome)",
            "  search type:exploit router -> lists OTHER brands only",
            "",
            "For Fiberhome / ISP CPE routers, Metasploit usually has NO public exploit.",
            "Focus instead on:",
            "  1. Browser login at http://192.168.1.1 (verify Hydra creds manually)",
            "  2. FFUF/dirsearch paths: /html /menu /cgi-bin",
            "  3. RouterSploit output in routersploit_scan.txt",
            "  4. SearchSploit + Nuclei findings in RESULTS_SUMMARY.txt",
            "",
            "Note on auxiliary/scanner/http/http_login:",
            "  - Only for HTTP Basic/Digest auth (browser popup).",
            "  - Fiberhome uses HTML login forms — 'No URI found' is normal.",
            "",
        ])
    else:
        for module in exploits[:5]:
            port = _default_port(module, web_ports, login_ports)
            lines.append(build_msf_one_liner(module, ip, port, use_ssl=port in (443, 8443)))
        if not exploits and aux:
            for module in aux[:3]:
                port = _default_port(module, web_ports, login_ports)
                lines.append(build_msf_one_liner(module, ip, port, use_ssl=port in (443, 8443)))
        lines.append("")

    lines.extend([
        "------------------------------------------------------------",
        " EXPLOIT MODULES (interactive steps)",
        "------------------------------------------------------------",
    ])

    if not exploits and not aux:
        lines.append("No vendor-matched exploit modules to list.")
        lines.append("(Generic 'search router' hits are intentionally excluded.)")
    else:
        for module in exploits[:15]:
            port = _default_port(module, web_ports, login_ports)
            lines.extend(build_msf_command_block(module, ip, port, use_ssl=port in (443, 8443)))

        lines.extend([
            "------------------------------------------------------------",
            " AUXILIARY MODULES (scan/check)",
            "------------------------------------------------------------",
        ])
        for module in aux[:10]:
            port = _default_port(module, web_ports, login_ports)
            lines.extend(build_msf_command_block(module, ip, port, use_ssl=port in (443, 8443)))

    lines.extend([
        "------------------------------------------------------------",
        " USEFUL MANUAL SEARCHES",
        "------------------------------------------------------------",
        f"  search fiberhome",
        f"  search type:exploit name:<your_vendor>",
        f"  search cve:2024",
        "",
        "After login (if Hydra found creds):",
        "  Open http://TARGET in browser — routers rarely use Metasploit http_login.",
        "  Try discovered paths: /html /menu /cgi-bin (from FFUF/dirsearch output).",
        "============================================================",
    ])

    text = "\n".join(lines)
    cmd_path = os.path.join(target_dir, MSF_COMMANDS_FILE)
    with open(cmd_path, "w", encoding="utf-8") as fh:
        fh.write(text)

    payload = {
        "target": ip,
        "vendor": vendor_label,
        "vendor_matched_modules": bool(modules),
        "exploit_modules": exploits[:15],
        "auxiliary_modules": aux[:10],
        "all_modules": modules[:25],
    }
    json_path = os.path.join(target_dir, MSF_MODULES_JSON)
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)

    print(f"[+] Metasploit command cheat sheet: {cmd_path}")
    return cmd_path


def run_metasploit_recon(ip, target_dir, open_ports, vendor=None):
    if not msf_available():
        print("[*] Metasploit not installed — skipping MSF search/plan.")
        return []

    queries = build_search_queries(open_ports, vendor=vendor)
    if not queries and vendor:
        queries = [vendor.split()[0]]

    print(f"\n[+] Metasploit module search ({len(queries)} queries)...")
    first = True
    for query in queries:
        run_metasploit_search(query, target_dir, append=not first)
        first = False

    search_text = ""
    search_path = os.path.join(target_dir, MSF_SEARCH_FILE)
    if os.path.exists(search_path):
        with open(search_path, "r", encoding="utf-8", errors="ignore") as fh:
            search_text = fh.read()

    modules = parse_msf_modules(search_text)
    if vendor:
        modules = [m for m in modules if vendor_matches_module(vendor, m)]
    if not modules:
        extra = build_fallback_search_queries(vendor=vendor)
        if extra:
            print("[*] No vendor modules yet — retrying vendor-specific searches only...")
            for query in extra:
                run_metasploit_search(query, target_dir, append=True)
            if os.path.exists(search_path):
                with open(search_path, "r", encoding="utf-8", errors="ignore") as fh:
                    search_text = fh.read()
                modules = parse_msf_modules(search_text)
        if vendor:
            modules = [m for m in modules if vendor_matches_module(vendor, m)]
    web_ports = []
    login_ports = []
    for entry in open_ports or []:
        if not isinstance(entry, dict) or not entry.get("port"):
            continue
        port = entry["port"]
        svc = (entry.get("service") or "").lower()
        if port in (80, 443, 8080, 8443) or "http" in svc:
            web_ports.append(port)
        if port in (21, 22, 23) or svc.split()[0] in ("ssh", "ftp", "telnet"):
            login_ports.append(entry)

    generate_msf_exploit_commands(
        ip, target_dir, modules,
        web_ports=web_ports, login_ports=login_ports, vendor=vendor,
    )
    if modules:
        print(f"[+] Parsed {len(modules)} Metasploit module(s) — see {MSF_COMMANDS_FILE}")
    else:
        print("[*] No Metasploit modules matched — manual search may still help.")
    return modules
