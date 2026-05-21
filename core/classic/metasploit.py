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


def build_search_queries(open_ports, vendor=None):
    queries = []
    if vendor:
        for token in re.split(r"[\s,]+", vendor):
            token = token.strip()
            if len(token) > 3 and token.lower() not in GENERIC_SKIP:
                queries.append(token)
        if "fiberhome" in vendor.lower():
            queries.extend(["fiberhome", "fiberhome router"])

    for entry in open_ports or []:
        if not isinstance(entry, dict):
            continue
        svc = (entry.get("service") or "").lower()
        for token in svc.split():
            if len(token) > 3 and token not in GENERIC_SKIP:
                queries.append(token)

    return list(dict.fromkeys(queries))[:8]


def _default_port(module, web_ports, login_ports):
    mod = module.lower()
    if "ssh" in mod and login_ports:
        return login_ports[0].get("port", 22)
    if "ssl" in mod or "https" in mod:
        return 443 if 443 in web_ports else (web_ports[0] if web_ports else 443)
    if "http" in mod or "web" in mod:
        return 80 if 80 in web_ports else (web_ports[0] if web_ports else 80)
    return web_ports[0] if web_ports else 80


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


def generate_msf_exploit_commands(ip, target_dir, modules, web_ports=None, login_ports=None):
    web_ports = web_ports or [80, 443]
    login_ports = login_ports or []
    exploits = [m for m in modules if m.startswith("exploit/")]
    aux = [m for m in modules if m.startswith("auxiliary/")]

    lines = [
        "============================================================",
        " METASPLOIT — suggested commands (review before running)",
        "============================================================",
        f"Target IP: {ip}",
        f"Web ports: {', '.join(str(p) for p in web_ports)}",
        "",
        "Run interactively:",
        "  msfconsole -q",
        "",
        "Or run one module:",
        "  msfconsole -q -x \"use exploit/...; set RHOSTS IP; set RPORT 80; check; run; exit\"",
        "",
        "------------------------------------------------------------",
        " EXPLOIT MODULES (higher priority)",
        "------------------------------------------------------------",
    ]

    if not exploits and not aux:
        lines.append("No Metasploit modules parsed from msf_search.txt.")
        lines.append("Run searches manually: search fiberhome | search router")
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
        f"  search type:exploit name:router",
        f"  search cve:2024",
        "",
        "After login (if Hydra found creds):",
        f"  use auxiliary/admin/http/tomcat_administration",
        f"  set RHOSTS {ip}",
        "============================================================",
    ])

    text = "\n".join(lines)
    cmd_path = os.path.join(target_dir, MSF_COMMANDS_FILE)
    with open(cmd_path, "w", encoding="utf-8") as fh:
        fh.write(text)

    payload = {
        "target": ip,
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

    generate_msf_exploit_commands(ip, target_dir, modules, web_ports=web_ports, login_ports=login_ports)
    if modules:
        print(f"[+] Parsed {len(modules)} Metasploit module(s) — see {MSF_COMMANDS_FILE}")
    else:
        print("[*] No Metasploit modules matched — manual search may still help.")
    return modules
