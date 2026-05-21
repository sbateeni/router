import glob
import json
import os
import re
from datetime import datetime

from core.report.analysis import analyze_exploit_status, dedupe_nuclei_findings
from core.report.parsers import (
    count_nuclei_findings,
    find_files,
    read_file,
    significant_nuclei_findings,
    strip_ansi,
)

REPORT_FILENAME = "RESULTS_SUMMARY.txt"
REPORT_JSON = "results_summary.json"

ERROR_PATTERNS = [
    r"traceback",
    r"modulenotfounderror",
    r"error:",
    r"flag provided but not defined",
    r"failed to",
    r"permission denied",
    r"not found at",
    r"is not installed",
    r"skipping due to",
]

SUCCESS_PATTERNS = [
    r"device is vulnerable",
    r"exploit successful",
    r"(?<!\bnot )is vulnerable",
    r"login:\s*\S+\s*password:",
    r"credentials found",
]

TOOL_CHECKS = [
    {
        "name": "Nmap",
        "outputs": ["nmap_scan.txt", "nmap_deep_scan.txt", "recon_summary.json"],
        "findings_if": lambda text: False,
        "ran_if": lambda text: "/tcp" in text and "open" in text.lower(),
    },
    {
        "name": "SearchSploit",
        "outputs": ["searchsploit.txt"],
        "findings_if": lambda text: "no results" not in text.lower() and "shellcodes:" in text.lower() and "exploits:" in text.lower() and len(text.strip()) > 60,
        "ran_if": lambda text: bool(text.strip()),
    },
    {
        "name": "Metasploit Search",
        "outputs": ["msf_search.txt"],
        "findings_if": lambda text: False,
        "ran_if": lambda text: bool(text.strip()) and "no results from search" not in text.lower(),
    },
    {
        "name": "Metasploit Exploit Plan",
        "outputs": ["MSF_EXPLOIT_COMMANDS.txt", "msf_modules.json"],
        "findings_if": lambda text: "use exploit/" in text.lower(),
        "ran_if": lambda text: bool(text.strip()),
    },
    {
        "name": "Dirsearch",
        "outputs": ["dirsearch_port_*_stdout.txt", "dirsearch_port_*.txt"],
        "findings_if": lambda text: False,
        "ran_if": lambda text: "http://" in text or "https://" in text,
    },
    {
        "name": "Nuclei",
        "outputs": ["nuclei_port_*.jsonl", "nuclei_port_*_stdout.txt", "nuclei_port_*.txt"],
        "findings_if": lambda text: "critical" in text.lower() or "high" in text.lower() or "medium" in text.lower(),
        "ran_if": lambda text: "nuclei" in text.lower() or ".jsonl" in text or "scan completed" in text.lower(),
    },
    {
        "name": "FFUF",
        "outputs": ["ffuf_port_*.json", "ffuf_port_*_stdout.txt"],
        "findings_if": lambda text: False,
        "ran_if": lambda text: '"results"' in text and '"url"' in text,
    },
    {
        "name": "GAU",
        "outputs": ["gau_urls.txt"],
        "findings_if": lambda text: False,
        "ran_if": lambda text: text.strip().startswith("http"),
    },
    {
        "name": "SQLMap",
        "outputs": ["sqlmap_scan.txt"],
        "findings_if": lambda text: "is vulnerable" in text.lower(),
        "ran_if": lambda text: "sqlmap" in text.lower() or "target url" in text.lower(),
    },
    {
        "name": "RouterSploit",
        "outputs": ["routersploit_scan.txt"],
        "findings_if": lambda text: "device is vulnerable" in text.lower() or "exploit successful" in text.lower(),
        "ran_if": lambda text: "running module" in text.lower() or "not vulnerable" in text.lower(),
    },
    {
        "name": "Ingram",
        "outputs": ["ingram_scan.txt", "ingram_results/results.csv", "ingram_results/log.txt"],
        "findings_if": lambda text: False,
        "ran_if": lambda text: "running at" in text.lower() or "config is config" in text.lower(),
    },
    {
        "name": "Hydra",
        "outputs": ["hydra_*.txt"],
        "findings_if": lambda text: "login:" in text.lower() and "password:" in text.lower(),
        "ran_if": lambda text: "hydra" in text.lower() or "brute" in text.lower(),
    },
    {
        "name": "Nikto",
        "outputs": ["nikto_port_*.txt", "nikto_port_*_stdout.txt"],
        "findings_if": lambda text: "+ " in text and "OSVDB" in text,
        "ran_if": lambda text: "nikto" in text.lower() or bool(text.strip()),
    },
    {
        "name": "WhatWeb",
        "outputs": ["whatweb_port_*.txt"],
        "findings_if": lambda text: False,
        "ran_if": lambda text: bool(text.strip()),
    },
    {
        "name": "Nmap Vuln Scripts",
        "outputs": ["nmap_vuln_scripts.txt"],
        "findings_if": lambda text: "vulnerable" in text.lower() or "cve-" in text.lower(),
        "ran_if": lambda text: "nmap" in text.lower() and bool(text.strip()),
    },
]


def detect_errors(text):
    cleaned = strip_ansi(text).lower()
    hits = []
    for pattern in ERROR_PATTERNS:
        if re.search(pattern, cleaned, re.IGNORECASE):
            hits.append(pattern)
    return hits


def detect_success(text):
    cleaned = strip_ansi(text).lower()
    if "not vulnerable" in cleaned or "no results" in cleaned:
        return False
    for pattern in SUCCESS_PATTERNS:
        if re.search(pattern, cleaned, re.IGNORECASE):
            return True
    return False


def ingram_has_results(target_dir):
    results_csv = os.path.join(target_dir, "ingram_results", "results.csv")
    try:
        return os.path.exists(results_csv) and os.path.getsize(results_csv) > 0
    except OSError:
        return False


def count_ffuf_paths(target_dir):
    paths = []
    for path in find_files(target_dir, "ffuf_port_*.json"):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                data = json.load(fh)
            for result in data.get("results", []):
                url = result.get("url")
                if url:
                    paths.append(url)
        except (OSError, json.JSONDecodeError):
            continue
    return list(dict.fromkeys(paths))


def parse_nmap_summary(target_dir):
    path = os.path.join(target_dir, "nmap_scan.txt")
    text = read_file(path)
    ports = re.findall(r"^(\d+)/tcp\s+open\s+(.+)$", text, re.MULTILINE)
    vendor = re.search(r"MAC Address:.*\((.+)\)", text)
    return {
        "ports": [{"port": int(p), "service": s.strip()} for p, s in ports],
        "vendor": vendor.group(1).strip() if vendor else None,
    }


def parse_dirsearch_paths(target_dir):
    paths = []
    for path in find_files(target_dir, "dirsearch_port_*.txt"):
        if path.endswith("_stdout.txt"):
            continue
        for line in read_file(path).splitlines():
            line = line.strip()
            if line.startswith("http://") or line.startswith("https://") or line.startswith("/"):
                paths.append(line)
    return list(dict.fromkeys(paths))[:30]


def parse_hydra_hits(target_dir):
    hits = []
    for path in find_files(target_dir, "hydra_*.txt"):
        text = strip_ansi(read_file(path))
        for line in text.splitlines():
            if "login:" in line.lower() and "password:" in line.lower():
                hits.append(line.strip())
    return hits


def assess_tool(target_dir, tool):
    files = []
    for pattern in tool["outputs"]:
        files.extend(find_files(target_dir, pattern))

    if not files:
        return {
            "tool": tool["name"],
            "status": "SKIPPED",
            "files": [],
            "notes": ["No output files found."],
        }

    combined = "\n".join(read_file(path) for path in files)
    errors = detect_errors(combined)
    has_findings = tool.get("findings_if", lambda _t: False)(combined)
    if not has_findings:
        has_findings = detect_success(combined)
    ran_ok = tool.get("ran_if", lambda _t: bool(combined.strip()))(combined)

    if errors and not ran_ok and not has_findings:
        status = "ERROR"
    elif has_findings:
        status = "FINDINGS"
    elif errors:
        status = "WARNING"
    elif ran_ok:
        status = "OK"
    else:
        status = "WARNING"

    notes = []
    if errors:
        notes.append(f"Detected issues: {', '.join(errors[:3])}")
    if has_findings:
        notes.append("Potential successful findings detected.")
    elif ran_ok:
        notes.append("Tool ran successfully.")
    else:
        notes.append("Tool output exists but looks incomplete.")

    return {
        "tool": tool["name"],
        "status": status,
        "files": [os.path.basename(f) for f in files],
        "notes": notes,
    }


def overall_status(tool_results, exploited):
    statuses = [item["status"] for item in tool_results if item["status"] != "SKIPPED"]
    if exploited:
        return "SUCCESS"
    if any(status == "ERROR" for status in statuses):
        return "ISSUES_FOUND"
    if statuses and all(status in {"OK", "WARNING"} for status in statuses):
        return "COMPLETED_CLEAN"
    return "COMPLETED"


def build_report_text(ip, target_dir, selection, exploited, payload):
    lines = [
        "============================================================",
        " ROUTER AUTO-PWN - SCAN RESULTS SUMMARY",
        "============================================================",
        f"Target IP      : {ip}",
        f"Generated At   : {payload['generated_at']}",
        f"Scan Profile   : {payload.get('profile', 'normal')}",
        f"Last Phase     : {payload.get('current_phase', 'Final')}",
        f"Mode Selected  : {payload['mode_label']}",
        f"Overall Status : {payload['overall_status']}",
        f"Exploit Found  : {'YES' if payload.get('confirmed_exploited') else 'NO'}",
        f"Exploit Detail : {payload.get('exploit_label', 'NONE')}",
        f"Report Folder  : {target_dir}",
        "",
        "Context File   : scan_context.json (shared data for all tools)",
        "Recon File     : recon_summary.json (from Nmap)",
        "",
        "------------------------------------------------------------",
        " QUICK OVERVIEW",
        "------------------------------------------------------------",
    ]

    nmap = payload["nmap"]
    if nmap["ports"]:
        lines.append("Open Ports:")
        for entry in nmap["ports"]:
            lines.append(f"  - {entry['port']}/tcp  {entry['service']}")
    else:
        lines.append("Open Ports: none detected")

    if nmap.get("vendor"):
        lines.append(f"Vendor/MAC Info: {nmap['vendor']}")

    nuclei_findings = payload.get("nuclei_deduped") or payload.get("nuclei_findings", [])
    lines.extend([
        "",
        f"Nuclei Findings : {len(nuclei_findings)} unique / {len(payload.get('actionable_nuclei', []))} actionable",
        f"Dirsearch Paths : {len(payload['dirsearch_paths'])}",
        f"FFUF Paths      : {len(payload['ffuf_paths'])}",
        f"Hydra Hits      : {len(payload.get('hydra_hits', []))} (verify manually)",
        "",
        "------------------------------------------------------------",
        " MANUAL VERIFICATION REQUIRED",
        "------------------------------------------------------------",
    ])
    for step in payload.get("manual_verification") or ["No extra manual steps recorded."]:
        lines.append(f"  - {step}")
    lines.append("")

    rsf = payload.get("routersploit") or {}
    lines.extend([
        "------------------------------------------------------------",
        " ROUTERSPLOIT SUMMARY",
        "------------------------------------------------------------",
        f"  {rsf.get('summary', 'No RouterSploit data.')}",
        "",
    ])

    sqlmap = payload.get("sqlmap") or {}
    lines.extend([
        "------------------------------------------------------------",
        " SQLMAP SUMMARY",
        "------------------------------------------------------------",
        f"  {sqlmap.get('summary', 'No SQLMap data.')}",
        "",
        "------------------------------------------------------------",
        " TOOL STATUS",
        "------------------------------------------------------------",
    ])

    for item in payload["tools"]:
        lines.append(f"[{item['status']}] {item['tool']}")
        if item["files"]:
            lines.append(f"  Files: {', '.join(item['files'][:5])}")
        for note in item["notes"]:
            lines.append(f"  Note: {note}")
        lines.append("")

    if payload["nuclei_findings"]:
        lines.extend([
            "------------------------------------------------------------",
            " NUCLEI FINDINGS (deduplicated)",
            "------------------------------------------------------------",
        ])
        for finding in (payload.get("nuclei_deduped") or payload["nuclei_findings"])[:20]:
            lines.append(
                f"  - [{finding['severity']}] {finding['template']} -> {finding['matched_at']}"
            )
        for note in payload.get("nuclei_notes") or []:
            lines.append(f"  * {note}")
        lines.append("")

    if payload.get("hydra_hits"):
        lines.extend([
            "------------------------------------------------------------",
            " CREDENTIALS / HYDRA (unverified until login works)",
            "------------------------------------------------------------",
        ])
        for hit in payload["hydra_hits"]:
            if isinstance(hit, dict):
                flag = " [likely false positive]" if hit.get("likely_false_positive") else ""
                lines.append(f"  - user={hit.get('login')} pass={hit.get('password')}{flag}")
            else:
                lines.append(f"  - {hit}")
        lines.append("")

    msf_cmds = payload.get("msf_commands_preview") or []
    if msf_cmds:
        lines.extend([
            "------------------------------------------------------------",
            " METASPLOIT EXPLOIT COMMANDS (preview)",
            "------------------------------------------------------------",
            "  Full file: MSF_EXPLOIT_COMMANDS.txt",
        ])
        for line in msf_cmds[:40]:
            lines.append(f"  {line}")
        lines.append("")

    if payload.get("dirsearch_paths"):
        lines.extend([
            "------------------------------------------------------------",
            " DISCOVERED PATHS (sample)",
            "------------------------------------------------------------",
        ])
        for path in payload["dirsearch_paths"][:20]:
            lines.append(f"  - {path}")
        lines.append("")

    if payload["ffuf_paths"]:
        lines.extend([
            "------------------------------------------------------------",
            " FFUF PATHS (sample)",
            "------------------------------------------------------------",
        ])
        for path in payload["ffuf_paths"][:20]:
            lines.append(f"  - {path}")
        lines.append("")

    lines.extend([
        "------------------------------------------------------------",
        " ALL FILES IN TARGET FOLDER",
        "------------------------------------------------------------",
    ])
    for rel_path in payload["all_files"]:
        size = payload["file_sizes"].get(rel_path, 0)
        lines.append(f"  - {rel_path} ({size} bytes)")

    lines.extend([
        "",
        "------------------------------------------------------------",
        " HOW TO SHARE WITH SUPPORT",
        "------------------------------------------------------------",
        "Send this file to review scan health:",
        f"  {os.path.join(target_dir, REPORT_FILENAME)}",
        "",
        "If issues exist, also attach the *_stdout.txt files marked ERROR above.",
        "============================================================",
    ])
    return "\n".join(lines)


MODE_LABELS = {
    1: "All tools (classic only)",
    2: "Nmap only",
    3: "Nuclei only",
    4: "Dirsearch only",
    5: "SQLMap only",
    6: "RouterSploit only",
    7: "Ingram only",
    8: "Hydra only",
    9: "FFUF only",
    10: "GAU only",
    11: "AI scan plan only",
    12: "AI Hydra commands only",
    13: "AI RouterSploit + follow-up",
    14: "AI final report only",
    16: "LAN network discovery",
    17: "Nikto only",
    18: "WhatWeb only",
    19: "Nmap vuln scripts only",
    20: "Exit",
}


def list_target_files(target_dir):
    files = []
    sizes = {}
    for root, _, filenames in os.walk(target_dir):
        for name in filenames:
            if name in {REPORT_FILENAME, REPORT_JSON}:
                continue
            full_path = os.path.join(root, name)
            rel_path = os.path.relpath(full_path, target_dir)
            files.append(rel_path)
            try:
                sizes[rel_path] = os.path.getsize(full_path)
            except OSError:
                sizes[rel_path] = 0
    return sorted(files), sizes


def generate_scan_report(ip, target_dir, selection, exploited, current_phase="Final", profile="normal"):
    analysis = analyze_exploit_status(target_dir, runtime_exploited=exploited)
    confirmed_exploited = analysis["confirmed_exploited"]

    tool_results = [assess_tool(target_dir, tool) for tool in TOOL_CHECKS]
    nuclei_findings = count_nuclei_findings(target_dir)
    nuclei_deduped = dedupe_nuclei_findings(nuclei_findings)
    actionable_nuclei = significant_nuclei_findings(nuclei_deduped)

    for item in tool_results:
        if item["tool"] == "Nuclei":
            if actionable_nuclei:
                item["status"] = "FINDINGS"
                item["notes"] = [f"Found {len(actionable_nuclei)} actionable Nuclei result(s)."]
            elif nuclei_deduped:
                item["status"] = "OK"
                item["notes"] = [
                    f"Found {len(nuclei_deduped)} unique informational/low result(s).",
                    "Tool ran successfully.",
                ]
        if item["tool"] == "Hydra":
            if analysis["hydra_hits"]:
                if analysis["hydra_unverified"] and not analysis["hydra_verified_candidates"]:
                    item["status"] = "WARNING"
                    item["notes"] = ["Hydra reported credentials — likely false positive; verify in browser."]
                elif analysis["hydra_verified_candidates"]:
                    item["status"] = "WARNING"
                    item["notes"] = ["Hydra found credentials — manual login verification required."]
                else:
                    item["status"] = "WARNING"
                    item["notes"] = ["Hydra output present — verify manually."]
        if item["tool"] == "Ingram" and ingram_has_results(target_dir):
            item["status"] = "FINDINGS"
            item["notes"].append("Ingram results.csv contains entries.")

    msf_preview = []
    msf_path = os.path.join(target_dir, "MSF_EXPLOIT_COMMANDS.txt")
    if os.path.exists(msf_path):
        msf_preview = read_file(msf_path, 4000).splitlines()[:40]

    all_files, file_sizes = list_target_files(target_dir)

    payload = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": ip,
        "mode": selection,
        "mode_label": MODE_LABELS.get(selection, f"Mode {selection}"),
        "exploited": confirmed_exploited,
        "confirmed_exploited": confirmed_exploited,
        "runtime_exploited": exploited,
        "exploit_label": analysis["exploit_label"],
        "overall_status": overall_status(tool_results, confirmed_exploited),
        "profile": profile,
        "current_phase": current_phase,
        "nmap": parse_nmap_summary(target_dir),
        "tools": tool_results,
        "nuclei_findings": nuclei_findings,
        "nuclei_deduped": nuclei_deduped,
        "actionable_nuclei": actionable_nuclei,
        "nuclei_notes": analysis.get("nuclei_notes", []),
        "dirsearch_paths": parse_dirsearch_paths(target_dir),
        "ffuf_paths": count_ffuf_paths(target_dir),
        "hydra_hits": analysis["hydra_hits"],
        "manual_verification": analysis["manual_verification"],
        "routersploit": analysis["routersploit"],
        "sqlmap": analysis["sqlmap"],
        "msf_commands_preview": msf_preview,
        "all_files": all_files,
        "file_sizes": file_sizes,
    }

    report_path = os.path.join(target_dir, REPORT_FILENAME)
    json_path = os.path.join(target_dir, REPORT_JSON)
    report_text = build_report_text(ip, target_dir, selection, confirmed_exploited, payload)

    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(report_text)

    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)

    return report_path, confirmed_exploited
