import os
import re

from core.report.parsers import (
    count_nuclei_findings,
    find_files,
    read_file,
    significant_nuclei_findings,
    strip_ansi,
)

HYDRA_FALSE_POSITIVE_PASSWORDS = {"root:calvin", "calvin", "password", "123456"}
NUCLEI_NOISE_TEMPLATES = {"waf-detect", "snmpv3-detect", "tls-version", "ssl-issuer", "ssl-dns-names"}


def dedupe_nuclei_findings(findings):
    seen = set()
    unique = []
    for item in findings:
        key = (item.get("template"), item.get("matched_at"), item.get("severity"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def nuclei_noise_notes(findings):
    notes = []
    templates = {f.get("template") for f in findings}
    if "snmpv3-detect" in templates:
        notes.append("snmpv3-detect often false-positive without open UDP/161 — verify with: nmap -sU -p 161 <IP>")
    low_actionable = [f for f in findings if f.get("severity") in ("info", "low")]
    if low_actionable and not significant_nuclei_findings(findings):
        notes.append(f"{len(low_actionable)} informational/low Nuclei hits — not treated as confirmed exploits.")
    return notes


def parse_hydra_credential(line):
    text = strip_ansi(line)
    login_match = re.search(r"login:\s*(\S+)", text, re.I)
    pass_match = re.search(r"password:\s*(.+?)(?:\s*$|\s+\[)", text, re.I)
    if not login_match or not pass_match:
        return None
    return {
        "raw": text.strip(),
        "login": login_match.group(1).strip(),
        "password": pass_match.group(1).strip(),
        "likely_false_positive": pass_match.group(1).strip().lower() in HYDRA_FALSE_POSITIVE_PASSWORDS
            or ":" in pass_match.group(1),
    }


def parse_hydra_hits_detailed(target_dir):
    hits = []
    for path in find_files(target_dir, "hydra_*.txt"):
        for line in read_file(path).splitlines():
            if "login:" not in line.lower() or "password:" not in line.lower():
                continue
            parsed = parse_hydra_credential(line)
            if parsed:
                hits.append(parsed)
    return hits


def parse_routersploit_summary(target_dir):
    path = os.path.join(target_dir, "routersploit_scan.txt")
    text = read_file(path, 20000)
    if not text.strip():
        return {"ran": False, "vulnerable": False, "summary": "RouterSploit did not run or produced no output."}

    lowered = text.lower()
    vulnerable = "device is vulnerable" in lowered or "exploit successful" in lowered
    modules_tried = re.findall(r"Running module '([^']+)'", text, re.I)
    not_vulnerable = len(re.findall(r"not vulnerable", lowered))
    unverified = len(re.findall(r"could not be verified", lowered))

    summary = f"AutoPwn modules tried: {len(modules_tried)} | not vulnerable: {not_vulnerable} | unverified: {unverified}"
    if vulnerable:
        summary = "RouterSploit reported the device as VULNERABLE."
    elif modules_tried:
        summary = f"No confirmed RouterSploit exploit. {summary}"

    return {
        "ran": True,
        "vulnerable": vulnerable,
        "modules_tried": len(modules_tried),
        "summary": summary,
    }


def parse_sqlmap_summary(target_dir):
    text = read_file(os.path.join(target_dir, "sqlmap_scan.txt"))
    if not text.strip():
        return {"ran": False, "vulnerable": False, "summary": "SQLMap did not run."}
    vulnerable = "is vulnerable" in text.lower()
    return {
        "ran": True,
        "vulnerable": vulnerable,
        "summary": "SQL injection confirmed." if vulnerable else "No SQL injection confirmed.",
    }


def analyze_exploit_status(target_dir, runtime_exploited=False):
    nuclei = dedupe_nuclei_findings(count_nuclei_findings(target_dir))
    actionable_nuclei = significant_nuclei_findings(nuclei)
    hydra_hits = parse_hydra_hits_detailed(target_dir)
    rsf = parse_routersploit_summary(target_dir)
    sqlmap = parse_sqlmap_summary(target_dir)

    verified_hydra = [h for h in hydra_hits if not h.get("likely_false_positive")]
    unverified_hydra = [h for h in hydra_hits if h.get("likely_false_positive")]

    confirmed = bool(
        rsf.get("vulnerable")
        or sqlmap.get("vulnerable")
        or actionable_nuclei
    )

    manual_steps = []
    if hydra_hits:
        manual_steps.append("Verify Hydra credentials manually in the router web UI before treating them as valid.")
        for hit in hydra_hits:
            manual_steps.append(f"  Try: user={hit['login']} pass={hit['password']} (http://TARGET or https://TARGET)")
    if unverified_hydra:
        manual_steps.append("Some Hydra hits look like false positives (e.g. root:calvin on http-get) — confirm in browser.")
    nuclei_notes = nuclei_noise_notes(nuclei) if nuclei else []
    if nuclei_notes:
        manual_steps.extend(nuclei_notes)
    manual_steps.append("Review MSF_EXPLOIT_COMMANDS.txt for Metasploit exploit/auxiliary commands.")

    return {
        "confirmed_exploited": confirmed,
        "runtime_exploited": runtime_exploited,
        "hydra_hits": hydra_hits,
        "hydra_verified_candidates": verified_hydra,
        "hydra_unverified": unverified_hydra,
        "routersploit": rsf,
        "sqlmap": sqlmap,
        "nuclei_deduped": nuclei,
        "actionable_nuclei": actionable_nuclei,
        "nuclei_notes": nuclei_notes,
        "manual_verification": manual_steps,
        "exploit_label": "CONFIRMED" if confirmed else ("UNVERIFIED (Hydra/creds only)" if hydra_hits else "NONE"),
    }
