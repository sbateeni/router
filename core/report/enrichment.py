import os
import re

from core.report.parsers import (
    count_ffuf_paths,
    detect_connectivity_issues,
    parse_dirsearch_entries,
    parse_ffuf_entries,
    parse_nmap_summary,
    pick_priority_web_targets,
    read_file,
)


def parse_searchsploit_summary(target_dir):
    path = os.path.join(target_dir, "searchsploit.txt")
    text = read_file(path, 30000)
    if not text.strip():
        return {"ran": False, "count": 0, "summary": "SearchSploit did not run or produced no output."}
    titles = re.findall(r"^\s*\d+\s+(.+?)\s+\|\s+", text, re.MULTILINE)
    if "No Results" in text and not titles:
        return {"ran": True, "count": 0, "summary": "SearchSploit ran — no matching exploits in local DB."}
    return {
        "ran": True,
        "count": len(titles),
        "summary": f"SearchSploit: {len(titles)} local exploit(s) listed — verify model/firmware before use.",
        "samples": titles[:8],
    }


def build_recommendations(target_dir, nmap_summary, enrichment):
    recs = []
    ports = nmap_summary.get("ports") or []
    blob = " ".join(p.get("service", "") for p in ports).lower()
    vendor = nmap_summary.get("vendor")

    if enrichment.get("connectivity_issues"):
        recs.append("Re-run SQLMap/Nuclei when target responds to curl (firewall may block after heavy scans).")
        recs.append("Add delay between phases or use: sqlmap ... --random-agent --delay=2")

    if vendor and "fiberhome" in vendor.lower():
        recs.append("Try SearchSploit fiberhome + CVE-2017-15647 webproc traversal (not Metasploit).")
    elif "apache" in blob and "php" in blob:
        recs.append("Focus on discovered .php paths and /txt.txt — test parameters with SQLMap manually.")
        recs.append("SearchSploit: match exact Apache/PHP versions from Nmap, not generic 'router' exploits.")
        recs.append("Skip RouterSploit on generic Apache/PHP hosts — use app-specific testing instead.")

    if enrichment.get("priority_targets"):
        recs.append("Priority URLs for manual review:")
        for url in enrichment["priority_targets"][:6]:
            recs.append(f"  curl -skI {url}")

    if enrichment.get("dirsearch_interesting"):
        recs.append("Interesting Dirsearch hits (status 200):")
        for item in enrichment["dirsearch_interesting"][:8]:
            recs.append(f"  {item['status']} {item['url']} ({item.get('size', '?')})")

    if not recs:
        recs.append("Review RESULTS_SUMMARY.txt tool sections and *_stdout.txt files marked ERROR/WARNING.")

    return recs


def build_scan_enrichment(target_dir, ip=None):
    nmap = parse_nmap_summary(target_dir)
    dir_entries = parse_dirsearch_entries(target_dir)
    ffuf_entries = parse_ffuf_entries(target_dir)
    web_ports = [p["port"] for p in nmap.get("ports", []) if p.get("port") in (80, 443, 8080, 8443) or "http" in str(p.get("service", "")).lower()]
    if not web_ports:
        web_ports = [80]

    interesting = [e for e in dir_entries if e.get("status") == 200]
    interesting.sort(key=lambda x: len(str(x.get("size", ""))), reverse=True)

    priority = pick_priority_web_targets(
        ip or nmap.get("target", ""),
        web_ports,
        [e["url"] for e in dir_entries],
    )

    enrichment = {
        "connectivity_issues": detect_connectivity_issues(target_dir),
        "searchsploit": parse_searchsploit_summary(target_dir),
        "dirsearch_entries": dir_entries[:40],
        "dirsearch_interesting": interesting[:15],
        "ffuf_entries": ffuf_entries[:40],
        "ffuf_paths": count_ffuf_paths(target_dir),
        "priority_targets": priority,
        "target_class": "router" if any(
            x in " ".join(str(p.get("service", "")) for p in nmap.get("ports", [])).lower()
            for x in ("router", "gateway", "modem", "fiberhome")
        ) else "web_server",
    }
    enrichment["recommendations"] = build_recommendations(target_dir, nmap, enrichment)
    return enrichment
