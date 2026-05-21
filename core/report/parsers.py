import glob
import json
import os
import re
from urllib.parse import urlparse, urlunparse

URL_IN_TEXT_RE = re.compile(r"https?://[^\s\)\]]+")
DIRSEARCH_LINE_RE = re.compile(
    r"^(?P<status>\d{3})\s+(?P<size>[\d.]+\w?)\s+(?P<url>https?://\S+)",
    re.MULTILINE,
)


def read_file(path, max_chars=12000):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read(max_chars)
    except OSError:
        return ""


def strip_ansi(text):
    return re.sub(r"\x1b\[[0-9;]*m", "", text or "")


def find_files(target_dir, pattern):
    return sorted(glob.glob(os.path.join(target_dir, pattern)))


def significant_nuclei_findings(findings):
    significant = {"critical", "high", "medium"}
    return [item for item in findings if str(item.get("severity", "unknown")).lower() in significant]


def count_nuclei_findings(target_dir):
    findings = []
    for path in find_files(target_dir, "nuclei_port_*.jsonl"):
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    item = json.loads(line)
                    info = item.get("info", {})
                    findings.append({
                        "template": item.get("template-id", "unknown"),
                        "severity": info.get("severity", "unknown"),
                        "matched_at": item.get("matched-at", ""),
                        "file": os.path.basename(path),
                    })
                except json.JSONDecodeError:
                    continue
    return findings


def normalize_target_url(url):
    """Use http://IP/ not http://IP:80/ — avoids some tools failing on explicit :80."""
    if not url:
        return url
    parsed = urlparse(url if "://" in url else f"http://{url}")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if (parsed.scheme == "http" and port == 80) or (parsed.scheme == "https" and port == 443):
        netloc = parsed.hostname or ""
    else:
        netloc = f"{parsed.hostname}:{port}"
    return urlunparse((parsed.scheme, netloc, parsed.path or "", parsed.params, parsed.query, parsed.fragment))


def extract_urls_from_text(text):
    return list(dict.fromkeys(URL_IN_TEXT_RE.findall(text or "")))


def parse_dirsearch_entries(target_dir):
    """Parse dirsearch log lines: '200  12KB http://host/path'."""
    entries = []
    seen = set()
    for path in find_files(target_dir, "dirsearch_port_*.txt"):
        if path.endswith("_stdout.txt"):
            continue
        text = read_file(path, 50000)
        for match in DIRSEARCH_LINE_RE.finditer(text):
            url = match.group("url").rstrip(")")
            key = url
            if key in seen:
                continue
            seen.add(key)
            entries.append({
                "url": url,
                "status": int(match.group("status")),
                "size": match.group("size"),
            })
        for url in extract_urls_from_text(text):
            if url not in seen:
                seen.add(url)
                entries.append({"url": url, "status": None, "size": None})
    return entries


def parse_dirsearch_paths(target_dir):
    return [e["url"] for e in parse_dirsearch_entries(target_dir)]


def parse_ffuf_entries(target_dir):
    entries = []
    seen = set()
    for path in find_files(target_dir, "ffuf_port_*.json"):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        base = ""
        m = re.search(r"ffuf_port_(\d+)", os.path.basename(path))
        if m:
            port = int(m.group(1))
            scheme = "https" if port in (443, 8443) else "http"
            host_match = re.search(r"targets[/\\]([^/\\]+)", path.replace("\\", "/"))
            if host_match:
                base = f"{scheme}://{host_match.group(1)}"
        for result in data.get("results", []):
            url = result.get("url")
            status = result.get("status")
            length = result.get("length")
            if not url:
                fuzz = result.get("input", {}).get("FUZZ") if isinstance(result.get("input"), dict) else None
                if fuzz and base:
                    url = f"{base.rstrip('/')}/{str(fuzz).lstrip('/')}"
            if not url or url in seen:
                continue
            seen.add(url)
            entries.append({"url": url, "status": status, "length": length})
    return entries


def count_ffuf_paths(target_dir):
    return [e["url"] for e in parse_ffuf_entries(target_dir)]


def parse_nmap_summary(target_dir):
    path = os.path.join(target_dir, "nmap_scan.txt")
    text = read_file(path)
    ports = re.findall(r"^(\d+)/tcp\s+open\s+(.+)$", text, re.MULTILINE)
    vendor = re.search(r"MAC Address:.*\((.+)\)", text)
    return {
        "ports": [{"port": int(p), "service": s.strip()} for p, s in ports],
        "vendor": vendor.group(1).strip() if vendor else None,
    }


def detect_connectivity_issues(target_dir):
    issues = []
    patterns = (
        ("sqlmap_scan.txt", "no route to host", "SQLMap lost connectivity (target may have rate-limited or blocked scans)."),
        ("sqlmap_scan.txt", "unable to connect", "SQLMap could not connect — results are inconclusive, not a clean negative."),
        ("nuclei_port_80_stdout.txt", "no route to host", "Nuclei skipped target as unreachable."),
        ("nuclei_port_443_stdout.txt", "no route to host", "Nuclei skipped target as unreachable."),
    )
    for filename, needle, message in patterns:
        path = os.path.join(target_dir, filename)
        if not os.path.exists(path):
            continue
        text = read_file(path, 8000).lower()
        if needle in text:
            issues.append(message)

    for path in find_files(target_dir, "nuclei_port_*.jsonl"):
        try:
            if os.path.getsize(path) == 0:
                issues.append(f"{os.path.basename(path)} is empty — Nuclei may have failed or found nothing.")
        except OSError:
            pass
    return list(dict.fromkeys(issues))


def pick_priority_web_targets(ip, web_ports, discovered_paths=None, limit=12):
    """URLs worth manual/sqlmap review: PHP, API, large 200 responses."""
    discovered_paths = discovered_paths or []
    candidates = []
    for port in web_ports or [80]:
        candidates.append(normalize_target_url(f"http://{ip}" if port == 80 else f"https://{ip}" if port == 443 else f"http://{ip}:{port}"))
    for raw in discovered_paths:
        url = raw if str(raw).startswith("http") else f"http://{ip}/{str(raw).lstrip('/')}"
        candidates.append(normalize_target_url(url))
    priority = []
    for url in dict.fromkeys(candidates):
        lower = url.lower()
        if "?" in lower or any(x in lower for x in (".php", "api", "login", "admin", "cgi")):
            priority.append(url)
        elif lower.endswith(".txt") and "txt.txt" in lower:
            priority.append(url)
    if not priority:
        priority = candidates[:3]
    return priority[:limit]
