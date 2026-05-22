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


def is_plausible_target_url(url):
    """Reject dirsearch metadata lines mistaken for paths."""
    if not url or not isinstance(url, str):
        return False
    lower = url.lower().strip()
    if not (lower.startswith("http://") or lower.startswith("https://")):
        return False
    junk_markers = (
        "extensions:", "http method:", "threads:", "wordlist size:",
        "started:", "finished:", "task completed",
    )
    if any(marker in lower for marker in junk_markers):
        return False
    if "|" in url and ".php" not in lower and "?" not in url:
        return False
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if not parsed.hostname:
        return False
    if " " in (parsed.path or ""):
        return False
    return True


def path_from_login_reference(login_ref):
    """Accept /login.cgi or http://host/login.cgi → path only."""
    ref = (login_ref or "").strip()
    if not ref:
        return "/"
    if ref.startswith("http://") or ref.startswith("https://"):
        parsed = urlparse(ref)
        return parsed.path or "/"
    return ref if ref.startswith("/") else f"/{ref}"


def hydra_form_for_path(login_path):
    path = path_from_login_reference(login_path)
    return f"{path}:user=^USER^&pass=^PASS^:F=invalid"


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
            if not is_plausible_target_url(url):
                continue
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
            if url not in seen and is_plausible_target_url(url):
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


IP_ONLY_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*\.?$"
)


def is_valid_ip(value):
    return bool(value and IP_ONLY_RE.match(value))


def is_valid_hostname(value):
    if not value or len(value) > 253:
        return False
    if value.endswith("."):
        value = value[:-1]
    if not HOSTNAME_RE.match(value):
        return False
    return all(len(label) <= 63 for label in value.split("."))


def resolve_host_ip(host):
    """Resolve domain to IP (best effort). Returns None if already IP or resolution fails."""
    if is_valid_ip(host):
        return host
    try:
        import socket
        return socket.gethostbyname(host)
    except OSError:
        return None


def sanitize_target_dir_name(host):
    name = (host or "unknown").strip().lower()
    name = name.replace(":", "_")
    return name[:120] or "unknown"


def _build_target_record(host, port, scheme, path, query, raw):
    login_path = path if path not in ("", "/") else None
    netloc = host if port in (80, 443) and (
        (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    ) else f"{host}:{port}"
    seed = urlunparse((scheme, netloc, path or "/", "", query or "", ""))
    seed = normalize_target_url(seed) if not query else seed.rstrip("/") if path == "/" and not query else seed

    resolved = resolve_host_ip(host)
    return {
        "host": host,
        "ip": host,
        "resolved_ip": resolved if resolved and resolved != host else (host if is_valid_ip(host) else None),
        "is_domain": is_valid_hostname(host) and not is_valid_ip(host),
        "port": port,
        "scheme": scheme,
        "login_path": login_path,
        "query_string": query or None,
        "seed_url": seed,
        "raw": raw,
        "target_dir_name": sanitize_target_dir_name(host),
    }


def parse_target_input(text):
    """
    Accept IP, domain, path, full URL — query strings preserved for SQLMap.
    """
    raw = (text or "").strip()
    if not raw or raw.startswith("/"):
        return None

    if raw.startswith("http://") or raw.startswith("https://"):
        parsed = urlparse(raw)
        host = parsed.hostname
        if not host or not (is_valid_ip(host) or is_valid_hostname(host)):
            return None
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        return _build_target_record(host, port, parsed.scheme, path, parsed.query, raw)

    if "/" in raw or "?" in raw:
        host_part = raw.split("/", 1)[0].split("?", 1)[0]
        if not (is_valid_ip(host_part) or is_valid_hostname(host_part)):
            return None
        if "?" in raw and "/" not in raw.split("?", 1)[0]:
            path = "/"
            query = raw.split("?", 1)[1]
        elif "/" in raw:
            rest = raw.split("/", 1)[1]
            if "?" in rest:
                path_part, query = rest.split("?", 1)
                path = "/" + path_part
            else:
                path = "/" + rest
                query = ""
        else:
            path = "/"
            query = raw.split("?", 1)[1]
        return _build_target_record(host_part, 80, "http", path, query, raw)

    if is_valid_ip(raw) or is_valid_hostname(raw):
        return _build_target_record(raw, 80, "http", "/", "", raw)
    return None


def target_scan_host(parsed):
    """Host string for nmap/tools (IP or domain)."""
    if not parsed:
        return None
    return parsed.get("host") or parsed.get("ip")


def target_workspace_name(parsed, fallback=None):
    if parsed and parsed.get("target_dir_name"):
        return parsed["target_dir_name"]
    return sanitize_target_dir_name(fallback or "unknown")


def save_target_hints(target_dir, hints):
    if not hints:
        return None
    path = os.path.join(target_dir, "target_hints.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(hints, fh, indent=2, ensure_ascii=False)
    return path


def load_target_hints(target_dir):
    path = os.path.join(target_dir, "target_hints.json")
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


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
                base = os.path.basename(path).replace(".jsonl", "")
                alt = os.path.join(target_dir, f"{base}_notags.jsonl")
                if not os.path.exists(alt) or os.path.getsize(alt) == 0:
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
        url = normalize_target_url(url)
        if is_plausible_target_url(url):
            candidates.append(url)
    priority = []
    for url in dict.fromkeys(candidates):
        lower = url.lower()
        if "?" in lower:
            priority.insert(0, url)
            continue
        if any(x in lower for x in (".php", "api", "login", "admin", "cgi")):
            priority.append(url)
        elif lower.endswith(".txt") and "txt.txt" in lower:
            priority.append(url)
    if not priority:
        priority = candidates[:3]
    return priority[:limit]
