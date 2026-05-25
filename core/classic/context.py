class ScanContext:
    def __init__(self):
        self.open_ports = []
        self.web_ports = []
        self.login_ports = []
        self.discovered_paths = []
        self.discovered_urls = []
        self.nuclei_findings = []
        self.sqlmap_targets = []
        self.ffuf_candidates = []
        self.gau_urls = []
        self.exploited = False
        self.target_hints = {}
        self.seed_urls = []
        self.login_paths = []


def apply_target_hints(context, hints):
    """Apply user-provided URL/path hints from Telegram or CLI."""
    if not hints:
        return
    context.target_hints = hints
    port = hints.get("port")
    if port and port not in context.web_ports:
        context.web_ports = [port] + [p for p in context.web_ports if p != port]
    seed = hints.get("seed_url")
    if seed:
        context.seed_urls.append(seed)
        context.discovered_urls.append(seed)
        context.discovered_paths.append(seed)
    if hints.get("query_string") and seed and "?" not in seed:
        qurl = f"{seed}?{hints['query_string']}"
        context.discovered_urls.append(qurl)
        context.seed_urls.append(qurl)
    login_path = hints.get("login_path")
    if login_path:
        context.login_paths.append(login_path)


def build_url(ip, port):
    from core.report.parsers import normalize_target_url
    if port in (443, 8443):
        return normalize_target_url(f"https://{ip}:{port}")
    if port == 80:
        return normalize_target_url(f"http://{ip}")
    return normalize_target_url(f"http://{ip}:{port}")


def normalize_url(url):
    return url.rstrip("/")


def extract_query_urls(urls):
    return [u for u in urls if "?" in u]


def extract_service_queries(open_ports):
    queries = set()
    for p in open_ports:
        if not isinstance(p, dict):
            continue
        if p.get("port") == 0:
            vendor = p.get("vendor") or p.get("service")
            if vendor:
                queries.add(vendor.split()[0])
            continue
        svc = p.get("service", "")
        if not svc:
            continue
        parts = svc.split()
        if len(parts) >= 2:
            queries.add(f"{parts[0]} {parts[1]}")
        queries.add(parts[0])
    return list(queries)


def _is_scan_port_entry(p):
    """Real TCP port dict — skip OS (-1) and MAC/vendor (0) metadata rows from Nmap."""
    if not isinstance(p, dict):
        return False
    port = p.get("port")
    return isinstance(port, int) and port > 0


def get_web_ports(open_ports):
    ports = []
    for p in open_ports:
        if not _is_scan_port_entry(p):
            continue
        service = str(p.get("service", "")).lower()
        port = p["port"]
        if port in [80, 443, 8080, 8443] or "http" in service:
            ports.append(port)
    return ports


def get_login_ports(open_ports):
    login = []
    for p in open_ports:
        if not _is_scan_port_entry(p):
            continue
        service = str(p.get("service", "")).lower()
        port = p["port"]
        first = service.split()[0] if service else ""
        if port in [21, 22, 23] or first in ["ssh", "ftp", "telnet"]:
            login.append(p)
    return login


def build_context_from_ports(open_ports):
    context = ScanContext()
    context.open_ports = open_ports or []
    context.web_ports = get_web_ports(context.open_ports)
    context.login_ports = get_login_ports(context.open_ports)
    return context


def should_run_ingram(open_ports):
    camera_services = {"rtsp", "onvif", "dvr", "ipcam", "hikvision", "dahua"}
    for entry in open_ports:
        service = str(entry.get("service", "")).lower()
        port = entry.get("port")
        if port in {554, 37777, 8000, 34567, 9000}:
            return True
        if any(token in service for token in camera_services):
            return True
    return False
