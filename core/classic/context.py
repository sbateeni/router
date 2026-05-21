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


def build_url(ip, port):
    return f"http://{ip}:{port}" if port not in [443, 8443] else f"https://{ip}:{port}"


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


def get_web_ports(open_ports):
    ports = []
    for p in open_ports:
        if not isinstance(p, dict) or not p.get("port"):
            continue
        if p["port"] in [80, 443, 8080, 8443] or "http" in p["service"].lower():
            ports.append(p["port"])
    return ports


def get_login_ports(open_ports):
    login = []
    for p in open_ports:
        if not isinstance(p, dict) or not p.get("port"):
            continue
        if p["port"] in [21, 22, 23] or p["service"].lower().split()[0] in ["ssh", "ftp", "telnet"]:
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
