import re

ROUTER_VENDOR_HINTS = (
    "fiberhome", "tp-link", "tplink", "d-link", "dlink", "netgear", "asus",
    "zyxel", "huawei", "zte", "tenda", "linksys", "router", "gateway", "modem", "ont", "cpe",
)
WEB_SERVER_HINTS = ("apache", "nginx", "iis", "httpd", "php", "win32", "microsoft")
VENDOR_NOISE = {
    "telecommunication", "telecommunications", "technologies", "technology",
    "communication", "communications", "corporation", "limited", "company",
}


def _service_blob(open_ports):
    parts = []
    for entry in open_ports or []:
        if isinstance(entry, dict):
            parts.append(str(entry.get("service", "")))
            parts.append(str(entry.get("vendor", "")))
    return " ".join(parts).lower()


def is_likely_router_target(open_ports, vendor=None):
    blob = _service_blob(open_ports)
    if vendor and any(h in vendor.lower() for h in ROUTER_VENDOR_HINTS):
        return True
    if any(h in blob for h in ROUTER_VENDOR_HINTS):
        return True
    for entry in open_ports or []:
        if not isinstance(entry, dict):
            continue
        port = entry.get("port")
        if port in {23, 7547, 8080, 8291}:
            return True
    return False


def should_run_routersploit(open_ports, vendor=None):
    """Skip RouterSploit on obvious generic web stacks (Apache+PHP on Windows)."""
    if is_likely_router_target(open_ports, vendor=vendor):
        return True
    blob = _service_blob(open_ports)
    if "apache" in blob and ("php" in blob or "win32" in blob):
        return False
    if "iis" in blob or "microsoft-iis" in blob:
        return False
    return True


def build_searchsploit_queries(open_ports, vendor=None):
    queries = []
    blob = _service_blob(open_ports)

    if vendor:
        vlower = vendor.lower()
        if "fiberhome" in vlower:
            queries.extend(["fiberhome", "fiberhome router"])
        else:
            first = vendor.split()[0]
            if len(first) > 3 and first.lower() not in VENDOR_NOISE:
                queries.append(first)

    apache_ver = re.search(r"apache\s+httpd\s+([\d.]+)", blob, re.I)
    if apache_ver:
        queries.append(f"apache {apache_ver.group(1)}")
    elif "apache" in blob:
        queries.append("apache")

    php_ver = re.search(r"php[/\s]([\d.]+)", blob, re.I)
    if php_ver:
        queries.append(f"php {php_ver.group(1)}")
    elif "php" in blob:
        queries.append("php")

    openssl_ver = re.search(r"openssl[/\s]([\w.]+)", blob, re.I)
    if openssl_ver:
        queries.append(f"openssl {openssl_ver.group(1)}")

    if "fortinet" in blob:
        queries.append("fortinet")

    for entry in open_ports or []:
        if not isinstance(entry, dict):
            continue
        svc = str(entry.get("service", "")).lower()
        if "fortinet" in svc or "reverse-ssl" in svc:
            queries.append("fortinet")

    return list(dict.fromkeys(q for q in queries if q and len(q) > 2))[:8]
