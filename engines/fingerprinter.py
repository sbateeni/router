import re
from urllib.parse import urlparse

import requests

from engines.utils import log


class Fingerprinter:
    def __init__(self, target_url):
        self.target_url = target_url
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        self.model = ""
        self.server = ""

    def identify(self) -> str:
        info = self.identify_details()
        return info["device_type"]

    def _probe_login_page(self, base_url: str) -> str:
        """Many routers redirect via JS — fetch the real login page."""
        parsed = urlparse(base_url)
        host = parsed.netloc or parsed.path.split("/")[0]
        scheme = parsed.scheme or "http"
        base = f"{scheme}://{host}"
        for path in ("/login.htm", "/login.html", "/login.asp", "/doc/page/login.asp"):
            try:
                r = requests.get(
                    base + path, timeout=8, verify=False, headers=self.headers
                )
                if r.status_code == 200 and len(r.text) > 80:
                    title_match = re.search(r"<title>([^<]{1,80})</title>", r.text, re.I)
                    if title_match:
                        self.model = title_match.group(1).strip()
                    return r.text
            except requests.RequestException:
                continue
        return ""

    def identify_details(self) -> dict:
        """Return device_type, model, server banner."""
        log(f"Fingerprinting {self.target_url}...", "INFO")
        device_type = "UNKNOWN"

        try:
            response = requests.get(
                self.target_url, timeout=10, verify=False, headers=self.headers
            )
            content = response.text.lower()
            headers = {k.lower(): v.lower() for k, v in response.headers.items()}
            self.server = headers.get("server", "")

            title_match = re.search(r"<title>([^<]{1,80})</title>", response.text, re.I)
            if title_match:
                self.model = title_match.group(1).strip()

            needs_probe = (
                device_type == "UNKNOWN"
                and (
                    "login.htm" in content
                    or "parent.location" in content
                    or "window.location" in content
                    or self.server == "virtual web 0.9"
                )
            )
            if needs_probe:
                probed = self._probe_login_page(self.target_url)
                if probed:
                    content = probed.lower()

            if any(x in content for x in ["hikvision", "web components", "doc/page/login.asp", "ws-show"]):
                device_type = "HIKVISION"
                model_match = re.search(r"(ds-[\w\-]+)", content, re.I)
                if model_match:
                    self.model = model_match.group(1).upper()
            elif any(x in content for x in ["dahua", "dahua technology", "/web/login", "dvr-login"]):
                device_type = "DAHUA"
            elif any(x in content for x in ["zte", "zxhn", "zxv10", "f460", "f660"]):
                device_type = "ZTE"
            elif "mikrotik" in content or "routeros" in content:
                device_type = "MIKROTIK"
            elif any(x in content for x in ["d-link", "dlink", "dir-"]):
                device_type = "DLINK"
            elif "tp-link" in content or "tplink" in content or "archer" in content:
                device_type = "TPLINK"
            elif "luci" in content or "cgi-bin/luci" in content or "openwrt" in content:
                device_type = "OPENWRT"
            elif "ubnt" in content or "ubiquiti" in content:
                device_type = "UBIQUITI"
            elif "cisco" in content or "cisco" in self.server:
                device_type = "CISCO"
            elif "synology" in content or "diskstation" in content:
                device_type = "SYNOLOGY"
            elif "laravel" in content:
                device_type = "LARAVEL"
            elif "llama.cpp" in content or "llama_cpp" in content or "llama" in self.server:
                device_type = "LLAMA_CPP"
            elif "netis" in content or ("login.cgi" in content and "adsl router login" in content):
                device_type = "NETIS"
                self.model = self.model or "Netis Router"
            elif any(x in content for x in ["net surveillance", "video loss", "login_bg_dvr"]):
                device_type = "GENERIC_DVR"

            if device_type == "UNKNOWN":
                device_type, model_hint = self._deep_probe(self.target_url)
                if model_hint:
                    self.model = model_hint

        except Exception as e:
            log(f"Fingerprinting error: {e}", "ERROR")

        return {
            "device_type": device_type,
            "model": self.model,
            "server": self.server,
        }

    def _deep_probe(self, base_url: str) -> tuple[str, str]:
        """Second-pass detection when root page is a bare redirect."""
        parsed = urlparse(base_url)
        host = parsed.netloc or parsed.path.split("/")[0]
        scheme = parsed.scheme or "http"
        base = f"{scheme}://{host}"

        camera_checks = (
            ("/doc/page/login.asp", ("hikvision", "web components", "login.asp")),
            ("/ISAPI/System/deviceInfo?auth=YWRtaW46MTEK", ("devicetype", "deviceinfo", "hikvision")),
            ("/Security/users?auth=YWRtaW46MTEK", ("userlist", "admin", "operator")),
        )
        for path, markers in camera_checks:
            try:
                r = requests.get(base + path, timeout=8, verify=False, headers=self.headers)
                text = r.text.lower()
                if r.status_code == 200 and any(m in text for m in markers):
                    model = ""
                    model_match = re.search(r"(ds-[\w\-]+)", r.text, re.I)
                    if model_match:
                        model = model_match.group(1).upper()
                    log("Deep probe identified HIKVISION camera/NVR.", "INFO")
                    return "HIKVISION", model
            except requests.RequestException:
                continue

        router_checks = (
            ("/login.htm", ("netis", "adsl router login", "login.cgi")),
            ("/cgi-bin/luci", ("luci", "openwrt")),
        )
        for path, markers in router_checks:
            try:
                r = requests.get(base + path, timeout=8, verify=False, headers=self.headers)
                text = r.text.lower()
                if r.status_code == 200 and any(m in text for m in markers):
                    if "netis" in text or "adsl router login" in text:
                        title_match = re.search(r"<title>([^<]{1,80})</title>", r.text, re.I)
                        model = title_match.group(1).strip() if title_match else "Netis Router"
                        log("Deep probe identified NETIS router.", "INFO")
                        return "NETIS", model
                    if "luci" in text:
                        log("Deep probe identified OPENWRT router.", "INFO")
                        return "OPENWRT", "OpenWrt/LuCI"
            except requests.RequestException:
                continue

        return "UNKNOWN", ""
