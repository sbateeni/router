"""IoT recon — full high/medium priority stack (every IP passes through all tools)."""

from __future__ import annotations

import glob
import json
import os
import re
import shutil
import socket
import urllib.error
import urllib.request
from typing import Any

from core.utils import PYTHON, TOOLS_DIR, run_cmd

SSDP_MCAST = ("239.255.255.250", 1900)
MSEARCH_ALL = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 2\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
)
MSEARCH_IGD = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 2\r\n"
    "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
    "\r\n"
)

CRED_SCANNERS = (("changeme", "changeme/changeme.py"),)


def _save_json(path: str, data: Any) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)


def _parse_ssdp_responses(raw: str) -> list[dict]:
    devices: list[dict] = []
    seen: set[str] = set()
    for block in re.split(r"\r?\n\r?\n", raw):
        if "200 OK" not in block and "NOTIFY" not in block.upper():
            continue
        loc = re.search(r"(?im)^location:\s*(.+)$", block)
        server = re.search(r"(?im)^server:\s*(.+)$", block)
        usn = re.search(r"(?im)^usn:\s*(.+)$", block)
        st = re.search(r"(?im)^st:\s*(.+)$", block)
        if not loc:
            continue
        url = loc.group(1).strip()
        if url in seen:
            continue
        seen.add(url)
        devices.append({
            "location": url,
            "server": server.group(1).strip() if server else "",
            "usn": usn.group(1).strip() if usn else "",
            "st": st.group(1).strip() if st else "",
        })
    return devices


def _ssdp_probe(payload: str, target_ip: str | None, timeout: float) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.settimeout(timeout)
        if target_ip:
            try:
                sock.sendto(payload.encode(), (target_ip, 1900))
            except OSError:
                pass
        else:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.sendto(payload.encode(), SSDP_MCAST)
        chunks: list[str] = []
        deadline = timeout
        while deadline > 0:
            try:
                data, _addr = sock.recvfrom(8192)
                chunks.append(data.decode("utf-8", errors="ignore"))
            except socket.timeout:
                break
            deadline -= 0.5
        return "\n\n".join(chunks)
    finally:
        sock.close()


def _parse_cred_output(output: str, source: str) -> list[dict]:
    hits: list[dict] = []
    for line in (output or "").splitlines():
        lower = line.lower()
        if not any(k in lower for k in ("success", "found credential", "valid", "login:", "password")):
            continue
        entry: dict[str, Any] = {"source": source, "raw": line.strip()}
        m = re.search(r"login:\s*(\S+).*password:\s*(.+?)(?:\s+\[|$)", line, re.I)
        if m:
            entry["login"] = m.group(1)
            entry["password"] = m.group(2).strip()
        elif re.search(r"(\S+):(\S+)", line) and "http" not in lower:
            m2 = re.search(r"(\S+):(\S+)", line)
            if m2 and len(m2.group(1)) < 40:
                entry["login"] = m2.group(1)
                entry["password"] = m2.group(2)
        hits.append(entry)
    return hits


def _protocols_for_ports(open_ports: list | None) -> list[str]:
    protocols = ["http", "https", "ssh", "telnet", "ftp", "snmp", "rtsp"]
    if not open_ports:
        return protocols
    port_nums = set()
    for p in open_ports:
        if isinstance(p, dict):
            port_nums.add(p.get("port"))
        elif isinstance(p, int):
            port_nums.add(p)
    if 554 in port_nums or 8554 in port_nums:
        protocols.append("rtsp")
    if 1883 in port_nums:
        protocols.append("mqtt")
    return list(dict.fromkeys(protocols))


def run_nuclei_template_refresh(target_dir: str) -> bool:
    """Refresh official Nuclei templates (router CVE templates incl. CVE-2024-9643)."""
    print("\n[+] Nuclei — updating templates...")
    try:
        from core.web.nuclei import update_nuclei_templates

        ok = update_nuclei_templates()
        log = os.path.join(target_dir, "nuclei_template_update.txt")
        with open(log, "w", encoding="utf-8") as fh:
            fh.write("ok\n" if ok else "failed or skipped\n")
        return ok
    except Exception as exc:
        print(f"[!] Nuclei template update: {exc}")
        return False


def run_upnp_discovery(ip: str, target_dir: str) -> list[dict]:
    """SSDP/UPnP — built-in UDP + upnpfuzz + optional upnp_info script."""
    print("\n[+] UPnP/SSDP discovery...")
    out_path = os.path.join(target_dir, "UPNP_DISCOVERY.json")
    devices: list[dict] = []

    try:
        raw = _ssdp_probe(MSEARCH_IGD, ip, 4.0)
        raw += "\n\n" + _ssdp_probe(MSEARCH_ALL, ip, 3.0)
        devices = _parse_ssdp_responses(raw)
    except OSError as exc:
        print(f"[!] SSDP probe: {exc}")

    _enrich_upnp_devices(devices, target_dir)

    if shutil.which("upnpfuzz"):
        log_file = os.path.join(target_dir, "upnpfuzz_discover.txt")
        cmd = ["upnpfuzz", "--ssdp", f"{ip}:1900", "--raw"]
        ok, output = run_cmd(cmd, capture=True, log_file=log_file)
        for line in (output or "").splitlines():
            m = re.search(r"(https?://\S+)", line)
            if m:
                url = m.group(1).rstrip(")")
                if not any(d.get("location") == url for d in devices):
                    devices.append({"location": url, "source": "upnpfuzz", "raw": line.strip()})

    _save_json(out_path, {"target": ip, "devices": devices})
    if devices:
        print(f"[+] UPnP: {len(devices)} device(s)")
        for d in devices[:5]:
            print(f"    → {d.get('location', '?')}")
    else:
        print("[*] UPnP: no SSDP responses")
    return devices


def _run_cred_scanner(name: str, script_rel: str, ip: str, target_dir: str, protocols: list[str]) -> list[dict]:
    script = os.path.join(TOOLS_DIR, script_rel)
    if not os.path.isfile(script):
        return []
    print(f"\n[+] {name} — default/backdoor credentials...")
    log_file = os.path.join(target_dir, f"{name.replace(' ', '_')}_scan.txt")
    cmd = [PYTHON, script, ip, "--timeout", "8", "--protocols", ",".join(protocols)]
    ok, output = run_cmd(cmd, capture=True, log_file=log_file)
    hits = _parse_cred_output(output, name)
    if hits:
        print(f"[+] {name}: {len(hits)} hit(s)")
    else:
        print(f"[*] {name}: no hits")
    return hits


def _run_default_hunter(ip: str, target_dir: str, protocols: list[str]) -> list[dict]:
    """SySS Default-Hunter (modern changeme fork) — CLI or python -m."""
    print("\n[+] Default-Hunter — extended default/backdoor creds...")
    log_file = os.path.join(target_dir, "default-hunter_scan.txt")
    proto = ",".join(protocols)
    attempts: list[list[str]] = []
    cli = shutil.which("default-hunter")
    if cli:
        attempts.append([cli, ip, "--timeout", "8", "--protocols", proto])
    attempts.append([PYTHON, "-m", "default_hunter", ip, "--timeout", "8", "--protocols", proto])
    dh_main = os.path.join(TOOLS_DIR, "default-hunter", "src", "default_hunter", "__main__.py")
    if os.path.isfile(dh_main):
        attempts.append([PYTHON, dh_main, ip, "--timeout", "8", "--protocols", proto])

    output = ""
    for cmd in attempts:
        ok, output = run_cmd(cmd, capture=True, log_file=log_file)
        if output and "no module named" not in output.lower():
            break

    hits = _parse_cred_output(output, "default-hunter")
    if hits:
        print(f"[+] Default-Hunter: {len(hits)} hit(s)")
    else:
        print("[*] Default-Hunter: no hits (install via install_tools.sh)")
    return hits


def _enrich_upnp_devices(devices: list[dict], target_dir: str) -> None:
    """Fetch UPnP device description XML from discovered Location URLs."""
    log_file = os.path.join(target_dir, "upnp_device_descriptions.txt")
    lines: list[str] = []
    for dev in devices:
        url = dev.get("location") or ""
        if not url.startswith("http"):
            continue
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "AUTO-PWN-UPnP/1.0"})
            with urllib.request.urlopen(req, timeout=6) as resp:
                body = resp.read(12000).decode("utf-8", errors="ignore")
            lines.append(f"=== {url} ===\n{body[:2000]}")
            for tag in ("friendlyName", "manufacturer", "modelName", "modelNumber"):
                m = re.search(rf"<{tag}>([^<]+)</{tag}>", body, re.I)
                if m:
                    dev[tag.lower()] = m.group(1).strip()
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            lines.append(f"=== {url} === ERROR: {exc}")
    if lines:
        with open(log_file, "w", encoding="utf-8") as fh:
            fh.write("\n\n".join(lines))


def run_changeme_only(ip: str, target_dir: str, open_ports: list | None = None) -> list[dict]:
    protocols = _protocols_for_ports(open_ports)
    hits: list[dict] = []
    for name, rel in CRED_SCANNERS:
        hits.extend(_run_cred_scanner(name, rel, ip, target_dir, protocols))
    return hits


def run_all_default_cred_scans(ip: str, target_dir: str, open_ports: list | None = None) -> list[dict]:
    """changeme + Default-Hunter (sequential fallback)."""
    all_hits = run_changeme_only(ip, target_dir, open_ports)
    all_hits.extend(_run_default_hunter(ip, target_dir, _protocols_for_ports(open_ports)))
    _save_json(os.path.join(target_dir, "CHANGEME_HITS.json"), all_hits)
    _save_json(os.path.join(target_dir, "IOT_DEFAULT_CREDS.json"), all_hits)
    return all_hits


def _merge_and_save_default_creds(target_dir: str, *hit_lists) -> list[dict]:
    merged: list[dict] = []
    seen: set[str] = set()
    for hits in hit_lists:
        for h in hits or []:
            key = str(h)
            if key in seen:
                continue
            seen.add(key)
            merged.append(h)
    _save_json(os.path.join(target_dir, "CHANGEME_HITS.json"), merged)
    _save_json(os.path.join(target_dir, "IOT_DEFAULT_CREDS.json"), merged)
    return merged


def _genzai_cmd(url: str) -> list[list[str]]:
    base = url.rstrip("/")
    return [
        ["genzai", "scan", "-u", base],
        ["genzai", "scan", base],
        ["genzai", "-u", base],
        ["genzai", base],
    ]


def run_genzai_scan(ip: str, target_dir: str, web_ports: list | None = None) -> dict:
    """Genzai — IoT dashboard fingerprint + vendor default passwords."""
    if not shutil.which("genzai"):
        print("[*] Genzai not in PATH — install via install_tools.sh / docs/TOOLS.md")
        return {}

    ports = web_ports or [80, 443, 8080, 8000, 8443]
    print("\n[+] Genzai — IoT dashboard fingerprint...")
    results: dict[str, Any] = {"findings": []}

    for port in ports[:8]:
        finding = run_genzai_single_port(ip, target_dir, port)
        if finding:
            results["findings"].append(finding)

    _save_json(os.path.join(target_dir, "GENZAI_RESULTS.json"), results)
    print(f"[*] Genzai: {len(results['findings'])} URL(s) scanned")
    return results


def run_genzai_single_port(ip: str, target_dir: str, port: int) -> dict | None:
    """Scan one web port with Genzai; returns finding dict or None."""
    if not shutil.which("genzai"):
        return None
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{ip}" if port in (80, 443) else f"{scheme}://{ip}:{port}"
    log_file = os.path.join(target_dir, f"genzai_port_{port}.txt")
    output = ""
    for cmd in _genzai_cmd(url):
        ok, output = run_cmd(cmd, capture=True, log_file=log_file, timeout=90)
        if output and "not found" not in output.lower() and "error" not in output.lower()[:80]:
            break
    if output:
        return {"url": url, "output": output[:4000]}
    return None


def merge_genzai_port_results(target_dir: str) -> dict:
    """Merge genzai_port_*.txt logs into GENZAI_RESULTS.json after parallel jobs."""
    findings: list[dict] = []
    for path in glob.glob(os.path.join(target_dir, "genzai_port_*.txt")):
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                body = fh.read().strip()
            if body and "not found" not in body.lower()[:80]:
                port = re.search(r"genzai_port_(\d+)\.txt", os.path.basename(path))
                findings.append({"port": int(port.group(1)) if port else 0, "output": body[:4000]})
        except OSError:
            pass
    results = {"findings": findings}
    _save_json(os.path.join(target_dir, "GENZAI_RESULTS.json"), results)
    return results


def iot_wordlist_paths() -> dict[str, str]:
    base = os.path.join(TOOLS_DIR, "jeanphorn-wordlist")
    return {
        "iot_txt": os.path.join(base, "passwords", "iot.txt"),
        "iot_json": os.path.join(base, "defaults", "iot.json"),
        "routers_json": os.path.join(base, "defaults", "routers.json"),
        "ip_cameras_json": os.path.join(base, "defaults", "ip_cameras.json"),
        "nas_json": os.path.join(base, "defaults", "nas.json"),
        "databases_json": os.path.join(base, "defaults", "databases.json"),
    }


def build_iot_hydra_wordlists(target_dir: str) -> dict[str, str | None]:
    """jeanphorn IoT + router + camera + NAS defaults → Hydra wordlists."""
    paths = iot_wordlist_paths()
    out: dict[str, str | None] = {"passwords": None, "combos": None}

    pwd_out = os.path.join(target_dir, "hydra_iot_passwords.txt")
    combo_out = os.path.join(target_dir, "hydra_iot_combos.txt")
    passwords: list[str] = []
    combos: list[str] = []
    seen_p: set[str] = set()
    seen_c: set[str] = set()

    if os.path.isfile(paths["iot_txt"]):
        try:
            with open(paths["iot_txt"], encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    p = line.strip()
                    if p and p not in seen_p:
                        seen_p.add(p)
                        passwords.append(p)
        except OSError:
            pass

    json_files = (
        paths["iot_json"], paths["routers_json"],
        paths["ip_cameras_json"], paths["nas_json"], paths["databases_json"],
    )
    for json_path in json_files:
        if not os.path.isfile(json_path):
            continue
        try:
            with open(json_path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        entries = data if isinstance(data, list) else data.get("credentials") or data.get("defaults") or []
        for entry in entries:
            if isinstance(entry, dict):
                user = str(entry.get("username") or entry.get("user") or "").strip()
                pwd = str(entry.get("password") or entry.get("pass") or "").strip()
            elif isinstance(entry, str) and ":" in entry:
                user, pwd = entry.split(":", 1)
                user, pwd = user.strip(), pwd.strip()
            else:
                continue
            if pwd and pwd not in seen_p:
                seen_p.add(pwd)
                passwords.append(pwd)
            if user and pwd:
                combo = f"{user}:{pwd}"
                if combo not in seen_c:
                    seen_c.add(combo)
                    combos.append(combo)

    if passwords:
        with open(pwd_out, "w", encoding="utf-8") as fh:
            fh.write("\n".join(passwords))
        out["passwords"] = pwd_out
    if combos:
        with open(combo_out, "w", encoding="utf-8") as fh:
            fh.write("\n".join(combos))
        out["combos"] = combo_out
    return out


def run_phase1_iot_recon(ip: str, target_dir: str, open_ports: list | None = None) -> dict:
    """Phase 1 — parallel IoT stack: Nuclei refresh, UPnP, changeme, Default-Hunter, wordlists."""
    from core.phase_jobs import PhaseRunner
    from core.scan_config import get_scan_profile

    runner = PhaseRunner(target_dir, "1-iot", "Phase 1 — IoT toolkit", max_workers=5)
    runner.add(
        "nuclei-templates",
        lambda: run_nuclei_template_refresh(target_dir),
        timeout=180,
        artifacts=("nuclei_template_update.txt",),
    )
    runner.add(
        "upnp",
        lambda: run_upnp_discovery(ip, target_dir),
        timeout=120,
        artifacts=("UPNP_DISCOVERY.json",),
    )
    runner.add(
        "changeme",
        lambda: run_changeme_only(ip, target_dir, open_ports),
        timeout=360,
        artifacts=("changeme_scan.txt",),
    )
    runner.add(
        "default-hunter",
        lambda: _run_default_hunter(ip, target_dir, _protocols_for_ports(open_ports)),
        timeout=360,
        artifacts=("default-hunter_scan.txt",),
    )
    runner.add(
        "jeanphorn-wordlists",
        lambda: build_iot_hydra_wordlists(target_dir),
        timeout=60,
        artifacts=("hydra_iot_passwords.txt", "hydra_iot_combos.txt"),
    )

    print(f"\n[+] Phase 1 parallel IoT: {len(runner.jobs)} job(s)")
    results = runner.run(group_timeout=get_scan_profile().get("phase1_iot_timeout", 900))

    changeme_hits = results.get("changeme")
    dh_hits = results.get("default-hunter")
    creds = _merge_and_save_default_creds(
        target_dir,
        changeme_hits.result if changeme_hits and changeme_hits.ok else [],
        dh_hits.result if dh_hits and dh_hits.ok else [],
    )

    upnp_r = results.get("upnp")
    wl_r = results.get("jeanphorn-wordlists")
    nuc_r = results.get("nuclei-templates")

    return {
        "nuclei_templates": bool(nuc_r and nuc_r.ok and nuc_r.result),
        "upnp": upnp_r.result if upnp_r and upnp_r.ok else [],
        "default_creds": creds,
        "wordlists": wl_r.result if wl_r and wl_r.ok else {},
    }


def run_phase2_iot_web(ip: str, target_dir: str, web_ports: list | None) -> dict:
    """Phase 2 — Genzai on all web ports."""
    return run_genzai_scan(ip, target_dir, web_ports)
