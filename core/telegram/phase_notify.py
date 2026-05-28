"""Send concise Telegram summaries after each scan phase (telegram scans only)."""

import json
import os

from core.notify import send_telegram_message
from core.report.analysis import (
    parse_hydra_hits_detailed,
    parse_routersploit_summary,
    significant_nuclei_findings,
)
from core.report.parsers import count_nuclei_findings, find_files, read_file


def _telegram_scan_active():
    return os.environ.get("AUTOPWN_SCAN_SOURCE") == "telegram"


def _chat_id():
    raw = os.environ.get("AUTOPWN_TELEGRAM_CHAT_ID") or os.environ.get("TELEGRAM_CHAT_ID", "")
    return str(raw).strip()


def _load_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError, TypeError):
        return {}


def _join_limited(items, limit=8):
    items = [str(x) for x in items if x]
    if not items:
        return "—"
    if len(items) <= limit:
        return ", ".join(items)
    extra = len(items) - limit
    return ", ".join(items[:limit]) + f" (+{extra})"


def _profile_brief(profile):
    if not profile:
        return []
    lines = []
    ttype = profile.get("target_type") or "unknown"
    conf = profile.get("confidence") or "?"
    summary = (profile.get("summary") or "").strip()
    lines.append(f"• النوع: {ttype} ({conf})")
    if summary:
        lines.append(f"• ملخص: {summary[:200]}")
    vendor = profile.get("vendor")
    if vendor:
        lines.append(f"• Vendor: {vendor}")
    login_paths = profile.get("login_paths") or []
    if login_paths:
        lines.append(f"• مسارات دخول: {_join_limited(login_paths, 5)}")
    return lines


def _phase0_lines(target_dir):
    lines = []
    social = _load_json(os.path.join(target_dir, "SOCIAL_OSINT.json"))
    if social:
        kind = social.get("kind") or "social"
        lines.append(f"• Social OSINT ({kind}): تم")
    recon = _load_json(os.path.join(target_dir, "DEEP_RECON.json"))
    if recon:
        subs = recon.get("subdomains") or recon.get("hosts") or []
        if subs:
            lines.append(f"• Domain recon: {len(subs)} host/subdomain")
        elif recon:
            lines.append("• Domain recon: تم")
    sf = _load_json(os.path.join(target_dir, "SPIDERFOOT.json"))
    if sf and sf.get("ok"):
        lines.append("• SpiderFoot: تم")
    elif sf and not sf.get("error") == "not_installed":
        lines.append("• SpiderFoot: جزئي")
    if not lines:
        lines.append("• OSINT: لا نتائج ملحوظة")
    return lines


def _phase1_lines(profile, context, target_dir=None):
    lines = []
    if target_dir:
        conn = _load_json(os.path.join(target_dir, "CONNECTIVITY.json"))
        mass = _load_json(os.path.join(target_dir, "MASSCAN_PORTS.json"))
        if conn:
            flag = "متاح" if conn.get("reachable") else "لا استجابة HTTP"
            lines.append(f"• Curl preflight: {flag}")
        if mass and mass.get("count"):
            lines.append(f"• Masscan: {mass['count']} منفذ")
    ports = getattr(context, "open_ports", None) or []
    if ports:
        port_nums = []
        for p in ports:
            if isinstance(p, dict):
                port_nums.append(str(p.get("port", p)))
            else:
                port_nums.append(str(p))
        lines.append(f"• المنافذ المفتوحة: {_join_limited(port_nums)}")
    else:
        lines.append("• المنافذ: لا منافذ مفتوحة")
    web_ports = profile.get("web_ports") or getattr(context, "web_ports", []) or []
    if web_ports:
        lines.append(f"• منافذ ويب: {_join_limited(web_ports)}")
    lines.extend(_profile_brief(profile))
    upnp = _load_json(os.path.join(target_dir, "UPNP_DISCOVERY.json"))
    devs = (upnp.get("devices") or []) if upnp else []
    if devs:
        lines.append(f"• UPnP/SSDP: {len(devs)} جهاز")
    cm = _load_json(os.path.join(target_dir, "IOT_DEFAULT_CREDS.json")) or _load_json(
        os.path.join(target_dir, "CHANGEME_HITS.json")
    )
    if cm:
        lines.append(f"• default creds (changeme/Default-Hunter): {len(cm)} hit(s)")
    nuc_up = read_file(os.path.join(target_dir, "nuclei_template_update.txt"), 200).strip()
    if nuc_up:
        lines.append(f"• Nuclei templates: {'محدّثة' if 'ok' in nuc_up.lower() else 'تحديث فشل/تخطي'}")
    return lines


def _phase2_lines(target_dir, context):
    lines = []
    paths = getattr(context, "discovered_paths", []) or []
    urls = getattr(context, "discovered_urls", []) or []
    lines.append(f"• مسارات مكتشفة: {len(paths)}")
    lines.append(f"• URLs للفحص: {len(urls)}")
    nuclei = count_nuclei_findings(target_dir)
    sig = significant_nuclei_findings(nuclei)
    if sig:
        tops = [f"{f.get('severity')}/{f.get('template')}" for f in sig[:5]]
        lines.append(f"• Nuclei ({len(sig)} مهم): {_join_limited(tops, 5)}")
    elif nuclei:
        lines.append(f"• Nuclei: {len(nuclei)} hit (info/low فقط)")
    else:
        lines.append("• Nuclei: لا نتائج")
    sql_hits = 0
    for path in find_files(target_dir, "sqlmap_*.txt"):
        text = read_file(path, 8000).lower()
        if "is vulnerable" in text or "sql injection" in text:
            sql_hits += 1
    if sql_hits:
        lines.append(f"• SQLMap: {sql_hits} هدف محتمل")
    else:
        lines.append("• SQLMap: لا SQLi مؤكد")
    if getattr(context, "exploited", False):
        lines.append("• ⚠️ نتائج استغلال محتملة في هذه المرحلة")
    genzai = _load_json(os.path.join(target_dir, "GENZAI_RESULTS.json"))
    if genzai.get("findings"):
        lines.append(f"• Genzai: {len(genzai['findings'])} IoT panel(s)")
    return lines


def _phase3_lines(target_dir, context):
    lines = []
    rs = parse_routersploit_summary(target_dir)
    if rs.get("ran"):
        flag = "✓ vulnerable" if rs.get("vulnerable") else "لا ثغرات مؤكدة"
        lines.append(f"• RouterSploit: {flag}")
    ingram = read_file(os.path.join(target_dir, "ingram_scan.txt"), 4000)
    if ingram.strip():
        creds = ingram.lower().count("password") + ingram.lower().count("credential")
        lines.append(f"• Ingram: تم ({'نتائج محتملة' if creds else 'لا creds واضحة'})")
    poc = _load_json(os.path.join(target_dir, "POC_SUCCESS.json"))
    if poc:
        if isinstance(poc, list):
            lines.append(f"• PoC arsenal: {len(poc)} نجاح")
        elif isinstance(poc, dict):
            hits = poc.get("hits") or poc.get("success") or []
            lines.append(f"• PoC arsenal: {len(hits) if isinstance(hits, list) else 'تم'}")
    loot = _load_json(os.path.join(target_dir, "ENGINE_LOOT.json"))
    if loot:
        entries = loot.get("entries") or loot.get("loot") or []
        if isinstance(entries, list) and entries:
            lines.append(f"• Device engine loot: {len(entries)} عنصر")
        else:
            lines.append("• Device engine: تم")
    elif find_files(target_dir, "SUCCESS_*.txt"):
        lines.append("• Device engine: SUCCESS artifacts")
    camover = _load_json(os.path.join(target_dir, "CAMOVER_HITS.json"))
    if camover:
        lines.append(f"• CamOver: {len(camover)} hit(s)")
    camraptor = _load_json(os.path.join(target_dir, "CAMRAPTOR_HITS.json"))
    if camraptor:
        lines.append(f"• CamRaptor: {len(camraptor)} hit(s)")
    ib = _load_json(os.path.join(target_dir, "IOTBREAKER_CHECKS.json"))
    vuln_cves = [r.get("cve") for r in ib if isinstance(r, dict) and r.get("vulnerable")]
    if vuln_cves:
        lines.append(f"• IoTBreaker: {_join_limited(vuln_cves, 4)}")
    elif ib:
        lines.append(f"• IoTBreaker: {len(ib)} فحص CVE/وحدة")
    rust_iot = _load_json(os.path.join(target_dir, "RUSTSPLOIT_SCAN.json"))
    if rust_iot.get("output"):
        lines.append("• Rustsploit: تم")
    iotscan = _load_json(os.path.join(target_dir, "IOTSCAN_RESULTS.json"))
    if iotscan.get("output"):
        lines.append("• IoTScan: تم")
    all_creds = _load_json(os.path.join(target_dir, "IOT_ALL_CREDS.json"))
    if all_creds:
        lines.append(f"• IoT creds مجمّعة: {len(all_creds)}")
    if getattr(context, "exploited", False):
        lines.append("• ⚠️ استغلال/نتائج حرجة محتملة")
    else:
        lines.append("• الاستغلال: لا تأكيد بعد")
    return lines


def _phase4_lines(target_dir):
    hits = parse_hydra_hits_detailed(target_dir)
    lines = []
    if not hits:
        lines.append("• Hydra: لا كلمات مرور")
        return lines
    real = [h for h in hits if not h.get("likely_false_positive")]
    fp = len(hits) - len(real)
    for h in real[:5]:
        lines.append(f"• cred: {h.get('login')} / {h.get('password')}")
    if fp:
        lines.append(f"• ({fp} نتيجة Hydra مُصفّاة كـ false positive)")
    if len(real) > 5:
        lines.append(f"• ... +{len(real) - 5} أخرى في التقرير")
    return lines


def _build_body(phase_id, title, ip, target_dir, profile, context, skipped=False, skip_reason=""):
    header = f"✅ انتهى — {title}" if not skipped else f"⏭️ تخطي — {title}"
    lines = [header, f"الهدف: {ip}", ""]
    if skipped:
        lines.append(f"• {skip_reason or 'لا ينطبق على هذا الهدف'}")
    elif phase_id == "0":
        lines.extend(_phase0_lines(target_dir))
    elif phase_id == "1":
        lines.extend(_phase1_lines(profile or {}, context, target_dir))
    elif phase_id == "2":
        lines.extend(_phase2_lines(target_dir, context))
    elif phase_id == "3":
        lines.extend(_phase3_lines(target_dir, context))
    elif phase_id == "4":
        lines.extend(_phase4_lines(target_dir))

    next_phase = {
        "0": "PHASE 1 — Scanning",
        "1": "PHASE 2 — Web Enumeration",
        "2": "PHASE 3 — Exploitation",
        "3": "PHASE 4 — Brute Force",
        "4": None,
    }.get(phase_id)
    if next_phase and not skipped:
        lines.extend(["", f"⏳ التالي: {next_phase}"])
    elif phase_id == "4" and not skipped:
        lines.extend(["", "📋 التقرير الكامل يُرسل عند انتهاء المسح"])
    return "\n".join(lines)


def notify_phase_complete(
    phase_id,
    title,
    ip,
    target_dir,
    profile=None,
    context=None,
    skipped=False,
    skip_reason="",
):
    """Push phase summary to Telegram when scan was started from the bot."""
    if not _telegram_scan_active():
        return False
    chat_id = _chat_id()
    if not chat_id:
        return False
    body = _build_body(phase_id, title, ip, target_dir, profile, context, skipped, skip_reason)
    ok = send_telegram_message(body, chat_id=chat_id)
    try:
        from core.live_scan_log import write as live_write

        live_write(f"\n[Telegram] Phase notify: {title}\n")
    except Exception:
        pass
    return ok
