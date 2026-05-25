"""
Telegram control bot: send IP → choose attack mode → scan runs automatically.
Supports a per-chat queue when a scan is already running.
"""
import json
import re
import threading
import time
from types import SimpleNamespace

import requests

from core.notify import (
    _telegram_request,
    load_dotenv,
    normalize_chat_id,
    notify_scan_complete,
    send_telegram_message,
    telegram_configured,
    telegram_placeholder_keys_present,
)
from core.report import generate_scan_report
from core.runner import run_selected_tool
from core.utils import reset_target_workspace

from core.report.parsers import (
    parse_target_input,
    save_target_hints,
    sanitize_target_dir_name,
    target_scan_host,
    target_workspace_name,
)
from core.telegram_extras import (
    detect_osint_message,
    format_history,
    format_lan_scan,
    run_decepticon,
    run_framework_update,
    run_osint_action,
    run_poc_scraper,
    run_task_async,
)

MAX_QUEUE_SIZE = 10

# Shown in Telegram when user taps "/" (setMyCommands on bot start)
BOT_COMMANDS = [
    ("start", "بدء — ترحيب ومساعدة"),
    ("help", "قائمة الأوامر"),
    ("engine", "Device Engine — AUTO-PWN"),
    ("osint", "Social OSINT — email/phone/user"),
    ("lan", "فحص الشبكة المحلية LAN"),
    ("history", "أهداف مسحّة سابقاً"),
    ("poc", "GitHub PoC scraper"),
    ("update", "تحديث المشروع والأدوات"),
    ("decepticon", "سلسلة Decepticon"),
    ("status", "حالة المسح الحالي"),
    ("queue", "قائمة الانتظار"),
    ("cancel", "إلغاء الاختيار"),
    ("clearqueue", "مسح قائمة الانتظار"),
]

# selection, label (Arabic), profile override
ATTACK_MODES = [
    (1, "مسح كامل — كل الأدوات", "normal"),
    (1, "مسح عميق — كل الأدوات مدمجة", "deep"),
    (21, "Device Engine — AUTO-PWN", "normal"),
    (2, "Nmap فقط", "normal"),
    (3, "Nuclei فقط", "normal"),
    (4, "Dirsearch — مسارات", "normal"),
    (5, "SQLMap — SQLi", "normal"),
    (6, "RouterSploit", "normal"),
    (7, "Ingram — كاميرات", "normal"),
    (8, "Hydra — كلمات مرور", "normal"),
    (9, "FFUF — fuzz", "normal"),
    (10, "GAU — URLs", "normal"),
    (17, "Nikto — فحص ويب", "normal"),
    (18, "WhatWeb — بصمة", "normal"),
    (19, "Nmap vuln scripts", "normal"),
]

_chat_lock = threading.Lock()
_sessions = {}


def _bot_token():
    import os
    return os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()


def register_bot_commands():
    """Register slash menu in Telegram (appears when user types /)."""
    token = _bot_token()
    if not token:
        return False
    payload = {
        "commands": json.dumps(
            [{"command": cmd, "description": desc} for cmd, desc in BOT_COMMANDS]
        ),
    }
    try:
        _telegram_request("setMyCommands", token, payload, timeout=15)
        return True
    except Exception as exc:
        print(f"[!] setMyCommands failed: {exc}")
        return False


def _allowed_chat(chat_id):
    import os
    allowed = normalize_chat_id(os.environ.get("TELEGRAM_CHAT_ID", ""))
    if not allowed or telegram_placeholder_keys_present():
        return True
    return str(chat_id) == str(allowed)


def _ensure_polling_mode():
    """Long-poll getUpdates fails if a webhook is still registered."""
    token = _bot_token()
    if not token:
        return
    try:
        info = _telegram_request("getWebhookInfo", token, {}, timeout=15)
        url = (info.get("result") or {}).get("url") or ""
        if url:
            print(f"[!] Webhook active ({url}) — deleting for polling...", flush=True)
        _telegram_request("deleteWebhook", token, {"drop_pending_updates": False}, timeout=15)
    except Exception as exc:
        print(f"[!] deleteWebhook failed: {exc}", flush=True)


def send_to_chat(chat_id, text, reply_markup=None):
    payload = {"chat_id": chat_id, "text": text}
    if reply_markup:
        import json
        payload["reply_markup"] = json.dumps(reply_markup)
    try:
        _telegram_request("sendMessage", _bot_token(), payload)
        return True
    except Exception as exc:
        print(f"[!] Telegram send failed: {exc}")
        return False


def _mode_keyboard():
    rows = []
    row = []
    for sel, label, prof in ATTACK_MODES:
        deep_flag = "d" if prof == "deep" else "n"
        row.append({"text": label[:40], "callback_data": f"m:{sel}:{deep_flag}"})
        if len(row) == 2:
            rows.append(row)
            row = []
    if row:
        rows.append(row)
    rows.append([{"text": "إلغاء", "callback_data": "cancel"}])
    return {"inline_keyboard": rows}


def _parse_target(text):
    return parse_target_input(text)


def _mode_label(selection, scan_profile):
    return next(
        (m[1] for m in ATTACK_MODES if m[0] == selection and m[2] == scan_profile),
        str(selection),
    )


def _new_session():
    return {
        "state": "idle",
        "ip": None,
        "pending_ip": None,
        "scanning": False,
        "current_ip": None,
        "current_mode": None,
        "queue": [],
        "lan_devices": [],
    }


def _session(chat_id):
    if chat_id not in _sessions:
        _sessions[chat_id] = _new_session()
    return _sessions[chat_id]


def _format_status(sess):
    lines = []
    if sess.get("scanning") and sess.get("current_ip"):
        mode = sess.get("current_mode") or "?"
        lines.append(f"▶ جاري المسح: {sess['current_ip']} ({mode})")
    else:
        lines.append("▶ لا يوجد مسح نشط.")
    queue = sess.get("queue") or []
    if queue:
        lines.append(f"⏳ قائمة الانتظار ({len(queue)}):")
        for idx, job in enumerate(queue, 1):
            lines.append(f"  {idx}. {job['ip']} — {job.get('mode_label', '?')}")
    elif sess.get("pending_ip"):
        lines.append(f"⏳ بانتظار اختيار نوع المسح: {sess['pending_ip']}")
    else:
        lines.append("⏳ قائمة الانتظار: فارغة")
    return "\n".join(lines)


def _run_scan_job(chat_id, job, base_dir):
    scan_host = job.get("scan_host") or job["ip"]
    workspace = job.get("workspace_name") or sanitize_target_dir_name(scan_host)
    selection = job["selection"]
    scan_profile = job["profile"]

    target_dir = __import__("os").path.join(base_dir, "targets", workspace)
    __import__("os").makedirs(target_dir, exist_ok=True)
    reset_target_workspace(target_dir)

    hints = job.get("hints") or {}
    if hints:
        save_target_hints(target_dir, hints)
        if hints.get("login_path"):
            send_to_chat(
                chat_id,
                f"📌 مسار الدخول: {hints['login_path']}\n"
                f"   (Tenda وغيرها — Hydra/Nuclei يستهدف هذا المسار أولاً)",
            )

    args = SimpleNamespace(subnet=None)
    exploited = run_selected_tool(
        selection, scan_host, target_dir, profile=scan_profile, subnet=None,
    )
    report_path, confirmed = generate_scan_report(
        scan_host, target_dir, selection, exploited,
        current_phase="Completed", profile=scan_profile,
    )

    ai_analysis = None
    if selection == 14:
        ai_path = __import__("os").path.join(target_dir, "AI_ANALYSIS.txt")
        if __import__("os").path.exists(ai_path):
            with open(ai_path, "r", encoding="utf-8") as fh:
                ai_analysis = fh.read()

    status_ar = "نجاح — نتائج محتملة" if confirmed else "اكتمل — لا استغلال مؤكد"
    send_to_chat(
        chat_id,
        f"✅ انتهى المسح على {scan_host}\nالوضع: {status_ar}\nالتقرير يُرسل الآن...",
    )
    notify_scan_complete(
        scan_host, target_dir, report_path, confirmed,
        profile=scan_profile, ai_analysis=ai_analysis, chat_id=str(chat_id),
    )
    return confirmed


def _process_queue(chat_id, base_dir):
    """Run queued jobs one after another (single worker per chat)."""
    sess = _session(chat_id)

    while sess["queue"]:
        job = sess["queue"].pop(0)
        sess["scanning"] = True
        sess["current_ip"] = job["ip"]
        sess["current_mode"] = job.get("mode_label")
        sess["state"] = "scanning"

        remaining = len(sess["queue"])
        extra = f"\nبعده: {remaining} في الانتظار" if remaining else ""
        send_to_chat(
            chat_id,
            f"▶ بدء المسح التالي\nالهدف: {job['ip']}\nالنوع: {job.get('mode_label')}{extra}",
        )

        try:
            _run_scan_job(chat_id, job, base_dir)
        except Exception as exc:
            send_to_chat(chat_id, f"❌ خطأ أثناء مسح {job['ip']}: {exc}")

    sess["scanning"] = False
    sess["current_ip"] = None
    sess["current_mode"] = None
    sess["state"] = "idle"
    sess["ip"] = None
    sess["pending_ip"] = None

    if not sess["queue"]:
        send_to_chat(chat_id, "✓ جميع المسوحات في قائمة الانتظار اكتملت.")


def _start_scan(chat_id, job, base_dir):
    """Start scan worker: current job first, then queue."""
    sess = _session(chat_id)

    with _chat_lock:
        if sess.get("scanning"):
            sess["queue"].append(job)
            pos = len(sess["queue"])
            send_to_chat(
                chat_id,
                f"⏳ مسح جاري على {sess.get('current_ip')}\n"
                f"✓ أُضيف {job['ip']} للانتظار (الموقع {pos})\n"
                f"النوع: {job.get('mode_label')}",
            )
            return

        def worker():
            with _chat_lock:
                sess["scanning"] = True
                sess["current_ip"] = job["ip"]
                sess["current_mode"] = job.get("mode_label")
                sess["state"] = "scanning"

            send_to_chat(
                chat_id,
                f"▶ بدء المسح\nالهدف: {job['ip']}\n"
                f"النوع: {job.get('mode_label')}\n"
                f"الملف الشخصي: {job['profile']}\n\n"
                f"سيصلك التقرير عند الانتهاء.",
            )

            try:
                _run_scan_job(chat_id, job, base_dir)
            except Exception as exc:
                send_to_chat(chat_id, f"❌ خطأ أثناء المسح: {exc}")

            _process_queue(chat_id, base_dir)

        threading.Thread(target=worker, daemon=True).start()


def _target_prompt_text(target):
    host = target.get("host") or target.get("ip")
    lines = [f"الهدف: {host}"]
    if target.get("resolved_ip") and target.get("is_domain"):
        lines.append(f"DNS → {target['resolved_ip']}")
    if target.get("login_path"):
        lines.append(f"مسار: {target['login_path']}")
    if target.get("query_string"):
        lines.append(f"Query: ?{target['query_string']}")
    if target.get("raw") and target["raw"] != host:
        lines.append(f"URL: {target['raw']}")
    lines.append("\nاختر نوع الهجوم / المسح:")
    return "\n".join(lines)


def _job_from_target(target, selection, scan_profile):
    scan_host = target_scan_host(target)
    return {
        "ip": scan_host,
        "scan_host": scan_host,
        "workspace_name": target_workspace_name(target),
        "selection": selection,
        "profile": scan_profile,
        "mode_label": _mode_label(selection, scan_profile),
        "hints": {
            "host": target.get("host"),
            "login_path": target.get("login_path"),
            "seed_url": target.get("seed_url"),
            "query_string": target.get("query_string"),
            "port": target.get("port"),
            "scheme": target.get("scheme"),
            "resolved_ip": target.get("resolved_ip"),
            "is_domain": target.get("is_domain"),
            "raw": target.get("raw"),
        },
    }


def _enqueue_or_prompt(chat_id, target, base_dir):
    """New IP while busy → queue after mode pick, or show mode keyboard."""
    sess = _session(chat_id)

    if sess.get("scanning") or sess.get("queue"):
        if len(sess.get("queue", [])) >= MAX_QUEUE_SIZE:
            send_to_chat(
                chat_id,
                f"⚠ قائمة الانتظار ممتلئة ({MAX_QUEUE_SIZE}).\n"
                f"الجاري: {sess.get('current_ip')}\n"
                f"استخدم /status أو انتظر.",
            )
            return

        sess["pending_ip"] = target
        sess["state"] = "choose_mode_queued"
        send_to_chat(
            chat_id,
            f"⏳ مسح جاري على: {sess.get('current_ip') or '?'}\n"
            f"في الانتظار: {len(sess.get('queue', []))} IP\n\n"
            f"{_target_prompt_text(target)}\n"
            f"(يُضاف للانتظار تلقائياً):",
            reply_markup=_mode_keyboard(),
        )
        return

    if sess.get("state") == "choose_mode" and sess.get("ip"):
        send_to_chat(
            chat_id,
            f"⚠ اختر نوع المسح أولاً للهدف {sess['ip'].get('ip', sess['ip'])} أو /cancel",
        )
        return

    sess["ip"] = target
    sess["state"] = "choose_mode"
    send_to_chat(chat_id, _target_prompt_text(target), reply_markup=_mode_keyboard())


def _handle_callback(callback, base_dir):
    chat_id = callback["message"]["chat"]["id"]
    data = callback.get("data", "")

    try:
        _telegram_request(
            "answerCallbackQuery",
            _bot_token(),
            {"callback_query_id": callback["id"]},
        )
    except Exception:
        pass

    if not _allowed_chat(chat_id):
        send_to_chat(chat_id, "غير مصرح لهذا الحساب.")
        return

    sess = _session(chat_id)

    if data == "cancel":
        sess["state"] = "idle"
        sess["ip"] = None
        sess["pending_ip"] = None
        send_to_chat(chat_id, "تم الإلغاء (المسح الجاري والانتظار يستمران).")
        return

    if not data.startswith("m:"):
        return

    parts = data.split(":")
    if len(parts) != 3:
        return

    selection = int(parts[1])
    scan_profile = "deep" if parts[2] == "d" else "normal"

    if sess.get("state") == "choose_mode_queued":
        target = sess.get("pending_ip")
        if not target:
            send_to_chat(chat_id, "أرسل IP أو URL أولاً.")
            return
        job = _job_from_target(target, selection, scan_profile)
        sess["pending_ip"] = None
        sess["state"] = "idle"
        _start_scan(chat_id, job, base_dir)
        return

    target = sess.get("ip")
    if not target:
        send_to_chat(chat_id, "أرسل IP أو URL أولاً.")
        return

    job = _job_from_target(target, selection, scan_profile)
    sess["ip"] = None
    _start_scan(chat_id, job, base_dir)


def _run_async_task(chat_id, label, fn, *args, **kwargs):
    send_to_chat(chat_id, f"⏳ {label}...")
    run_task_async(fn, lambda text: send_to_chat(chat_id, text), *args, **kwargs)


def _handle_slash_command(chat_id, text, base_dir):
    """Return True if message was handled as a command."""
    parts = text.strip().split(maxsplit=2)
    cmd = parts[0].lower()
    arg1 = parts[1].lower() if len(parts) > 1 else ""
    arg2 = parts[2] if len(parts) > 2 else (parts[1] if len(parts) > 1 and cmd == "/decepticon" else "")

    if cmd == "/osint":
        if not arg1:
            send_to_chat(
                chat_id,
                "Usage:\n/osint email user@mail.com\n/osint phone +966...\n"
                "/osint user username\n/osint full user@mail.com",
            )
            return True
        if arg1 in ("email", "phone", "user", "full", "mail", "tel", "u", "f", "investigate", "e", "p"):
            value = arg2 or (parts[1] if len(parts) == 2 and "@" in parts[1] else "")
            if not value and len(parts) >= 2:
                value = parts[1]
            _run_async_task(chat_id, f"Social OSINT ({arg1})", run_osint_action, arg1, value or arg2)
            return True
        # /osint user@mail.com shorthand
        _run_async_task(chat_id, "Social OSINT", run_osint_action, "email", arg1)
        return True

    if cmd == "/lan":
        if arg1 == "attack" and arg2.isdigit():
            sess = _session(chat_id)
            idx = int(arg2) - 1
            devices = sess.get("lan_devices") or []
            if 0 <= idx < len(devices):
                target = f"http://{devices[idx]['ip']}"
                from core.report.parsers import parse_target_input
                t = parse_target_input(target)
                if t:
                    _enqueue_or_prompt(chat_id, t, base_dir)
                else:
                    send_to_chat(chat_id, f"❌ Invalid LAN target: {target}")
            else:
                send_to_chat(chat_id, "❌ Invalid device number. Run /lan first.")
            return True

        def _lan_done(result):
            if isinstance(result, tuple):
                msg, devices = result
                _session(chat_id)["lan_devices"] = devices
                send_to_chat(chat_id, msg)
            else:
                send_to_chat(chat_id, str(result))

        send_to_chat(chat_id, "⏳ LAN scan running...")
        run_task_async(format_lan_scan, _lan_done)
        return True

    if cmd == "/history":
        msg, _ = format_history()
        send_to_chat(chat_id, msg)
        return True

    if cmd == "/poc":
        _run_async_task(chat_id, "GitHub Zero-Day PoC Scraper", run_poc_scraper)
        return True

    if cmd == "/update":
        _run_async_task(chat_id, "Framework & tools update", run_framework_update)
        return True

    if cmd in ("/decepticon", "/killchain"):
        target = arg2 or arg1
        if not target:
            send_to_chat(chat_id, "Usage: /decepticon http://IP or domain")
            return True
        _run_async_task(chat_id, f"Decepticon kill-chain on {target}", run_decepticon, target)
        return True

    if cmd in ("/engine", "/autopwn"):
        target = arg2 or arg1
        if not target:
            send_to_chat(chat_id, "Usage: /engine http://IP")
            return True
        t = _parse_target(target)
        if not t:
            send_to_chat(chat_id, "❌ Invalid target for Device Engine.")
            return True
        job = _job_from_target(t, 21, "normal")
        _start_scan(chat_id, job, base_dir)
        return True

    return False


def _handle_message(message, base_dir):
    chat_id = message["chat"]["id"]
    text = (message.get("text") or "").strip()

    if not _allowed_chat(chat_id):
        send_to_chat(
            chat_id,
            f"غير مصرح لهذا الحساب.\n"
            f"ضع في .env:\nTELEGRAM_CHAT_ID={chat_id}\n"
            f"(المعرّف الحالي في .env لا يطابق محادثتك)",
        )
        return

    sess = _session(chat_id)

    if text in ("/start", "/help"):
        send_to_chat(
            chat_id,
            "Router Auto-Pwn — Telegram\n\n"
            "📋 اضغط / في الشات لعرض قائمة الأوامر\n\n"
            "▶ مسح شبكي: أرسل IP / domain / URL ثم اختر نوع المسح\n"
            "  188.225.134.26 | router.com/login.html | http://site.com?id=1\n\n"
            "▶ Device Engine: /engine http://IP\n"
            "▶ Social OSINT:\n"
            "  /osint email user@mail.com | /osint phone +966... | /osint user name\n"
            "  أو أرسل email/phone مباشرة\n\n"
            "▶ /lan — LAN scan | /lan attack 1 — AUTO-PWN\n"
            "▶ /history | /poc | /update | /decepticon http://IP\n\n"
            "/status /queue /clearqueue /cancel",
        )
        return

    if text.startswith("/") and _handle_slash_command(chat_id, text, base_dir):
        return

    osint = detect_osint_message(text)
    if osint:
        kind, value = osint
        _run_async_task(chat_id, f"Social OSINT ({kind})", run_osint_action, kind, value)
        return

    if text == "/status":
        send_to_chat(chat_id, _format_status(sess))
        return

    if text == "/queue":
        send_to_chat(chat_id, _format_status(sess))
        return

    if text == "/clearqueue":
        cleared = len(sess.get("queue") or [])
        sess["queue"] = []
        sess["pending_ip"] = None
        if sess.get("state") == "choose_mode_queued":
            sess["state"] = "idle"
        send_to_chat(chat_id, f"✓ تم مسح {cleared} IP من قائمة الانتظار.\n{_format_status(sess)}")
        return

    if text == "/cancel":
        sess["state"] = "idle"
        sess["ip"] = None
        sess["pending_ip"] = None
        send_to_chat(
            chat_id,
            "تم إلغاء الاختيار.\n"
            "(المسح الجاري وقائمة الانتظار لم تُلغَ — /clearqueue لمسح الانتظار)",
        )
        return

    target = _parse_target(text)
    if target:
        _enqueue_or_prompt(chat_id, target, base_dir)
        return

    send_to_chat(
        chat_id,
        "أرسل IP أو domain أو URL\n"
        "أو: /osint | /lan | /engine | /help",
    )


_poll_error_lock = threading.Lock()
_last_poll_error_log = 0.0
POLL_ERROR_LOG_INTERVAL = 120


def _log_poll_error(exc):
    """Avoid spamming the terminal during long scans — one warning every 2 minutes."""
    global _last_poll_error_log
    now = time.time()
    with _poll_error_lock:
        if now - _last_poll_error_log < POLL_ERROR_LOG_INTERVAL:
            return
        _last_poll_error_log = now
    print(f"[!] Telegram poll warning: {exc} (retrying in background)")


def _poll_updates_loop(base_dir, poll_timeout=25, stop_event=None):
    token = _bot_token()
    offset = 0
    # HTTP timeout must exceed Telegram long-poll timeout (otherwise every empty poll looks like an error).
    http_timeout = poll_timeout + 20
    while not (stop_event and stop_event.is_set()):
        try:
            result = _telegram_request(
                "getUpdates",
                token,
                {"timeout": poll_timeout, "offset": offset},
                timeout=http_timeout,
            )
            for update in result.get("result", []):
                offset = update["update_id"] + 1
                if "callback_query" in update:
                    _handle_callback(update["callback_query"], base_dir)
                elif "message" in update:
                    msg = update["message"]
                    who = (msg.get("from") or {}).get("username") or msg.get("chat", {}).get("id")
                    text_preview = (msg.get("text") or "")[:60]
                    print(f"[Telegram] ← {who}: {text_preview}", flush=True)
                    _handle_message(msg, base_dir)
        except KeyboardInterrupt:
            raise
        except requests.exceptions.ReadTimeout:
            continue
        except Exception as exc:
            _log_poll_error(exc)
            time.sleep(5)


def run_telegram_bot(base_dir, poll_timeout=25):
    load_dotenv(base_dir)
    if not telegram_configured() or telegram_placeholder_keys_present():
        print("[!] أعد TELEGRAM_BOT_TOKEN و TELEGRAM_CHAT_ID في .env")
        return 1

    _ensure_polling_mode()

    if register_bot_commands():
        print("[+] Telegram command menu registered (type / in chat)")
    else:
        print("[!] Could not register / commands menu — bot still works")

    send_telegram_message(
        "✅ البوت يستمع الآن — أرسل /start أو IP\n"
        "(إذا لم تصلك هذه الرسالة، تحقق من logs/telegram.log)",
    )

    print("[+] Telegram bot running (Ctrl+C to stop)", flush=True)
    print("[*] Send IP or /start to @H_the_box_bot — polling getUpdates...", flush=True)

    try:
        _poll_updates_loop(base_dir, poll_timeout)
    except KeyboardInterrupt:
        print("\n[-] Bot stopped.")
        return 0
    return 0


def start_telegram_bot_background(base_dir, poll_timeout=25):
    """Start Telegram polling in a daemon thread; local CLI menu keeps running."""
    load_dotenv(base_dir)
    if not telegram_configured() or telegram_placeholder_keys_present():
        return None

    def worker():
        try:
            _poll_updates_loop(base_dir, poll_timeout)
        except KeyboardInterrupt:
            pass
        except Exception as exc:
            print(f"[!] Telegram background bot stopped: {exc}")

    if register_bot_commands():
        print("[+] Telegram command menu registered (type / in chat)")

    thread = threading.Thread(target=worker, daemon=True, name="telegram-bot")
    thread.start()
    print("[+] Telegram bot listening in background")
    print("[*] Send IP in Telegram → pick mode → scan runs automatically.")
    print("[*] Local menu below — you can scan from this terminal too.\n")
    return thread


def should_run_telegram_background(args):
    import os
    if getattr(args, "no_telegram", False) or getattr(args, "telegram", False):
        return False
    # run.sh already started scripts/telegram_service.sh (avoid duplicate getUpdates)
    if os.environ.get("NUCLEI_TELEGRAM_EXTERNAL", "").strip() == "1":
        return False
    if os.environ.get("TELEGRAM_AUTO", "1").strip().lower() in ("0", "false", "no", "off"):
        return False
    return telegram_configured() and not telegram_placeholder_keys_present()


def should_default_to_telegram(args):
    """Backward-compatible alias — bot-only mode is now opt-in via --telegram."""
    return getattr(args, "telegram", False)
