"""
Telegram control bot: send IP → choose attack mode → scan runs automatically.
Supports a per-chat queue when a scan is already running.
"""
import re
import threading
import time
from types import SimpleNamespace

from core.notify import (
    _telegram_request,
    load_dotenv,
    notify_scan_complete,
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

MAX_QUEUE_SIZE = 10

# selection, label (Arabic), profile override
ATTACK_MODES = [
    (1, "مسح كامل — كل الأدوات", "normal"),
    (1, "مسح عميق — Full Power", "deep"),
    (2, "Nmap فقط", "normal"),
    (3, "Nuclei فقط", "normal"),
    (4, "Dirsearch — مسارات مخفية", "normal"),
    (5, "SQLMap — SQL injection", "normal"),
    (6, "RouterSploit", "normal"),
    (8, "Hydra — كلمات مرور", "normal"),
    (9, "FFUF — fuzz", "normal"),
    (17, "Nikto — فحص ويب", "normal"),
    (18, "WhatWeb — بصمة", "normal"),
    (19, "Nmap vuln scripts", "normal"),
]

_chat_lock = threading.Lock()
_sessions = {}


def _bot_token():
    import os
    return os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()


def _allowed_chat(chat_id):
    import os
    allowed = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    if not allowed or telegram_placeholder_keys_present():
        return True
    return str(chat_id) == str(allowed)


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


def _handle_message(message, base_dir):
    chat_id = message["chat"]["id"]
    text = (message.get("text") or "").strip()

    if not _allowed_chat(chat_id):
        send_to_chat(chat_id, "غير مصرح. ضع TELEGRAM_CHAT_ID في .env لحسابك فقط.")
        return

    sess = _session(chat_id)

    if text in ("/start", "/help"):
        send_to_chat(
            chat_id,
            "Router Auto-Pwn — Telegram\n\n"
            "1) أرسل IP أو URL\n"
            "   مثال: 188.225.134.26\n"
            "   أو: http://router.example.com/login.html\n"
            "   أو: http://IP/page.php?id=1\n"
            "2) اختر نوع المسح\n"
            "3) ينفّذ تلقائياً ويرسل التقرير\n\n"
            "إذا مسح جاري وأرسلت IP آخر:\n"
            "  → يُضاف للانتظار (لا يفتح عمليتين معاً)\n\n"
            "/status — المسح الجاري + قائمة الانتظار\n"
            "/queue — عرض الانتظار\n"
            "/clearqueue — مسح الانتظار (لا يلغي المسح الجاري)\n"
            "/cancel — إلغاء الاختيار الحالي",
        )
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
        "مثال: router.example.com\n"
        "http://188.225.134.26/login.html\n"
        "http://site.com/page.php?id=1",
    )


def _poll_updates_loop(base_dir, poll_timeout=30, stop_event=None):
    token = _bot_token()
    offset = 0
    while not (stop_event and stop_event.is_set()):
        try:
            result = _telegram_request(
                "getUpdates",
                token,
                {"timeout": poll_timeout, "offset": offset},
            )
            for update in result.get("result", []):
                offset = update["update_id"] + 1
                if "callback_query" in update:
                    _handle_callback(update["callback_query"], base_dir)
                elif "message" in update:
                    _handle_message(update["message"], base_dir)
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            print(f"[!] Telegram poll error: {exc}")
            time.sleep(5)


def run_telegram_bot(base_dir, poll_timeout=30):
    load_dotenv(base_dir)
    if not telegram_configured() or telegram_placeholder_keys_present():
        print("[!] أعد TELEGRAM_BOT_TOKEN و TELEGRAM_CHAT_ID في .env")
        return 1

    print("[+] Telegram bot running (Ctrl+C to stop)")
    print("[*] Send IP → pick mode. Busy scans queue the next IP automatically.")

    try:
        _poll_updates_loop(base_dir, poll_timeout)
    except KeyboardInterrupt:
        print("\n[-] Bot stopped.")
        return 0
    return 0


def start_telegram_bot_background(base_dir, poll_timeout=30):
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
    if os.environ.get("TELEGRAM_AUTO", "1").strip().lower() in ("0", "false", "no", "off"):
        return False
    return telegram_configured() and not telegram_placeholder_keys_present()


def should_default_to_telegram(args):
    """Backward-compatible alias — bot-only mode is now opt-in via --telegram."""
    return getattr(args, "telegram", False)
