"""Telegram message and inline-keyboard callback handlers."""

from core.telegram_extras import detect_osint_message, run_osint_action

from core.telegram.api import allowed_chat, answer_callback, send_to_chat
from core.telegram.commands import handle_slash_command, run_async_task
from core.telegram.scans import enqueue_or_prompt, force_idle, start_scan
from core.telegram.sessions import format_status, get_session, mode_keyboard
from core.telegram.targets import job_from_target, parse_target


def handle_callback(callback, base_dir):
    chat_id = callback["message"]["chat"]["id"]
    data = callback.get("data", "")

    answer_callback(callback["id"])

    if not allowed_chat(chat_id):
        send_to_chat(chat_id, "غير مصرح لهذا الحساب.")
        return

    sess = get_session(chat_id)

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
        if isinstance(target, str):
            target = parse_target(target)
        if not target:
            send_to_chat(chat_id, "❌ هدف غير صالح.")
            return
        job = job_from_target(target, selection, scan_profile)
        sess["pending_ip"] = None
        sess["state"] = "idle"
        if sess.get("scanning") or sess.get("queue"):
            sess["queue"].append(job)
            send_to_chat(
                chat_id,
                f"✓ أُضيف {job['ip']} للانتظار (الموقع {len(sess['queue'])})\n"
                f"النوع: {job.get('mode_label')}",
            )
        else:
            start_scan(chat_id, job, base_dir)
        return

    target = sess.get("ip")
    if not target:
        send_to_chat(chat_id, "أرسل IP أو URL أولاً.")
        return

    job = job_from_target(target, selection, scan_profile)
    sess["ip"] = None
    start_scan(chat_id, job, base_dir)


def handle_message(message, base_dir):
    chat_id = message["chat"]["id"]
    text = (message.get("text") or "").strip()

    if not allowed_chat(chat_id):
        send_to_chat(
            chat_id,
            f"غير مصرح لهذا الحساب.\n"
            f"ضع في .env:\nTELEGRAM_CHAT_ID={chat_id}\n"
            f"(المعرّف الحالي في .env لا يطابق محادثتك)",
        )
        return

    sess = get_session(chat_id)

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
            "/status /queue /clearqueue /cancel /stopscan",
        )
        return

    if text.startswith("/") and handle_slash_command(chat_id, text, base_dir):
        return

    osint = detect_osint_message(text)
    if osint:
        kind, value = osint
        run_async_task(chat_id, f"Social OSINT ({kind})", run_osint_action, kind, value)
        return

    if text == "/status":
        send_to_chat(chat_id, format_status(sess))
        return

    if text == "/queue":
        send_to_chat(chat_id, format_status(sess))
        return

    if text == "/clearqueue":
        cleared = len(sess.get("queue") or [])
        sess["queue"] = []
        sess["pending_ip"] = None
        if sess.get("state") == "choose_mode_queued":
            sess["state"] = "idle"
        send_to_chat(chat_id, f"✓ تم مسح {cleared} IP من قائمة الانتظار.\n{format_status(sess)}")
        return

    if text in ("/cancel", "/stopscan", "/stop"):
        force_idle(sess)
        send_to_chat(
            chat_id,
            "✓ تم إلغاء حالة «مسح جاري» واختيار الهدف.\n"
            "(عملية المسح في الخلفية قد تستمر — /clearqueue لمسح الانتظار)\n"
            f"{format_status(sess)}",
        )
        return

    target = parse_target(text)
    if target:
        enqueue_or_prompt(chat_id, target, base_dir)
        return

    send_to_chat(
        chat_id,
        "أرسل IP أو domain أو URL\n"
        "أو: /osint | /lan | /engine | /help",
    )
