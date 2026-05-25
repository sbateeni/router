"""Slash command handlers (/osint, /lan, /engine, …)."""

from core.telegram_extras import (
    format_history,
    format_lan_scan,
    run_decepticon,
    run_framework_update,
    run_osint_action,
    run_poc_scraper,
    run_task_async,
)

from core.telegram.api import send_to_chat
from core.telegram.scans import enqueue_or_prompt, start_scan
from core.telegram.sessions import get_session
from core.telegram.targets import job_from_target, parse_target


def run_async_task(chat_id, label, fn, *args, **kwargs):
    send_to_chat(chat_id, f"⏳ {label}...")
    run_task_async(fn, lambda text: send_to_chat(chat_id, text), *args, **kwargs)


def handle_slash_command(chat_id, text, base_dir):
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
            run_async_task(chat_id, f"Social OSINT ({arg1})", run_osint_action, arg1, value or arg2)
            return True
        run_async_task(chat_id, "Social OSINT", run_osint_action, "email", arg1)
        return True

    if cmd == "/lan":
        if arg1 == "attack" and arg2.isdigit():
            sess = get_session(chat_id)
            idx = int(arg2) - 1
            devices = sess.get("lan_devices") or []
            if 0 <= idx < len(devices):
                target = f"http://{devices[idx]['ip']}"
                t = parse_target(target)
                if t:
                    enqueue_or_prompt(chat_id, t, base_dir)
                else:
                    send_to_chat(chat_id, f"❌ Invalid LAN target: {target}")
            else:
                send_to_chat(chat_id, "❌ Invalid device number. Run /lan first.")
            return True

        def _lan_done(result):
            if isinstance(result, tuple):
                msg, devices = result
                get_session(chat_id)["lan_devices"] = devices
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
        run_async_task(chat_id, "GitHub Zero-Day PoC Scraper", run_poc_scraper)
        return True

    if cmd == "/update":
        run_async_task(chat_id, "Framework & tools update", run_framework_update)
        return True

    if cmd in ("/decepticon", "/killchain"):
        target = arg2 or arg1
        if not target:
            send_to_chat(chat_id, "Usage: /decepticon http://IP or domain")
            return True
        run_async_task(chat_id, f"Decepticon kill-chain on {target}", run_decepticon, target)
        return True

    if cmd in ("/engine", "/autopwn"):
        target = arg2 or arg1
        if not target:
            send_to_chat(chat_id, "Usage: /engine http://IP")
            return True
        t = parse_target(target)
        if not t:
            send_to_chat(chat_id, "❌ Invalid target for Device Engine.")
            return True
        start_scan(chat_id, job_from_target(t, 21, "normal"), base_dir)
        return True

    return False
