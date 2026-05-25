"""Bot lifecycle — foreground daemon, background thread, CLI integration flags."""

import threading

from core.notify import (
    explain_telegram_config,
    load_telegram_env,
    send_telegram_message,
    telegram_configured,
    telegram_placeholder_keys_present,
)

from core.telegram.api import ensure_polling_mode, register_bot_commands
from core.telegram.polling import poll_updates_loop


def run_telegram_bot(base_dir, poll_timeout=25):
    load_telegram_env(base_dir)
    if not telegram_configured() or telegram_placeholder_keys_present():
        print("[!] Telegram غير جاهز — راجع .env على هذا الجهاز:\n")
        print(explain_telegram_config(base_dir))
        return 1

    ensure_polling_mode()

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
        poll_updates_loop(base_dir, poll_timeout)
    except KeyboardInterrupt:
        print("\n[-] Bot stopped.")
        return 0
    return 0


def start_telegram_bot_background(base_dir, poll_timeout=25):
    """Start Telegram polling in a daemon thread; local CLI menu keeps running."""
    load_telegram_env(base_dir)
    if not telegram_configured() or telegram_placeholder_keys_present():
        return None

    def worker():
        try:
            poll_updates_loop(base_dir, poll_timeout)
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
    if os.environ.get("NUCLEI_TELEGRAM_EXTERNAL", "").strip() == "1":
        return False
    if os.environ.get("TELEGRAM_AUTO", "1").strip().lower() in ("0", "false", "no", "off"):
        return False
    return telegram_configured() and not telegram_placeholder_keys_present()


def should_default_to_telegram(args):
    """Backward-compatible alias — bot-only mode is now opt-in via --telegram."""
    return getattr(args, "telegram", False)
