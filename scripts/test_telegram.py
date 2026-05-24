#!/usr/bin/env python3
"""Test Telegram bot token + chat id from .env (or .env.example)."""

import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from core.paths import setup_project_env
from core.notify import (
    load_dotenv,
    normalize_chat_id,
    send_telegram_message,
    telegram_configured,
    _telegram_request,
)

setup_project_env()


def load_env_example():
    path = os.path.join(ROOT, ".env.example")
    if not os.path.isfile(path):
        return False
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key, value = key.strip(), value.strip().strip('"').strip("'")
            if key.startswith("TELEGRAM_") and key not in os.environ:
                os.environ[key] = value
    return True


def main():
    if not load_dotenv(ROOT):
        load_env_example()

    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    raw_chat = os.environ.get("TELEGRAM_CHAT_ID", "")
    chat_id = normalize_chat_id(raw_chat)

    if chat_id != raw_chat:
        os.environ["TELEGRAM_CHAT_ID"] = chat_id
        print(f"[*] Normalized TELEGRAM_CHAT_ID: {raw_chat!r} -> {chat_id!r}")

    if not token or not chat_id:
        print("[!] Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID in .env / .env.example")
        return 1

    if "your_" in token.lower() or "here" in token.lower():
        print("[!] Token looks like a placeholder — set real values in .env")
        return 1

    print("[*] getMe...")
    try:
        data = _telegram_request("getMe", token, timeout=15)
        bot = data.get("result", {})
        print(f"[+] Bot OK: @{bot.get('username')} ({bot.get('first_name')})")
    except Exception as exc:
        err = str(exc)
        if "CERTIFICATE_VERIFY_FAILED" in err or "SSL" in err.upper():
            print(f"[!] getMe failed (SSL): {exc}")
            print("[i] Windows / corporate proxy often causes this.")
            print("    Try: pip install certifi")
            print("    Or add to .env: TELEGRAM_SSL_VERIFY=0  (dev only, less secure)")
            print("    Or test on Kali: python scripts/test_telegram.py")
        else:
            print(f"[!] getMe failed: {exc}")
        return 1

    print("[*] sendMessage test...")
    ok = send_telegram_message(
        "AUTO-PWN UNIFIED — Telegram test OK.\nIf you see this, notifications work.",
        chat_id=chat_id,
    )
    if ok:
        print("[+] Test message sent. Check your Telegram chat.")
        try:
            from core.telegram_bot import register_bot_commands
            if register_bot_commands():
                print("[+] Slash menu registered — type / in Telegram to see commands")
        except Exception as exc:
            print(f"[i] setMyCommands skipped: {exc}")
        return 0

    print("[!] sendMessage failed (check chat id — message the bot first with /start)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
