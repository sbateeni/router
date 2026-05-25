"""Telegram Bot API helpers — send, auth, webhook, command menu."""

import json
import os

from core.notify import (
    _telegram_request,
    normalize_chat_id,
    telegram_placeholder_keys_present,
)

from core.telegram.constants import BOT_COMMANDS


def bot_token():
    return os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()


def allowed_chat(chat_id):
    allowed = normalize_chat_id(os.environ.get("TELEGRAM_CHAT_ID", ""))
    if not allowed or telegram_placeholder_keys_present():
        return True
    return str(chat_id) == str(allowed)


def ensure_polling_mode():
    """Long-poll getUpdates fails if a webhook is still registered."""
    token = bot_token()
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


def register_bot_commands():
    """Register slash menu in Telegram (appears when user types /)."""
    token = bot_token()
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


def send_to_chat(chat_id, text, reply_markup=None):
    payload = {"chat_id": chat_id, "text": text}
    if reply_markup:
        payload["reply_markup"] = json.dumps(reply_markup)
    try:
        _telegram_request("sendMessage", bot_token(), payload)
        return True
    except Exception as exc:
        print(f"[!] Telegram send failed: {exc}")
        return False


def answer_callback(callback_query_id):
    try:
        _telegram_request(
            "answerCallbackQuery",
            bot_token(),
            {"callback_query_id": callback_query_id},
        )
    except Exception:
        pass
