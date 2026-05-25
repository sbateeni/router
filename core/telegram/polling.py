"""Long-polling loop for Telegram updates."""

import threading
import time

import requests

from core.notify import _telegram_request

from core.telegram.api import bot_token
from core.telegram.handlers import handle_callback, handle_message

_poll_error_lock = threading.Lock()
_last_poll_error_log = 0.0
POLL_ERROR_LOG_INTERVAL = 120


def log_poll_error(exc):
    """Avoid spamming the terminal during long scans — one warning every 2 minutes."""
    global _last_poll_error_log
    now = time.time()
    with _poll_error_lock:
        if now - _last_poll_error_log < POLL_ERROR_LOG_INTERVAL:
            return
        _last_poll_error_log = now
    print(f"[!] Telegram poll warning: {exc} (retrying in background)")


def poll_updates_loop(base_dir, poll_timeout=25, stop_event=None):
    token = bot_token()
    offset = 0
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
                    handle_callback(update["callback_query"], base_dir)
                elif "message" in update:
                    msg = update["message"]
                    who = (msg.get("from") or {}).get("username") or msg.get("chat", {}).get("id")
                    text_preview = (msg.get("text") or "")[:60]
                    print(f"[Telegram] ← {who}: {text_preview}", flush=True)
                    handle_message(msg, base_dir)
        except KeyboardInterrupt:
            raise
        except requests.exceptions.ReadTimeout:
            continue
        except Exception as exc:
            log_poll_error(exc)
            time.sleep(5)
