"""
Telegram control bot package.

Send IP → choose attack mode → scan runs automatically.
Supports a per-chat queue when a scan is already running.
"""

from core.telegram.api import send_to_chat, register_bot_commands
from core.telegram.constants import ATTACK_MODES, BOT_COMMANDS, MAX_QUEUE_SIZE
from core.telegram.runner import (
    run_telegram_bot,
    should_default_to_telegram,
    should_run_telegram_background,
    start_telegram_bot_background,
)

__all__ = [
    "ATTACK_MODES",
    "BOT_COMMANDS",
    "MAX_QUEUE_SIZE",
    "register_bot_commands",
    "run_telegram_bot",
    "send_to_chat",
    "should_default_to_telegram",
    "should_run_telegram_background",
    "start_telegram_bot_background",
]
