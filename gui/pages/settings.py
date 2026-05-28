"""Settings — dependency and PATH checks."""

from __future__ import annotations

import shutil

from PyQt6.QtWidgets import QHBoxLayout, QLabel, QMessageBox, QPushButton, QVBoxLayout, QWidget

from core.notify import (
    explain_telegram_config,
    load_telegram_env,
    send_telegram_message,
    telegram_configured,
    telegram_placeholder_keys_present,
)
from core.paths import project_root
from core.telegram.runner import start_telegram_bot_background
from core.utils import missing_python_modules
from gui.session import GuiSession

EXTERNAL_TOOLS = ("nmap", "nuclei", "hydra", "ffuf", "gau", "nikto", "whatweb", "git")


class SettingsPage(QWidget):
    def __init__(self, session: GuiSession, parent=None):
        super().__init__(parent)
        self._session = session
        self._telegram_thread = None
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("<h2>Settings</h2>"))
        self._status = QLabel()
        self._status.setWordWrap(True)
        layout.addWidget(self._status)
        telegram_row = QHBoxLayout()
        self._tg_send_btn = QPushButton("Telegram: Send test")
        self._tg_send_btn.clicked.connect(self._send_test_message)
        self._tg_start_btn = QPushButton("Telegram: Start listener")
        self._tg_start_btn.clicked.connect(self._start_listener)
        telegram_row.addWidget(self._tg_send_btn)
        telegram_row.addWidget(self._tg_start_btn)
        layout.addLayout(telegram_row)
        refresh = QPushButton("Refresh checks")
        refresh.clicked.connect(self.refresh)
        layout.addWidget(refresh)
        layout.addStretch()

    def refresh(self) -> None:
        load_telegram_env(project_root())
        lines = ["<b>Environment checks</b>", ""]
        missing_py = missing_python_modules()
        lines.append(
            f"Python modules: {'OK' if not missing_py else ', '.join(missing_py)}"
        )
        for tool in EXTERNAL_TOOLS:
            found = shutil.which(tool) or shutil.which(f"{tool}.exe")
            status = "OK" if found else "<span style=color:orange>not in PATH</span>"
            lines.append(f"{tool}: {status}")
        lines.append("")
        lines.append(f"AUTOPWN_SCAN_SOURCE=gui")
        lines.append(f"Keep artifacts: {self._session.keep_artifacts}")
        lines.append("")
        if telegram_configured() and not telegram_placeholder_keys_present():
            lines.append("Telegram config: OK")
        else:
            lines.append("Telegram config: invalid or placeholder in .env")
        if self._telegram_thread and self._telegram_thread.is_alive():
            lines.append("Telegram listener: running in background")
        else:
            lines.append("Telegram listener: not running")
        self._status.setText("<br>".join(lines))

    def _send_test_message(self) -> None:
        load_telegram_env(project_root())
        if not telegram_configured() or telegram_placeholder_keys_present():
            QMessageBox.warning(
                self,
                "Telegram not configured",
                explain_telegram_config(project_root()),
            )
            return
        ok = send_telegram_message("✅ GUI test message: send path is working.")
        if ok:
            QMessageBox.information(
                self,
                "Telegram send",
                "Test message sent successfully to TELEGRAM_CHAT_ID.",
            )
        else:
            QMessageBox.critical(
                self,
                "Telegram send failed",
                "Could not send test message. Check token/chat id/network.",
            )
        self.refresh()

    def _start_listener(self) -> None:
        load_telegram_env(project_root())
        if not telegram_configured() or telegram_placeholder_keys_present():
            QMessageBox.warning(
                self,
                "Telegram not configured",
                explain_telegram_config(project_root()),
            )
            return
        if self._telegram_thread and self._telegram_thread.is_alive():
            QMessageBox.information(
                self,
                "Telegram listener",
                "Listener is already running.",
            )
            return
        self._telegram_thread = start_telegram_bot_background(project_root())
        if self._telegram_thread:
            QMessageBox.information(
                self,
                "Telegram listener",
                "Listener started. Now bot can receive commands/messages.",
            )
        else:
            QMessageBox.warning(
                self,
                "Telegram listener",
                "Could not start listener. Verify .env and logs/telegram.log.",
            )
        self.refresh()
