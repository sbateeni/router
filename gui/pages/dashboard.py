"""Dashboard — env status and quick links."""

from __future__ import annotations

import glob
import os

from PyQt6.QtWidgets import QLabel, QVBoxLayout, QWidget

from core.ai.analyst import ai_placeholder_keys_present
from core.notify import telegram_placeholder_keys_present
from core.paths import project_root
from core.utils import missing_python_modules
from gui.session import GuiSession


class DashboardPage(QWidget):
    def __init__(self, session: GuiSession, parent=None):
        super().__init__(parent)
        self._session = session
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("<h2>Dashboard</h2>"))
        self._status = QLabel()
        self._status.setWordWrap(True)
        layout.addWidget(self._status)
        layout.addStretch()

    def refresh(self) -> None:
        lines = ["<b>AUTO-PWN UNIFIED — GUI</b>", ""]
        env_path = os.path.join(project_root(), ".env")
        lines.append(f".env: {'found' if os.path.isfile(env_path) else '<span style=color:red>missing</span>'}")
        if ai_placeholder_keys_present():
            lines.append("AI keys: <span style=color:orange>placeholders in .env</span>")
        else:
            lines.append("AI keys: configured (or not using placeholders)")
        if telegram_placeholder_keys_present():
            lines.append("Telegram: <span style=color:orange>placeholders</span>")
        else:
            lines.append("Telegram: configured (or not using placeholders)")
        missing = missing_python_modules()
        if missing:
            lines.append(f"Python modules missing: {', '.join(missing)}")
        else:
            lines.append("Python modules: OK")
        targets = glob.glob(os.path.join(project_root(), "targets", "*"))
        lines.append(f"Workspaces: {len([t for t in targets if os.path.isdir(t)])}")
        if self._session.target_dir:
            lines.append(f"Current workspace: <code>{self._session.target_dir}</code>")
        self._status.setText("<br>".join(lines))
