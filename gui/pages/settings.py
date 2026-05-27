"""Settings — dependency and PATH checks."""

from __future__ import annotations

import shutil

from PyQt6.QtWidgets import QLabel, QPushButton, QVBoxLayout, QWidget

from core.utils import missing_python_modules
from gui.session import GuiSession

EXTERNAL_TOOLS = ("nmap", "nuclei", "hydra", "ffuf", "gau", "nikto", "whatweb", "git")


class SettingsPage(QWidget):
    def __init__(self, session: GuiSession, parent=None):
        super().__init__(parent)
        self._session = session
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("<h2>Settings</h2>"))
        self._status = QLabel()
        self._status.setWordWrap(True)
        layout.addWidget(self._status)
        refresh = QPushButton("Refresh checks")
        refresh.clicked.connect(self.refresh)
        layout.addWidget(refresh)
        layout.addStretch()

    def refresh(self) -> None:
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
        self._status.setText("<br>".join(lines))
