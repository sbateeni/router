"""Shows the active target from the top bar (single source of truth)."""

from __future__ import annotations

from PyQt6.QtWidgets import QLabel, QVBoxLayout, QWidget

from gui.session import GuiSession


class TargetBanner(QWidget):
    def __init__(self, session: GuiSession, parent=None):
        super().__init__(parent)
        self._session = session
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self._label = QLabel()
        self._label.setObjectName("targetBanner")
        self._label.setWordWrap(True)
        layout.addWidget(self._label)
        self.refresh()

    def refresh(self) -> None:
        t = self._session.target.strip()
        if not t:
            self._label.setText(
                "<b>No target applied.</b> Enter IP in the top bar and click "
                "<b>Apply target</b> — all tools use that value."
            )
            return
        ws = self._session.target_dir or "(workspace pending)"
        self._label.setText(
            f"<b>Active target:</b> <code>{t}</code> &nbsp;|&nbsp; "
            f"<b>Profile:</b> {self._session.profile}<br>"
            f"<span style='color:#8b95a5'>Workspace: {ws}</span>"
        )
