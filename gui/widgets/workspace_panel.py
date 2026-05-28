"""Right sidebar — target workspace summary and artifact chaining hints."""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QLabel, QListWidget, QListWidgetItem, QVBoxLayout, QWidget

from gui.workspace_context import summarize_workspace


class WorkspacePanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        self._title = QLabel("<b>Target workspace</b>")
        layout.addWidget(self._title)
        self._target = QLabel("No target applied")
        self._target.setWordWrap(True)
        layout.addWidget(self._target)
        self._chain = QLabel("")
        self._chain.setObjectName("chainInfo")
        self._chain.setWordWrap(True)
        layout.addWidget(self._chain)
        layout.addWidget(QLabel("<b>Artifacts for chaining</b>"))
        self._list = QListWidget()
        layout.addWidget(self._list, stretch=1)
        self._ready = QLabel("")
        self._ready.setWordWrap(True)
        layout.addWidget(self._ready)
        self.setMinimumWidth(220)
        self.setMaximumWidth(320)

    def refresh(self, target: str, target_dir: str) -> None:
        if target:
            self._target.setText(f"<code>{target}</code><br><span style='color:#8b95a5'>{target_dir or '—'}</span>")
        else:
            self._target.setText("<span style='color:#8b95a5'>Enter IP above → Apply target</span>")

        summary = summarize_workspace(target_dir)
        self._list.clear()
        for art in summary.get("artifacts") or []:
            item = QListWidgetItem(f"✓ {art['label']}")
            item.setToolTip(art["file"])
            self._list.addItem(item)
        if not summary.get("artifacts"):
            item = QListWidgetItem("— none yet —")
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsSelectable)
            self._list.addItem(item)

        hints = summary.get("hints") or []
        self._chain.setText("<br>".join(hints) if hints else "Tools share this folder automatically.")

        ready = summary.get("ready_for") or []
        if ready:
            self._ready.setText("<b>Suggested next:</b> " + ", ".join(ready))
        else:
            self._ready.setText("")
