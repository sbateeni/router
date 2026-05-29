"""Results hub — credentials, next tools, file preview, Telegram send."""

from __future__ import annotations

import os

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from gui.workspace_hub import collect_workspace_view, format_results_summary, page_id_for_tool_name


class ResultsPanel(QWidget):
    navigate_requested = pyqtSignal(str)  # page_id

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._summary = QPlainTextEdit()
        self._summary.setReadOnly(True)
        self._summary.setMaximumHeight(140)
        self._summary.setFont(QFont("Consolas", 10))
        layout.addWidget(QLabel("<b>Summary</b>"))
        layout.addWidget(self._summary)

        split = QSplitter()
        left = QWidget()
        left_lay = QVBoxLayout(left)
        left_lay.setContentsMargins(0, 0, 0, 0)
        left_lay.addWidget(QLabel("<b>Next tools (click)</b>"))
        self._tools = QListWidget()
        self._tools.itemClicked.connect(self._on_tool_click)
        left_lay.addWidget(self._tools)
        left_lay.addWidget(QLabel("<b>Files (double-click to open)</b>"))
        self._files = QListWidget()
        self._files.itemDoubleClicked.connect(self._open_file_item)
        left_lay.addWidget(self._files, stretch=1)
        split.addWidget(left)

        right = QWidget()
        right_lay = QVBoxLayout(right)
        right_lay.setContentsMargins(0, 0, 0, 0)
        right_lay.addWidget(QLabel("<b>Preview</b>"))
        self._preview = QPlainTextEdit()
        self._preview.setReadOnly(True)
        self._preview.setFont(QFont("Consolas", 10))
        self._files.itemClicked.connect(self._preview_file_item)
        right_lay.addWidget(self._preview, stretch=1)
        split.addWidget(right)
        split.setStretchFactor(0, 1)
        split.setStretchFactor(1, 2)
        layout.addWidget(split, stretch=1)

        row = QHBoxLayout()
        self._refresh_btn = QPushButton("Refresh")
        self._refresh_btn.clicked.connect(self.refresh)
        self._folder_btn = QPushButton("Open workspace folder")
        self._folder_btn.clicked.connect(self._open_folder)
        self._telegram_btn = QPushButton("Send summary to Telegram")
        self._telegram_btn.clicked.connect(self._send_telegram)
        row.addWidget(self._refresh_btn)
        row.addWidget(self._folder_btn)
        row.addWidget(self._telegram_btn)
        layout.addLayout(row)

        self._target_dir = ""
        self._host = ""

    def set_context(self, target_dir: str, host: str = "") -> None:
        self._target_dir = target_dir or ""
        self._host = host or ""
        self.refresh()

    def focus_artifact(self, filename: str) -> bool:
        """Select a workspace file in the list and show it in the preview pane."""
        if not self._target_dir:
            return False
        path = os.path.join(self._target_dir, filename)
        if not os.path.isfile(path):
            self.refresh()
            path = os.path.join(self._target_dir, filename)
        if not os.path.isfile(path):
            return False
        for i in range(self._files.count()):
            item = self._files.item(i)
            if item and item.data(256) == path:
                self._files.setCurrentItem(item)
                self._preview_file_item(item)
                return True
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                self._preview.setPlainText(fh.read(50000))
        except OSError as exc:
            self._preview.setPlainText(str(exc))
        return True

    def refresh(self) -> None:
        view = collect_workspace_view(self._target_dir, self._host)
        self._summary.setPlainText(format_results_summary(view))

        self._tools.clear()
        for t in view.get("next_tools") or []:
            name = t.get("gui_name", "?")
            reason = (t.get("reason") or "")[:60]
            item = QListWidgetItem(f"[{t.get('priority', '?')}] {name} — {reason}")
            pid = t.get("page_id") or page_id_for_tool_name(name)
            item.setData(256, pid or "")
            self._tools.addItem(item)
        if self._tools.count() == 0:
            item = QListWidgetItem("(run a tool — recommendations appear here)")
            item.setFlags(Qt.ItemFlag.NoItemFlags)
            self._tools.addItem(item)

        self._files.clear()
        for h in view.get("highlights") or []:
            item = QListWidgetItem(f"★ {h.get('file')}")
            item.setData(256, h.get("path"))
            item.setData(257, True)
            self._files.addItem(item)
        for f in view.get("files") or []:
            rel = f.get("rel", "")
            if rel.startswith("snapshots/") or rel in {x["file"] for x in view.get("highlights") or []}:
                continue
            item = QListWidgetItem(rel)
            item.setData(256, f.get("path"))
            self._files.addItem(item)

    def _on_tool_click(self, item: QListWidgetItem) -> None:
        pid = item.data(256)
        if pid:
            self.navigate_requested.emit(str(pid))

    def _preview_file_item(self, item: QListWidgetItem) -> None:
        path = item.data(256)
        if not path:
            return
        if item.data(257) and os.path.isdir(path):
            names = os.listdir(path)[:40]
            self._preview.setPlainText("\n".join(names) or "(empty)")
            return
        if os.path.isfile(path):
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    self._preview.setPlainText(fh.read(50000))
            except OSError as exc:
                self._preview.setPlainText(str(exc))

    def _open_file_item(self, item: QListWidgetItem) -> None:
        from gui.widgets.artifact_panel import ArtifactPanel

        path = item.data(256)
        if path:
            ArtifactPanel._open_path(path)

    def _open_folder(self) -> None:
        from gui.widgets.artifact_panel import ArtifactPanel

        if self._target_dir and os.path.isdir(self._target_dir):
            ArtifactPanel._open_path(self._target_dir)

    def _send_telegram(self) -> None:
        from core.notify import send_telegram_message, telegram_configured, telegram_placeholder_keys_present
        from gui.workspace_hub import build_telegram_digest

        if not telegram_configured() or telegram_placeholder_keys_present():
            QMessageBox.warning(
                self,
                "Telegram",
                "Telegram not configured. Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in Settings.",
            )
            return
        text = build_telegram_digest(self._target_dir, self._host)
        if send_telegram_message(text):
            QMessageBox.information(self, "Telegram", "Summary sent to your Telegram chat.")
        else:
            QMessageBox.warning(self, "Telegram", "Failed to send message. Check logs/telegram.log.")
