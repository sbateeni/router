"""Live scan log viewer — tails logs/LIVE_SCAN*.log."""

from __future__ import annotations

import os

from PyQt6.QtCore import QFileSystemWatcher, QTimer
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QTextEdit, QVBoxLayout, QWidget

from core.live_scan_log import path as live_log_path
from core.paths import logs_dir


class LogPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        title_row = QHBoxLayout()
        self._title = QLabel("Live log")
        self._copy_btn = QPushButton("Copy all")
        self._copy_btn.clicked.connect(self.copy_all)
        self._clear_btn = QPushButton("Clear view")
        self._clear_btn.clicked.connect(self._text.clear)
        title_row.addWidget(self._title)
        title_row.addStretch()
        title_row.addWidget(self._copy_btn)
        title_row.addWidget(self._clear_btn)
        layout.addLayout(title_row)
        self._text = QTextEdit()
        self._text.setReadOnly(True)
        self._text.setFont(QFont("Consolas", 11))
        layout.addWidget(self._text)
        self._path = live_log_path()
        self._offset = 0
        self._watcher = QFileSystemWatcher(self)
        self._timer = QTimer(self)
        self._timer.setInterval(500)
        self._timer.timeout.connect(self._poll)
        self._watcher.fileChanged.connect(self._on_file_changed)

    def start_tailing(self, job_id: str | None = None) -> None:
        if job_id:
            safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in job_id)
            self._path = os.path.join(logs_dir(), f"LIVE_SCAN_{safe}.log")
        else:
            self._path = live_log_path()
        self._offset = 0
        self._text.clear()
        self._title.setText(f"Live log — {os.path.basename(self._path)}")
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        if not os.path.isfile(self._path):
            open(self._path, "a", encoding="utf-8").close()
        if self._watcher.files():
            self._watcher.removePaths(self._watcher.files())
        self._watcher.addPath(self._path)
        self._timer.start()
        self._poll()

    def stop_tailing(self) -> None:
        self._timer.stop()
        if self._watcher.files():
            self._watcher.removePaths(self._watcher.files())

    def append(self, text: str) -> None:
        self._text.moveCursor(self._text.textCursor().MoveOperation.End)
        self._text.insertPlainText(text)
        self._text.moveCursor(self._text.textCursor().MoveOperation.End)

    def copy_all(self) -> None:
        self._text.selectAll()
        self._text.copy()
        cursor = self._text.textCursor()
        cursor.clearSelection()
        self._text.setTextCursor(cursor)

    def _on_file_changed(self, path: str) -> None:
        if path == self._path and path not in self._watcher.files():
            self._watcher.addPath(path)
        self._poll()

    def _poll(self) -> None:
        if not os.path.isfile(self._path):
            return
        try:
            size = os.path.getsize(self._path)
            if size < self._offset:
                self._offset = 0
            if size == self._offset:
                return
            with open(self._path, "r", encoding="utf-8", errors="ignore") as fh:
                fh.seek(self._offset)
                chunk = fh.read()
                self._offset = fh.tell()
            if chunk:
                self.append(chunk)
        except OSError:
            pass
