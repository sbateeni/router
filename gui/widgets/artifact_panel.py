"""Browse artifact files in the current target workspace."""

from __future__ import annotations

import os
import subprocess
import sys

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

KEY_ARTIFACTS = (
    "NMAP_OPEN_PORTS.json",
    "target_hints.json",
    "AI_ANALYSIS.txt",
    "hydra_iot_passwords.txt",
    "TARGET_PROFILE.json",
)


class ArtifactPanel(QWidget):
    workspace_changed = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self._label = QLabel("Workspace artifacts")
        layout.addWidget(self._label)
        self._list = QListWidget()
        self._list.itemDoubleClicked.connect(self._open_selected)
        layout.addWidget(self._list)
        row = QHBoxLayout()
        self._refresh_btn = QPushButton("Refresh")
        self._refresh_btn.clicked.connect(self.refresh)
        self._open_dir_btn = QPushButton("Open folder")
        self._open_dir_btn.clicked.connect(self._open_folder)
        row.addWidget(self._refresh_btn)
        row.addWidget(self._open_dir_btn)
        layout.addLayout(row)
        self._target_dir = ""

    def set_workspace(self, target_dir: str) -> None:
        self._target_dir = target_dir or ""
        self._label.setText(
            f"Workspace: {self._target_dir}" if self._target_dir else "Workspace artifacts (no target)"
        )
        self.refresh()
        self.workspace_changed.emit(self._target_dir)

    def refresh(self) -> None:
        self._list.clear()
        if not self._target_dir or not os.path.isdir(self._target_dir):
            return
        names = sorted(os.listdir(self._target_dir))
        for name in names:
            path = os.path.join(self._target_dir, name)
            if os.path.isfile(path):
                prefix = "★ " if name in KEY_ARTIFACTS else ""
                item = QListWidgetItem(f"{prefix}{name}")
                item.setData(256, path)
                self._list.addItem(item)

    def _open_selected(self, item: QListWidgetItem) -> None:
        path = item.data(256)
        if path and os.path.isfile(path):
            self._open_path(path)

    def _open_folder(self) -> None:
        if self._target_dir and os.path.isdir(self._target_dir):
            self._open_path(self._target_dir)

    @staticmethod
    def _open_path(path: str) -> None:
        try:
            if sys.platform == "win32":
                os.startfile(path)  # noqa: S606
            elif sys.platform == "darwin":
                subprocess.run(["open", path], check=False)
            else:
                subprocess.run(["xdg-open", path], check=False)
        except OSError:
            pass
