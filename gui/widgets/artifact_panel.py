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
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

KEY_ARTIFACTS = (
    "nmap_scan.txt",
    "ingram_scan.txt",
    "workflow_recommendations.json",
    "hikvision_test_report.json",
    "recon_summary.json",
    "target_profile.json",
    "NMAP_OPEN_PORTS.json",
    "target_hints.json",
    "AI_ANALYSIS.txt",
    "hydra_iot_passwords.txt",
    "RESULTS_SUMMARY.txt",
)


class ArtifactPanel(QWidget):
    workspace_changed = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self._label = QLabel("Workspace artifacts")
        layout.addWidget(self._label)
        self._list = QListWidget()
        self._list.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self._list.itemDoubleClicked.connect(self._open_selected)
        layout.addWidget(self._list, stretch=1)
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
        root = self._target_dir
        for name in sorted(os.listdir(root)):
            path = os.path.join(root, name)
            if os.path.isfile(path):
                prefix = "★ " if name in KEY_ARTIFACTS else ""
                item = QListWidgetItem(f"{prefix}{name}")
                item.setData(256, path)
                self._list.addItem(item)
            elif os.path.isdir(path) and name in ("snapshots", "ingram_results"):
                for child in sorted(os.listdir(path))[:80]:
                    cp = os.path.join(path, child)
                    if os.path.isfile(cp):
                        rel = f"{name}/{child}"
                        item = QListWidgetItem(f"★ {rel}" if name == "snapshots" else rel)
                        item.setData(256, cp)
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
