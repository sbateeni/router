"""Target History — list saved sessions and restore workspace + target bar."""

from __future__ import annotations

import os

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.paths import project_root
from core.target_history import list_sessions
from gui.session import GuiSession
from gui.widgets.target_banner import TargetBanner


class HistoryPage(QWidget):
    target_selected = pyqtSignal(str)

    def __init__(self, session: GuiSession, parent=None):
        super().__init__(parent)
        self._session = session
        self._rows: list[dict] = []

        layout = QVBoxLayout(self)
        self._banner = TargetBanner(session)
        layout.addWidget(self._banner)

        layout.addWidget(QLabel("<h2>Target History</h2>"))
        layout.addWidget(
            QLabel(
                "Saved when you <b>Apply target</b> or finish a scan. "
                "<b>Restore</b> loads the IP and workspace artifacts (Keep artifacts on)."
            )
        )

        row = QHBoxLayout()
        self._refresh_btn = QPushButton("Refresh list")
        self._refresh_btn.setObjectName("secondaryBtn")
        self._refresh_btn.clicked.connect(self.refresh)
        self._restore_btn = QPushButton("Restore session")
        self._restore_btn.clicked.connect(self._restore_selected)
        self._open_btn = QPushButton("Open workspace folder")
        self._open_btn.setObjectName("secondaryBtn")
        self._open_btn.clicked.connect(self._open_folder)
        row.addWidget(self._refresh_btn)
        row.addWidget(self._restore_btn)
        row.addWidget(self._open_btn)
        row.addStretch()
        layout.addLayout(row)

        self._table = QTableWidget(0, 6)
        self._table.setHorizontalHeaderLabels(
            ["Target", "Status", "Profile", "Artifacts", "Last seen", "Workspace"]
        )
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._table.doubleClicked.connect(self._restore_selected)
        layout.addWidget(self._table)

        self._hint = QLabel("")
        self._hint.setWordWrap(True)
        layout.addWidget(self._hint)

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._banner.refresh()
        self.refresh()

    def refresh(self) -> None:
        self._rows = list_sessions(merge_workspaces=True)
        self._table.setRowCount(0)
        for s in self._rows:
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setItem(row, 0, QTableWidgetItem(s.get("target", "?")))
            self._table.setItem(row, 1, QTableWidgetItem(str(s.get("status", "?"))))
            self._table.setItem(row, 2, QTableWidgetItem(str(s.get("profile", "?"))))
            self._table.setItem(row, 3, QTableWidgetItem(str(s.get("artifact_count", 0))))
            last = s.get("last_seen") or "—"
            self._table.setItem(row, 4, QTableWidgetItem(last))
            ws = s.get("workspace_name") or "?"
            self._table.setItem(row, 5, QTableWidgetItem(ws))

        if not self._rows:
            self._hint.setText(
                "No sessions yet. Enter a target above → Apply target, or run any scan. "
                f"Index file: <code>{os.path.join(project_root(), 'db', 'sessions_index.json')}</code>"
            )
        else:
            self._hint.setText(f"{len(self._rows)} session(s) — double-click a row to restore.")

    def _selected(self) -> dict | None:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return None
        idx = rows[0].row()
        if 0 <= idx < len(self._rows):
            return self._rows[idx]
        return None

    def _restore_selected(self) -> None:
        entry = self._selected()
        if not entry:
            QMessageBox.information(self, "History", "Select a row first.")
            return

        target = entry.get("target") or entry.get("scan_host", "")
        if not target:
            return

        profile = entry.get("profile")
        if profile in ("normal", "deep"):
            self._session.set_profile(profile)

        self._session.target = target
        self._session.keep_artifacts = True
        self._session._prepared = False
        if not self._session.prepare(force_reset=False):
            QMessageBox.warning(self, "Restore failed", "Could not open workspace.")
            return

        self._banner.refresh()
        self.target_selected.emit(target)
        QMessageBox.information(
            self,
            "Session restored",
            f"Target: {target}\nWorkspace: {self._session.target_dir}\n"
            "Artifacts from previous scans are available to other tools.",
        )

    def _open_folder(self) -> None:
        entry = self._selected()
        if not entry:
            QMessageBox.information(self, "History", "Select a row first.")
            return
        path = entry.get("target_dir", "")
        if not path or not os.path.isdir(path):
            QMessageBox.warning(self, "Folder", "Workspace folder not found.")
            return
        from gui.widgets.artifact_panel import ArtifactPanel

        ArtifactPanel._open_path(path)
