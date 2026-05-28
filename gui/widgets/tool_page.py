"""Reusable page: run a single master_pwn tool selection (target-aware + chaining)."""

from __future__ import annotations

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core.scan_cancel import cancel_job
from gui.session import GuiSession
from gui.workers.scan_worker import ScanJob, ScanWorker


class ToolPage(QWidget):
    run_requested = pyqtSignal(object)  # ScanWorker

    def __init__(
        self,
        session: GuiSession,
        *,
        title: str,
        description: str,
        selection: int | None = None,
        kind: str = "tool",
        manual_mode: bool = False,
        parent=None,
    ):
        super().__init__(parent)
        self._session = session
        self._title = title
        self._selection = selection
        self._kind = kind
        self._manual_mode = manual_mode
        self._worker: ScanWorker | None = None

        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        self._banner = QLabel()
        self._banner.setObjectName("targetBanner")
        self._banner.setWordWrap(True)
        layout.addWidget(self._banner)

        layout.addWidget(QLabel(f"<h2 style='margin:0'>{title}</h2>"))
        layout.addWidget(QLabel(description))
        self._chain_note = QLabel(
            "<i>Uses the target from the top bar and reuses artifacts "
            "(Nmap, Hydra wordlists, profiles) from the same workspace.</i>"
        )
        self._chain_note.setWordWrap(True)
        layout.addWidget(self._chain_note)

        row = QHBoxLayout()
        self._run_btn = QPushButton("Run on target")
        self._run_btn.clicked.connect(self._start)
        self._cancel_btn = QPushButton("Cancel")
        self._cancel_btn.setObjectName("secondaryBtn")
        self._cancel_btn.setEnabled(False)
        self._cancel_btn.clicked.connect(self._cancel)
        row.addWidget(self._run_btn)
        row.addWidget(self._cancel_btn)
        row.addStretch()
        layout.addLayout(row)
        layout.addStretch()
        self.refresh_context()

    def refresh_context(self) -> None:
        t = self._session.target.strip() or "(no target — set above and Apply)"
        prof = self._session.profile
        ws = self._session.target_dir or "workspace not created yet"
        self._banner.setText(
            f"<b>Active target:</b> <code>{t}</code> &nbsp;|&nbsp; "
            f"<b>Profile:</b> {prof}<br>"
            f"<span style='color:#8b95a5'>Workspace: {ws}</span>"
        )

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self.refresh_context()

    def _start(self) -> None:
        if not self._session.target.strip():
            QMessageBox.warning(
                self,
                "Target required",
                "Enter the IP/URL in the top bar (e.g. 188.225.140.99) and click Apply target.",
            )
            return
        if not self._session.prepare():
            QMessageBox.warning(self, "Workspace error", "Could not prepare target workspace.")
            return
        self.refresh_context()
        job = ScanJob(
            kind=self._kind,
            label=self._title,
            selection=self._selection,
            manual_mode=self._manual_mode,
        )
        self._worker = ScanWorker(self._session, job, self)
        self._run_btn.setEnabled(False)
        self._cancel_btn.setEnabled(True)
        self.run_requested.emit(self._worker)
        self._worker.finished_ok.connect(self._on_done)
        self._worker.error.connect(self._on_error)
        self._worker.start()

    def _cancel(self) -> None:
        if self._worker:
            cancel_job(self._worker.job_id)

    def _on_done(self, _ok: bool, _msg: str) -> None:
        self._run_btn.setEnabled(True)
        self._cancel_btn.setEnabled(False)
        self.refresh_context()

    def _on_error(self, msg: str) -> None:
        QMessageBox.critical(self, "Scan error", msg)
        self._run_btn.setEnabled(True)
        self._cancel_btn.setEnabled(False)
