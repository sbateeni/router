"""Reusable page: run a single master_pwn tool selection."""

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
        self._selection = selection
        self._kind = kind
        self._manual_mode = manual_mode
        self._worker: ScanWorker | None = None

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(f"<h2>{title}</h2>"))
        layout.addWidget(QLabel(description))
        layout.addWidget(QLabel(f"<i>Uses workspace artifacts when available.</i>"))

        row = QHBoxLayout()
        self._run_btn = QPushButton("Run")
        self._run_btn.clicked.connect(self._start)
        self._cancel_btn = QPushButton("Cancel")
        self._cancel_btn.setEnabled(False)
        self._cancel_btn.clicked.connect(self._cancel)
        row.addWidget(self._run_btn)
        row.addWidget(self._cancel_btn)
        row.addStretch()
        layout.addLayout(row)
        layout.addStretch()

    def _start(self) -> None:
        if not self._session.target.strip():
            QMessageBox.warning(self, "Target required", "Enter a target in the bar above and click Apply.")
            return
        job = ScanJob(
            kind=self._kind,
            label=self.windowTitle() or "scan",
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

    def _on_error(self, msg: str) -> None:
        QMessageBox.critical(self, "Scan error", msg)
        self._run_btn.setEnabled(True)
        self._cancel_btn.setEnabled(False)
