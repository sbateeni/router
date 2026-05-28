"""Comprehensive scan — full classic, deep profile, 4-phase auto."""

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


class ComprehensivePage(QWidget):
    run_requested = pyqtSignal(object)

    def __init__(self, session: GuiSession, parent=None):
        super().__init__(parent)
        self._session = session
        self._worker: ScanWorker | None = None

        layout = QVBoxLayout(self)
        self._banner = QLabel()
        self._banner.setObjectName("targetBanner")
        self._banner.setWordWrap(True)
        layout.addWidget(self._banner)
        layout.addWidget(QLabel("<h2>Comprehensive Scan</h2>"))
        layout.addWidget(
            QLabel(
                "Runs the full classic pipeline (selection=1). Use <b>deep</b> profile "
                "in the target bar for deep/full merge. Artifacts chain across tools in the same workspace."
            )
        )

        row = QHBoxLayout()
        self._full_btn = QPushButton("Run Full Scan (normal profile)")
        self._full_btn.clicked.connect(lambda: self._start("normal"))
        self._deep_btn = QPushButton("Run Deep Scan")
        self._deep_btn.clicked.connect(lambda: self._start("deep"))
        self._auto_btn = QPushButton("Run 4-Phase Auto")
        self._auto_btn.clicked.connect(lambda: self._start("auto"))
        self._cancel_btn = QPushButton("Cancel")
        self._cancel_btn.setEnabled(False)
        self._cancel_btn.clicked.connect(self._cancel)
        row.addWidget(self._full_btn)
        row.addWidget(self._deep_btn)
        row.addWidget(self._auto_btn)
        row.addWidget(self._cancel_btn)
        layout.addLayout(row)

        self._hint = QLabel("")
        self._hint.setWordWrap(True)
        layout.addWidget(self._hint)
        layout.addStretch()
        self._refresh_banner()

    def _refresh_banner(self) -> None:
        t = self._session.target.strip() or "(set target above)"
        self._banner.setText(
            f"<b>Target:</b> <code>{t}</code> — full pipeline writes to "
            f"<code>{self._session.target_dir or '…'}</code>"
        )

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._refresh_banner()

    def _start(self, mode: str) -> None:
        if not self._session.target.strip():
            QMessageBox.warning(self, "Target required", "Enter a target and click Apply.")
            return
        if not self._session.prepare():
            QMessageBox.warning(self, "Workspace error", "Could not prepare target workspace.")
            return
        self._refresh_banner()
        if mode == "deep":
            self._session.set_profile("deep")
        elif mode == "normal":
            self._session.set_profile("normal")
        else:
            self._session.set_profile(self._session.profile)

        job = ScanJob(kind="comprehensive", label=f"comprehensive-{mode}")
        self._worker = ScanWorker(self._session, job, self)
        self._set_running(True)
        self._hint.setText(f"Running comprehensive scan ({mode})…")
        self.run_requested.emit(self._worker)
        self._worker.finished_ok.connect(self._on_done)
        self._worker.error.connect(self._on_error)
        self._worker.start()

    def _cancel(self) -> None:
        if self._worker:
            cancel_job(self._worker.job_id)

    def _set_running(self, running: bool) -> None:
        for btn in (self._full_btn, self._deep_btn, self._auto_btn):
            btn.setEnabled(not running)
        self._cancel_btn.setEnabled(running)

    def _on_done(self, ok: bool, msg: str) -> None:
        self._set_running(False)
        self._hint.setText(f"Finished ({msg}). Confirmed findings: {'yes' if ok else 'see logs'}")

    def _on_error(self, msg: str) -> None:
        self._set_running(False)
        QMessageBox.critical(self, "Scan error", msg)
