"""AI Guided Scan — autonomous orchestrator loop + comprehensive report."""

from __future__ import annotations

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QLabel,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core.scan_cancel import cancel_job
from gui.session import GuiSession
from gui.widgets.target_banner import TargetBanner
from gui.workers.scan_worker import ScanJob, ScanWorker


class AiGuidedPage(QWidget):
    run_requested = pyqtSignal(object)

    def __init__(self, session: GuiSession, parent=None):
        super().__init__(parent)
        self._session = session
        self._worker: ScanWorker | None = None

        layout = QVBoxLayout(self)
        self._banner = TargetBanner(session)
        layout.addWidget(self._banner)

        layout.addWidget(QLabel("<h2>AI Guided Scan</h2>"))
        layout.addWidget(
            QLabel(
                "<b>حلقة ذكية مغلقة:</b> يجمع حالة الـ workspace → AI (أو قواعد محلية) يختار "
                "الأداة التالية → تنفيذ → تكرار → <code>AI_COMPREHENSIVE_REPORT.txt</code>.<br><br>"
                "• ضع مفتاح <code>OPENROUTER_API_KEY</code> أو <code>GEMINI_API_KEY</code> في <code>.env</code><br>"
                "• للراوتر مع دخول: <code>http://user:pass@IP/</code> في شريط الهدف<br>"
                "• يشغّل تلقائياً: Nmap, Nuclei, Hydra, Harvest, Hikvision, … حسب الحالة"
            )
        )

        self._run_btn = QPushButton("Start AI Guided Scan")
        self._run_btn.clicked.connect(self._start)
        layout.addWidget(self._run_btn)

        self._cancel_btn = QPushButton("Cancel")
        self._cancel_btn.setEnabled(False)
        self._cancel_btn.clicked.connect(self._cancel)
        layout.addWidget(self._cancel_btn)

        self._hint = QLabel("")
        self._hint.setWordWrap(True)
        layout.addWidget(self._hint)
        layout.addStretch()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._banner.refresh()
        try:
            from core.ai.analyst import ai_configured

            if ai_configured():
                self._hint.setText("AI API configured — full LLM orchestration enabled.")
            else:
                self._hint.setText(
                    "No valid AI key — orchestrator will use local heuristics + offline report template."
                )
        except Exception:
            pass

    def _start(self) -> None:
        if not self._session.target.strip():
            QMessageBox.warning(self, "Target", "Enter target (IP or http://user:pass@IP/) and Apply.")
            return
        if not self._session.prepare():
            QMessageBox.warning(self, "Workspace", "Could not prepare workspace.")
            return
        self._banner.refresh()
        self._session.set_profile(self._session.profile or "normal")

        def task():
            from core.ai.orchestrator import run_ai_guided_scan

            return run_ai_guided_scan(
                self._session.scan_host or self._session.target,
                self._session.target_dir,
                raw_target=self._session.target,
                profile=self._session.profile,
            )

        job = ScanJob(kind="custom", label="ai-guided-scan", custom_fn=task)
        self._worker = ScanWorker(self._session, job, self)
        self._run_btn.setEnabled(False)
        self._cancel_btn.setEnabled(True)
        self._hint.setText("AI Guided Scan running — see Live Log. Results tab when finished.")
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
        self._hint.setText(
            "Finished — open <b>Results</b> tab and read "
            "<code>AI_COMPREHENSIVE_REPORT.txt</code> in artifacts."
        )

    def _on_error(self, msg: str) -> None:
        QMessageBox.critical(self, "AI Guided Scan", msg)
        self._on_done(False, msg)
