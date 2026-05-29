"""AI Guided Scan — autonomous orchestrator loop + comprehensive report."""

from __future__ import annotations

import os

from PyQt6.QtCore import QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core.ai.orchestrator import load_orchestrator_progress
from core.scan_cancel import cancel_job
from gui.session import GuiSession
from gui.widgets.artifact_panel import ArtifactPanel
from gui.widgets.target_banner import TargetBanner
from gui.workers.scan_worker import ScanJob, ScanWorker

AI_REPORT_FILE = "AI_COMPREHENSIVE_REPORT.txt"


class AiGuidedPage(QWidget):
    run_requested = pyqtSignal(object)
    show_report_in_results = pyqtSignal()

    def __init__(self, session: GuiSession, parent=None):
        super().__init__(parent)
        self._session = session
        self._worker: ScanWorker | None = None
        self._max_steps = 12

        layout = QVBoxLayout(self)
        self._banner = TargetBanner(session)
        layout.addWidget(self._banner)

        layout.addWidget(QLabel("<h2>AI Guided Scan</h2>"))
        layout.addWidget(
            QLabel(
                "<b>وضع Hybrid (افتراضي):</b> Nmap والأدوات تُشغَّل <b>محلياً</b> — "
                "الـ AI يُستدعى فقط عند غموض الخطوة التالية + تقرير عربي واحد في النهاية.<br><br>"
                "• <code>AI_ORCHESTRATOR_MODE=hybrid</code> في <code>.env</code> "
                "(أو <code>local_rules</code> / <code>full_ai</code>)<br>"
                "• مفاتيح AI في <code>.env</code> ثم <b>Settings → Pull .env from file</b><br>"
                "• راوتر مع دخول: <code>http://user:pass@IP/</code><br>"
                "• للمسح الأسرع: اختر <b>Normal</b> من شريط الأدوات (Deep يشغّل Masscan أولاً)"
            )
        )

        self._progress = QProgressBar()
        self._progress.setMaximum(12)
        self._progress.setValue(0)
        self._progress.setFormat("في الانتظار…")
        self._progress.setTextVisible(True)
        layout.addWidget(self._progress)

        self._step_label = QLabel("")
        self._step_label.setWordWrap(True)
        layout.addWidget(self._step_label)

        row = QHBoxLayout()
        self._run_btn = QPushButton("Start AI Guided Scan")
        self._run_btn.clicked.connect(self._start)
        row.addWidget(self._run_btn)

        self._cancel_btn = QPushButton("Cancel")
        self._cancel_btn.setEnabled(False)
        self._cancel_btn.clicked.connect(self._cancel)
        row.addWidget(self._cancel_btn)
        layout.addLayout(row)

        report_row = QHBoxLayout()
        self._open_report_btn = QPushButton("Open report (external)")
        self._open_report_btn.setEnabled(False)
        self._open_report_btn.clicked.connect(self._open_report_external)
        report_row.addWidget(self._open_report_btn)

        self._results_btn = QPushButton("View report in Results tab")
        self._results_btn.setEnabled(False)
        self._results_btn.clicked.connect(self.show_report_in_results.emit)
        report_row.addWidget(self._results_btn)
        layout.addLayout(report_row)

        self._hint = QLabel("")
        self._hint.setWordWrap(True)
        layout.addWidget(self._hint)
        layout.addStretch()

        self._poll = QTimer(self)
        self._poll.setInterval(500)
        self._poll.timeout.connect(self._poll_progress)

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._banner.refresh()
        self._load_max_steps_hint()
        if self._worker and self._worker.isRunning():
            self._poll.start()
            self._poll_progress()
        else:
            self._refresh_idle_progress()

    def _load_max_steps_hint(self) -> None:
        try:
            from core.ai.analyst import ai_configured, ai_llm_available, ai_provider_status
            import os as _os

            self._max_steps = int(_os.environ.get("AI_ORCHESTRATOR_MAX_STEPS", "12"))
            self._progress.setMaximum(self._max_steps)
            mode = _os.environ.get("AI_ORCHESTRATOR_MODE", "hybrid").strip().lower()

            if ai_llm_available():
                self._hint.setText(
                    f"Mode: {mode} | LLM: {ai_provider_status()} — "
                    f"local tools first, up to {self._max_steps} steps."
                )
            elif ai_configured():
                self._hint.setText(
                    f"Keys present but LLM unavailable — heuristics only. "
                    f"Add AI_SKIP_OPENROUTER=1 and AI_PROVIDER_ORDER=gemini,openrouter to .env"
                )
            else:
                self._hint.setText(
                    f"No valid AI key — local heuristics + offline report (max {self._max_steps} steps)."
                )
        except Exception:
            pass

    def _report_path(self) -> str:
        if not self._session.target_dir:
            return ""
        return os.path.join(self._session.target_dir, AI_REPORT_FILE)

    def _open_report_external(self) -> None:
        path = self._report_path()
        if path and os.path.isfile(path):
            ArtifactPanel._open_path(path)
        else:
            QMessageBox.information(
                self,
                "Report",
                f"{AI_REPORT_FILE} not found yet. Run a scan or wait until it finishes.",
            )

    def _refresh_idle_progress(self) -> None:
        if not self._session.target_dir:
            self._progress.setValue(0)
            self._progress.setFormat("في الانتظار…")
            self._step_label.setText("")
            return
        prog = load_orchestrator_progress(self._session.target_dir)
        if prog.get("finished"):
            self._apply_progress(prog)
            self._enable_report_buttons(os.path.isfile(self._report_path()))
        else:
            self._progress.setValue(0)
            self._progress.setFormat("جاهز للتشغيل")
            self._step_label.setText("")

    def _apply_progress(self, prog: dict) -> None:
        step = int(prog.get("step") or 0)
        max_steps = int(prog.get("max_steps") or self._max_steps)
        self._progress.setMaximum(max(1, max_steps))
        phase = str(prog.get("phase") or "")
        tool = str(prog.get("current_tool") or prog.get("planned_tool") or "")
        reason = str(prog.get("last_reason") or "")
        finished = bool(prog.get("finished"))

        if finished:
            self._progress.setValue(max_steps)
            self._progress.setFormat("اكتمل ✓")
        elif phase == "report":
            self._progress.setValue(max_steps)
            self._progress.setFormat("توليد التقرير…")
        elif step > 0:
            self._progress.setValue(min(step, max_steps))
            self._progress.setFormat(f"خطوة {step} / {max_steps}")
        else:
            self._progress.setValue(0)
            self._progress.setFormat("بدء…")

        parts = []
        if phase:
            labels = {
                "starting": "بدء",
                "deciding": "اختيار الأداة",
                "running": "تنفيذ",
                "report": "تقرير نهائي",
                "done": "منتهي",
            }
            parts.append(labels.get(phase, phase))
        if tool:
            parts.append(f"أداة: <b>{tool}</b>")
        if reason:
            parts.append(reason[:200])
        self._step_label.setText(" — ".join(parts) if parts else "")

    def _poll_progress(self) -> None:
        if not self._session.target_dir:
            return
        prog = load_orchestrator_progress(self._session.target_dir)
        if prog:
            self._apply_progress(prog)
        if prog.get("finished") and os.path.isfile(self._report_path()):
            self._enable_report_buttons(True)

    def _enable_report_buttons(self, enabled: bool) -> None:
        self._open_report_btn.setEnabled(enabled)
        self._results_btn.setEnabled(enabled)

    def _start(self) -> None:
        if not self._session.target.strip():
            QMessageBox.warning(self, "Target", "Enter target (IP or http://user:pass@IP/) and Apply.")
            return
        if not self._session.prepare():
            QMessageBox.warning(self, "Workspace", "Could not prepare workspace.")
            return
        self._banner.refresh()
        self._session.set_profile(self._session.profile or "normal")
        self._enable_report_buttons(False)
        self._progress.setValue(0)
        self._progress.setFormat("بدء…")
        self._step_label.setText("جاري تشغيل المنسّق…")

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
        self._hint.setText("AI Guided Scan running — Live Log below. Progress updates here.")
        self._poll.start()
        self.run_requested.emit(self._worker)
        self._worker.finished_ok.connect(self._on_done)
        self._worker.error.connect(self._on_error)
        self._worker.start()

    def _cancel(self) -> None:
        if self._worker:
            cancel_job(self._worker.job_id)

    def _on_done(self, _ok: bool, _msg: str) -> None:
        self._poll.stop()
        self._poll_progress()
        self._run_btn.setEnabled(True)
        self._cancel_btn.setEnabled(False)
        has_report = os.path.isfile(self._report_path())
        self._enable_report_buttons(has_report)
        if has_report:
            self._hint.setText(
                "Finished — use <b>Open report</b> or <b>View report in Results tab</b>."
            )
        else:
            self._hint.setText(
                "Finished — report file missing (check Live Log). Try Refresh on Results tab."
            )

    def _on_error(self, msg: str) -> None:
        self._poll.stop()
        QMessageBox.critical(self, "AI Guided Scan", msg)
        self._on_done(False, msg)
