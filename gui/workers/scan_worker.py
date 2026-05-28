"""Background QThread for long-running scans."""

from __future__ import annotations

import os
import threading
import uuid
from dataclasses import dataclass
from typing import Any, Callable

from PyQt6.QtCore import QThread, pyqtSignal

from gui.bridge.input_bridge import install_gui_bridge, uninstall_gui_bridge
from gui.session import GuiSession


@dataclass
class ScanJob:
    kind: str  # tool | comprehensive | engine | custom
    label: str = ""
    selection: int | None = None
    manual_mode: bool = False
    known_open_ports: list[int] | None = None
    custom_fn: Callable[[], Any] | None = None


class ScanWorker(QThread):
    _run_lock = threading.Lock()
    _active_job_id: str | None = None

    log_line = pyqtSignal(str)
    finished_ok = pyqtSignal(bool, str)
    error = pyqtSignal(str)

    def __init__(self, session: GuiSession, job: ScanJob, parent=None):
        super().__init__(parent)
        self._session = session
        self._job = job
        self._job_id = f"gui-{uuid.uuid4().hex[:12]}"

    @property
    def job_id(self) -> str:
        return self._job_id

    def run(self) -> None:
        previous_env = {
            "AUTOPWN_GUI": os.environ.get("AUTOPWN_GUI"),
            "AUTOPWN_LIVE_WINDOW": os.environ.get("AUTOPWN_LIVE_WINDOW"),
            "AUTOPWN_JOB_ID": os.environ.get("AUTOPWN_JOB_ID"),
            "AUTOPWN_SCAN_SOURCE": os.environ.get("AUTOPWN_SCAN_SOURCE"),
            "ENGINE_WORKSPACE": os.environ.get("ENGINE_WORKSPACE"),
        }

        if not self._acquire_slot():
            self.error.emit("Another scan is already running. Wait or cancel it first.")
            self.finished_ok.emit(False, "busy")
            return

        os.environ["AUTOPWN_GUI"] = "1"
        os.environ["AUTOPWN_LIVE_WINDOW"] = "0"
        os.environ["AUTOPWN_JOB_ID"] = self._job_id
        os.environ["AUTOPWN_SCAN_SOURCE"] = "gui"
        install_gui_bridge()

        from core.scan_cancel import ScanCancelled, finish_job, start_job

        start_job(self._job_id, meta={"label": self._job.label})
        try:
            if not self._session.prepare():
                self.error.emit("No target configured.")
                return
            os.environ["ENGINE_WORKSPACE"] = self._session.target_dir
            self._session.set_profile(self._session.profile)
            result = self._execute()
            self.finished_ok.emit(bool(result), self._job.label or "done")
        except ScanCancelled:
            self.log_line.emit("[!] Scan cancelled by user.\n")
            self.finished_ok.emit(False, "cancelled")
        except Exception as exc:
            self.error.emit(str(exc))
            self.finished_ok.emit(False, str(exc))
        finally:
            try:
                if self._session.target_dir and self._session.scan_host:
                    from core.target_history import record_session

                    record_session(
                        target=self._session.target,
                        scan_host=self._session.scan_host,
                        workspace_name=self._session.workspace_name,
                        target_dir=self._session.target_dir,
                        profile=self._session.profile,
                        status="SCANNED",
                        note=self._job.label or "",
                    )
            except Exception:
                pass
            finish_job(self._job_id)
            uninstall_gui_bridge()
            self._restore_env(previous_env)
            self._release_slot()

    def _execute(self) -> Any:
        job = self._job
        session = self._session
        scan_host = session.scan_host
        target_dir = session.target_dir
        profile = session.profile
        subnet = session.subnet or None

        if job.kind == "custom" and job.custom_fn:
            from core.live_scan_log import begin as live_begin, end as live_end, mirror_stdout

            label = job.label or "custom"
            host = session.scan_host or session.target or "?"
            live_begin(f"{host} | {label}", source="gui")
            try:
                with mirror_stdout():
                    result = job.custom_fn()
                if result is None:
                    return True
                return bool(result)
            finally:
                live_end()

        if job.kind == "engine":
            from engines.auto_pwn_main import main as engine_main

            target = session.target
            if not target.startswith("http"):
                target = f"http://{target}"
            engine_main(
                target,
                manual_mode=job.manual_mode,
                known_open_ports=job.known_open_ports,
            )
            return True

        if job.kind == "comprehensive":
            from core.runner import run_selected_tool
            from core.report import generate_scan_report

            selection = 1
            exploited = run_selected_tool(
                selection,
                scan_host,
                target_dir,
                profile=profile,
                subnet=subnet,
            )
            generate_scan_report(
                scan_host,
                target_dir,
                selection,
                exploited,
                current_phase="Completed",
                profile=profile,
            )
            return exploited

        if job.kind == "tool" and job.selection is not None:
            from core.runner import run_selected_tool

            if job.selection == 21:
                from core.runner import run_device_engine_only

                return run_device_engine_only(scan_host, target_dir, manual_mode=job.manual_mode)
            return run_selected_tool(
                job.selection,
                scan_host,
                target_dir,
                profile=profile,
                subnet=subnet,
            )

        raise ValueError(f"Unknown job kind: {job.kind}")

    @classmethod
    def _acquire_slot(cls) -> bool:
        with cls._run_lock:
            if cls._active_job_id:
                return False
            cls._active_job_id = "locked"
            return True

    @classmethod
    def _release_slot(cls) -> None:
        with cls._run_lock:
            cls._active_job_id = None

    @staticmethod
    def _restore_env(previous_env: dict[str, str | None]) -> None:
        for key, value in previous_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
