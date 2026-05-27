"""Utility pages — direct camera, update tools, test scripts."""

from __future__ import annotations

import subprocess
import sys

from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core.paths import project_root
from gui.session import GuiSession
from gui.workers.scan_worker import ScanJob, ScanWorker


class DirectCameraPage(QWidget):
    run_requested = pyqtSignal = None  # set by main window

    def __init__(self, session: GuiSession, parent=None):
        super().__init__(parent)
        self._session = session
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("<h2>Direct Camera (VLC)</h2>"))
        self._url = QLineEdit()
        self._url.setPlaceholderText("http://user:pass@IP or IP")
        layout.addWidget(self._url)
        self._run_btn = QPushButton("Run direct view")
        self._run_btn.clicked.connect(self._run)
        layout.addWidget(self._run_btn)

    def _run(self):
        url = self._url.text().strip() or self._session.target
        if not url:
            QMessageBox.warning(self, "URL", "Enter camera URL.")
            return

        def task():
            from bin.direct_camera import direct_view

            direct_view(url)

        return task


class UtilitiesMixin:
    """Shared run helper for utility pages."""

    @staticmethod
    def make_custom_page(session, title, description, task_fn, label="utility"):
        from PyQt6.QtCore import pyqtSignal
        from PyQt6.QtWidgets import QWidget

        class Page(QWidget):
            run_requested = pyqtSignal(object)

            def __init__(self, parent=None):
                super().__init__(parent)
                self._session = session
                lay = QVBoxLayout(self)
                lay.addWidget(QLabel(f"<h2>{title}</h2>"))
                lay.addWidget(QLabel(description))
                self._target = QLineEdit()
                self._target.setPlaceholderText("Target IP (optional if set in bar)")
                lay.addWidget(self._target)
                btn = QPushButton("Run")
                btn.clicked.connect(self._go)
                lay.addWidget(btn)

            def _go(self):
                t = self._target.text().strip() or self._session.target
                if not t:
                    QMessageBox.warning(self, "Target", "Enter target IP.")
                    return

                def task():
                    task_fn(t)

                job = ScanJob(kind="custom", label=label, custom_fn=task)
                w = ScanWorker(self._session, job, self)
                self.run_requested.emit(w)
                w.start()

        return Page


def build_test_router_page(session: GuiSession):
    def run_test(ip: str):
        subprocess.run(
            [sys.executable, "tests/test_router_target.py", "-H", ip],
            cwd=project_root(),
            check=False,
        )

    return UtilitiesMixin.make_custom_page(
        session,
        "Test Router",
        "Netis/router credential test.",
        run_test,
        "test-router",
    )


def build_test_hikvision_page(session: GuiSession):
    def run_test(ip: str):
        subprocess.run(
            [sys.executable, "tests/test_hikvision_target.py", "-H", ip],
            cwd=project_root(),
            check=False,
        )

    return UtilitiesMixin.make_custom_page(
        session,
        "Test Hikvision",
        "Hikvision backdoor + Digest test.",
        run_test,
        "test-hikvision",
    )


def build_test_cve_page(session: GuiSession):
    def run_test(ip: str):
        subprocess.run(
            [sys.executable, "tests/test_device_cve.py", "-H", ip],
            cwd=project_root(),
            check=False,
        )

    return UtilitiesMixin.make_custom_page(
        session,
        "CVE Report",
        "CVE intelligence report for target.",
        run_test,
        "test-cve",
    )


def build_update_tools_page(session: GuiSession):
    from PyQt6.QtCore import pyqtSignal
    from PyQt6.QtWidgets import QWidget

    class Page(QWidget):
        run_requested = pyqtSignal(object)

        def __init__(self, parent=None):
            super().__init__(parent)
            self._session = session
            lay = QVBoxLayout(self)
            lay.addWidget(QLabel("<h2>Update Tools</h2>"))
            lay.addWidget(QLabel("Git pull project + external tools (scripts/update_tools.py)."))
            btn = QPushButton("Run update")
            btn.clicked.connect(self._go)
            lay.addWidget(btn)

        def _go(self):
            def task():
                subprocess.run(
                    [sys.executable, "scripts/update_tools.py"],
                    cwd=project_root(),
                    check=False,
                )

            job = ScanJob(kind="custom", label="update-tools", custom_fn=task)
            w = ScanWorker(self._session, job, self)
            self.run_requested.emit(w)
            w.start()

    return Page
