"""Utility pages — direct camera, update tools, test scripts."""

from __future__ import annotations

import os
import subprocess
import sys

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QLabel,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core.paths import project_root
from gui.session import GuiSession
from gui.util_runner import run_cve_test, run_hikvision_test, run_router_test
from gui.widgets.target_banner import TargetBanner
from gui.workers.scan_worker import ScanJob, ScanWorker


class DirectCameraPage(QWidget):
    run_requested = pyqtSignal(object)

    def __init__(self, session: GuiSession, parent=None):
        super().__init__(parent)
        self._session = session
        layout = QVBoxLayout(self)
        self._banner = TargetBanner(session)
        layout.addWidget(self._banner)
        layout.addWidget(QLabel("<h2>Direct Camera (VLC)</h2>"))
        layout.addWidget(
            QLabel(
                "Opens the camera from the <b>active target</b> (URL with creds in the top bar if needed)."
            )
        )
        self._run_btn = QPushButton("Run direct view on target")
        self._run_btn.clicked.connect(self._run)
        layout.addWidget(self._run_btn)
        layout.addStretch()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._banner.refresh()

    def _run(self) -> None:
        url = self._session.target.strip()
        if not url:
            QMessageBox.warning(self, "Target", "Set target in the top bar and click Apply.")
            return
        if not self._session.prepare():
            QMessageBox.warning(self, "Workspace", "Could not prepare workspace.")
            return

        def task():
            from engines.utils import log, extract_ip, extract_credentials
            from engines.camera_viewer import CameraViewer

            ip = extract_ip(url)
            if not ip:
                log("Invalid URL/IP in target bar.", "ERROR")
                return False
            user, pwd = extract_credentials(url)
            user = user or "admin"
            pwd = pwd or "12345"
            cam = CameraViewer(ip, user, pwd)
            cam.discover_channels()
            cam.take_snapshots()
            cam.print_summary()
            cam.open_in_vlc(use_sub_stream=True)
            return True

        self._start_worker("direct-camera", task)

    def _start_worker(self, label: str, fn) -> None:
        job = ScanJob(kind="custom", label=label, custom_fn=fn)
        worker = ScanWorker(self._session, job, self)
        self.run_requested.emit(worker)
        worker.start()


def _utility_test_page(
    session: GuiSession,
    title: str,
    description: str,
    label: str,
    script_path: str,
    runner,
):
    class Page(QWidget):
        run_requested = pyqtSignal(object)

        def __init__(self, parent=None):
            super().__init__(parent)
            self._session = session
            lay = QVBoxLayout(self)
            self._banner = TargetBanner(session)
            lay.addWidget(self._banner)
            lay.addWidget(QLabel(f"<h2>{title}</h2>"))
            lay.addWidget(QLabel(description))
            lay.addWidget(
                QLabel(
                    f"<i>Uses the IP from the top bar only. Script: "
                    f"<code>{script_path}</code> — output appears in Live Log.</i>"
                )
            )
            btn = QPushButton("Run on target")
            btn.clicked.connect(self._go)
            lay.addWidget(btn)
            lay.addStretch()

        def showEvent(self, event) -> None:
            super().showEvent(event)
            self._banner.refresh()

        def _go(self) -> None:
            if not self._session.target.strip():
                QMessageBox.warning(
                    self,
                    "Target",
                    "Enter IP in the top bar (e.g. 188.225.140.99) and click Apply target.",
                )
                return
            if not self._session.prepare():
                QMessageBox.warning(self, "Workspace", "Could not prepare workspace.")
                return
            self._banner.refresh()
            host = self._session.scan_host or self._session.target.strip()

            def task():
                print(f"[*] Running {title} on {host} ...\n")
                return runner(host)

            job = ScanJob(kind="custom", label=label, custom_fn=task)
            w = ScanWorker(self._session, job, self)
            self.run_requested.emit(w)
            w.start()

    return Page


def build_router_harvest_page(session: GuiSession):
    class Page(QWidget):
        run_requested = pyqtSignal(object)

        def __init__(self, parent=None):
            super().__init__(parent)
            self._session = session
            lay = QVBoxLayout(self)
            self._banner = TargetBanner(session)
            lay.addWidget(self._banner)
            lay.addWidget(QLabel("<h2>Router Deep Harvest</h2>"))
            lay.addWidget(
                QLabel(
                    "For an <b>already logged-in</b> router: put credentials in the top bar, "
                    "e.g. <code>http://guest:guest@188.225.140.99/</code>, click "
                    "<b>Apply target</b>, then <b>Run harvest</b>.<br><br>"
                    "Collects: device info, Wi‑Fi keys, DHCP/LAN clients, secrets in HTML, "
                    "CVE assessment, saves <code>ROUTER_HARVEST.txt</code> and page snapshots."
                )
            )
            btn = QPushButton("Run harvest on target")
            btn.clicked.connect(self._go)
            lay.addWidget(btn)
            lay.addStretch()

        def showEvent(self, event) -> None:
            super().showEvent(event)
            self._banner.refresh()

        def _go(self) -> None:
            raw = self._session.target.strip()
            if not raw:
                QMessageBox.warning(
                    self,
                    "Target",
                    "Enter http://user:pass@IP/ in the top bar and click Apply target.",
                )
                return
            from core.target_auth import parse_target_auth

            if not parse_target_auth(raw):
                QMessageBox.warning(
                    self,
                    "Credentials required",
                    "URL must include username and password, e.g.\n"
                    "http://guest:guest@188.225.140.99/",
                )
                return
            if not self._session.prepare():
                QMessageBox.warning(self, "Workspace", "Could not prepare workspace.")
                return
            self._banner.refresh()

            def task():
                from engines.router_harvest import run_router_harvest

                print(f"[*] Router deep harvest — {raw}\n")
                run_router_harvest(self._session.target_dir, raw)
                return True

            job = ScanJob(kind="custom", label="router-harvest", custom_fn=task)
            w = ScanWorker(self._session, job, self)
            self.run_requested.emit(w)
            w.start()

    return Page


def build_test_router_page(session: GuiSession):
    return _utility_test_page(
        session,
        "Test Router",
        "Netis/router credential test on the active target.",
        "test-router",
        "tests/test_router_target.py",
        run_router_test,
    )


def build_test_hikvision_page(session: GuiSession):
    return _utility_test_page(
        session,
        "Test Hikvision",
        "Hikvision CVE-2017-7921 backdoor + HTTP Digest login test.",
        "test-hikvision",
        "tests/test_hikvision_target.py",
        run_hikvision_test,
    )


def build_test_cve_page(session: GuiSession):
    return _utility_test_page(
        session,
        "CVE Report",
        "CVE intelligence report for the active target.",
        "test-cve",
        "tests/test_device_cve.py",
        run_cve_test,
    )


def build_update_tools_page(session: GuiSession):
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

        def _go(self) -> None:
            def task():
                from core.utils import run_cmd

                ok, _ = run_cmd(
                    [sys.executable, "scripts/update_tools.py"],
                    capture=True,
                    cwd=project_root(),
                    timeout=3600,
                )
                return ok

            job = ScanJob(kind="custom", label="update-tools", custom_fn=task)
            w = ScanWorker(self._session, job, self)
            self.run_requested.emit(w)
            w.start()

    return Page
