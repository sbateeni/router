"""Device Engine pages — LAN, history, OSINT, Decepticon, update."""

from __future__ import annotations

import json
import os

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.paths import project_root
from core.scan_cancel import cancel_job
from gui.session import GuiSession
from gui.workers.scan_worker import ScanJob, ScanWorker


class EngineAutoPwnPage(QWidget):
    run_requested = pyqtSignal(object)

    def __init__(self, session: GuiSession, parent=None):
        super().__init__(parent)
        self._session = session
        self._worker: ScanWorker | None = None
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("<h2>Device AUTO-PWN</h2>"))
        layout.addWidget(QLabel("Full device engine: cameras, routers, OSINT, PoCs."))
        mode_row = QHBoxLayout()
        mode_row.addWidget(QLabel("Mode:"))
        self._mode = QComboBox()
        self._mode.addItems(["Full auto", "Expert manual"])
        mode_row.addWidget(self._mode)
        layout.addLayout(mode_row)
        btn_row = QHBoxLayout()
        self._run_btn = QPushButton("Run")
        self._run_btn.clicked.connect(self._start)
        self._cancel_btn = QPushButton("Cancel")
        self._cancel_btn.setEnabled(False)
        self._cancel_btn.clicked.connect(self._cancel)
        btn_row.addWidget(self._run_btn)
        btn_row.addWidget(self._cancel_btn)
        layout.addLayout(btn_row)
        layout.addStretch()

    def _start(self) -> None:
        if not self._session.target.strip():
            QMessageBox.warning(self, "Target required", "Enter a target in the bar above.")
            return
        manual = self._mode.currentIndex() == 1
        job = ScanJob(kind="engine", label="device-engine", manual_mode=manual)
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

    def _on_done(self, *_args) -> None:
        self._run_btn.setEnabled(True)
        self._cancel_btn.setEnabled(False)

    def _on_error(self, msg: str) -> None:
        QMessageBox.critical(self, "Error", msg)
        self._run_btn.setEnabled(True)
        self._cancel_btn.setEnabled(False)


class LanScanPage(QWidget):
    device_selected = pyqtSignal(str, object)

    def __init__(self, session: GuiSession, parent=None):
        super().__init__(parent)
        self._session = session
        self._devices: list[dict] = []
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("<h2>LAN Scan</h2>"))
        layout.addWidget(QLabel("Discover cameras and routers on the local network."))
        btn_row = QHBoxLayout()
        self._scan_btn = QPushButton("Scan LAN")
        self._scan_btn.clicked.connect(self._scan)
        self._pwn_btn = QPushButton("AUTO-PWN selected")
        self._pwn_btn.clicked.connect(self._pwn_selected)
        btn_row.addWidget(self._scan_btn)
        btn_row.addWidget(self._pwn_btn)
        layout.addLayout(btn_row)
        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(["#", "IP", "Port", "Type", "Vendor"])
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self._table)

    def _scan(self) -> None:
        self._scan_btn.setEnabled(False)
        try:
            from engines.lan_scanner import LANScanner

            scanner = LANScanner()
            self._devices = scanner.run_scan() or []
            self._table.setRowCount(0)
            for i, dev in enumerate(self._devices):
                row = self._table.rowCount()
                self._table.insertRow(row)
                self._table.setItem(row, 0, QTableWidgetItem(str(i + 1)))
                self._table.setItem(row, 1, QTableWidgetItem(dev.get("ip", "")))
                self._table.setItem(row, 2, QTableWidgetItem(str(dev.get("port", ""))))
                self._table.setItem(row, 3, QTableWidgetItem(dev.get("type", "")))
                self._table.setItem(row, 4, QTableWidgetItem(dev.get("vendor", "")))
        except Exception as exc:
            QMessageBox.critical(self, "LAN scan failed", str(exc))
        finally:
            self._scan_btn.setEnabled(True)

    def _pwn_selected(self) -> None:
        rows = self._table.selectionModel().selectedRows()
        if not rows or not self._devices:
            QMessageBox.information(self, "Select device", "Run LAN scan and select a row.")
            return
        idx = rows[0].row()
        if idx < 0 or idx >= len(self._devices):
            return
        dev = self._devices[idx]
        url = f"http://{dev['ip']}:{dev.get('port', 80)}"
        ports = None
        if dev.get("port"):
            try:
                ports = [int(dev["port"])]
            except (TypeError, ValueError):
                pass
        self._session.target = url
        self._session.prepare(force_reset=True)
        self.device_selected.emit(url, ports)


class HistoryPage(QWidget):
    target_selected = pyqtSignal(str)

    def __init__(self, session: GuiSession, parent=None):
        super().__init__(parent)
        self._session = session
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("<h2>Target History</h2>"))
        self._refresh_btn = QPushButton("Refresh")
        self._refresh_btn.clicked.connect(self.refresh)
        self._use_btn = QPushButton("Use selected target")
        self._use_btn.clicked.connect(self._use_selected)
        row = QHBoxLayout()
        row.addWidget(self._refresh_btn)
        row.addWidget(self._use_btn)
        layout.addLayout(row)
        self._table = QTableWidget(0, 3)
        self._table.setHorizontalHeaderLabels(["IP", "Status", "File"])
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self._table)
        self._files: list[str] = []

    def refresh(self) -> None:
        db_dir = os.path.join(project_root(), "db")
        self._table.setRowCount(0)
        self._files = []
        if not os.path.isdir(db_dir):
            return
        for name in sorted(os.listdir(db_dir)):
            if not name.endswith(".json"):
                continue
            path = os.path.join(db_dir, name)
            ip = name.replace(".json", "")
            status = "?"
            try:
                with open(path, encoding="utf-8") as fh:
                    data = json.load(fh)
                status = data.get("status", "?")
            except (OSError, json.JSONDecodeError):
                pass
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setItem(row, 0, QTableWidgetItem(ip))
            self._table.setItem(row, 1, QTableWidgetItem(str(status)))
            self._table.setItem(row, 2, QTableWidgetItem(name))
            self._files.append(ip)

    def _use_selected(self) -> None:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return
        ip = self._table.item(rows[0].row(), 0).text()
        self._session.target = ip
        self._session.prepare(force_reset=False)
        self.target_selected.emit(ip)


class OsintPage(QWidget):
    run_requested = pyqtSignal(object)

    def __init__(self, session: GuiSession, parent=None):
        super().__init__(parent)
        self._session = session
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("<h2>Social OSINT</h2>"))
        self._mode = QComboBox()
        self._mode.addItems(["Email", "Phone", "Username", "Full (email + username)"])
        layout.addWidget(self._mode)
        self._input = QLineEdit()
        self._input.setPlaceholderText("email, phone, or username")
        layout.addWidget(self._input)
        self._run_btn = QPushButton("Run OSINT")
        self._run_btn.clicked.connect(self._run)
        layout.addWidget(self._run_btn)

    def _run(self) -> None:
        value = self._input.text().strip()
        if not value:
            return
        mode = self._mode.currentIndex()

        def task():
            from engines.social_osint import SocialOSINT

            osint = SocialOSINT()
            if mode == 0:
                osint.check_email(value)
            elif mode == 1:
                osint.check_phone(value)
            elif mode == 2:
                osint.hunt_username(value)
            else:
                osint.check_email(value)
                osint.hunt_username(value.split("@")[0])
            out = os.path.join(project_root(), "logs", "osint_report.json")
            osint.save_results(out)

        job = ScanJob(kind="custom", label="osint", custom_fn=task)
        worker = ScanWorker(self._session, job, self)
        self.run_requested.emit(worker)
        worker.start()


class DecepticonPage(QWidget):
    run_requested = pyqtSignal(object)

    def __init__(self, session: GuiSession, parent=None):
        super().__init__(parent)
        self._session = session
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("<h2>Decepticon Kill-Chain</h2>"))
        self._target = QLineEdit()
        self._target.setPlaceholderText("Target URL or IP")
        layout.addWidget(self._target)
        self._run_btn = QPushButton("Run autonomous mode")
        self._run_btn.clicked.connect(self._run)
        layout.addWidget(self._run_btn)

    def _run(self) -> None:
        t = self._target.text().strip() or self._session.target
        if not t:
            QMessageBox.warning(self, "Target", "Enter a target.")
            return

        def task():
            from engines.decepticon_core import DecepticonCore

            DecepticonCore(t).run_autonomous_mode()

        job = ScanJob(kind="custom", label="decepticon", custom_fn=task)
        worker = ScanWorker(self._session, job, self)
        self.run_requested.emit(worker)
        worker.start()


class FrameworkUpdatePage(QWidget):
    run_requested = pyqtSignal(object)

    def __init__(self, session: GuiSession, parent=None):
        super().__init__(parent)
        self._session = session
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("<h2>Framework Update</h2>"))
        self._run_btn = QPushButton("Update framework & tools (git pull)")
        self._run_btn.clicked.connect(self._run)
        layout.addWidget(self._run_btn)

    def _run(self) -> None:
        def task():
            from engines.updater import run_startup_update

            run_startup_update(update_project=True, update_tools=True, update_templates=True)

        job = ScanJob(kind="custom", label="update", custom_fn=task)
        worker = ScanWorker(self._session, job, self)
        self.run_requested.emit(worker)
        worker.start()


class PocScraperPage(QWidget):
    run_requested = pyqtSignal(object)

    def __init__(self, session: GuiSession, parent=None):
        super().__init__(parent)
        self._session = session
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("<h2>GitHub PoC Scraper</h2>"))
        self._run_btn = QPushButton("Update exploit arsenal")
        self._run_btn.clicked.connect(self._run)
        layout.addWidget(self._run_btn)

    def _run(self) -> None:
        def task():
            from engines.zero_day_scraper import ZeroDayScraper

            ZeroDayScraper().search_and_download()

        job = ScanJob(kind="custom", label="poc-scraper", custom_fn=task)
        worker = ScanWorker(self._session, job, self)
        self.run_requested.emit(worker)
        worker.start()
