"""Main PyQt6 window — navigation tree + stacked pages."""

from __future__ import annotations

import os

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction, QGuiApplication
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QMainWindow,
    QMessageBox,
    QSizePolicy,
    QSplitter,
    QStackedWidget,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.notify import load_dotenv
from core.paths import project_root, setup_project_env
from core.telegram.runner import start_telegram_bot_background
from gui.navigation import CATEGORIES, NAV_ITEMS, PAGE_SPECS
from gui.pages.comprehensive import ComprehensivePage
from gui.pages.dashboard import DashboardPage
from gui.pages.engine_pages import (
    DecepticonPage,
    EngineAutoPwnPage,
    FrameworkUpdatePage,
    HistoryPage,
    LanScanPage,
    OsintPage,
    PocScraperPage,
)
from gui.pages.settings import SettingsPage
from gui.pages.utilities_pages import (
    build_test_cve_page,
    build_test_hikvision_page,
    build_test_router_page,
    build_update_tools_page,
)
from gui.session import GuiSession
from gui.widgets.artifact_panel import ArtifactPanel
from gui.widgets.log_panel import LogPanel
from gui.widgets.terminal_panel import TerminalPanel
from gui.widgets.target_bar import TargetBar
from gui.widgets.tool_page import ToolPage
from gui.workers.scan_worker import ScanWorker


def _tune_splitter(splitter: QSplitter) -> None:
    splitter.setChildrenCollapsible(False)
    splitter.setHandleWidth(10)
    splitter.setOpaqueResize(True)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        setup_project_env()
        load_dotenv(project_root())
        os.environ["AUTOPWN_LIVE_WINDOW"] = "0"
        os.environ["AUTOPWN_SCAN_SOURCE"] = "gui"

        self._session = GuiSession()
        self._telegram_thread = None
        self._split_sizes_applied = False
        self.setWindowTitle("AUTO-PWN UNIFIED")
        self.setMinimumSize(720, 520)
        self.resize(1280, 860)

        central = QWidget()
        central.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(6, 6, 6, 6)
        root.setSpacing(6)

        self._target_bar = TargetBar(self._session)
        root.addWidget(self._target_bar)

        h_split = QSplitter(Qt.Orientation.Horizontal)
        _tune_splitter(h_split)
        root.addWidget(h_split, stretch=1)

        self._tree = QTreeWidget()
        self._tree.setHeaderHidden(True)
        self._tree.setMinimumWidth(180)
        self._tree.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Expanding)
        self._tree.currentItemChanged.connect(self._on_nav)
        h_split.addWidget(self._tree)

        right = QWidget()
        right.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)

        # Pages (top) vs console area (bottom) — drag handle between them
        self._page_console_split = QSplitter(Qt.Orientation.Vertical)
        _tune_splitter(self._page_console_split)

        self._stack = QStackedWidget()
        self._stack.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self._stack.setMinimumHeight(80)
        self._page_console_split.addWidget(self._stack)

        # Bottom: Live Log / Artifacts tabs (small) + Terminal (large, always visible)
        self._console_split = QSplitter(Qt.Orientation.Vertical)
        _tune_splitter(self._console_split)

        self._bottom_tabs = QTabWidget()
        self._bottom_tabs.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self._bottom_tabs.setMinimumHeight(100)
        self._log = LogPanel()
        self._artifacts = ArtifactPanel()
        self._bottom_tabs.addTab(self._log, "Live Log")
        self._bottom_tabs.addTab(self._artifacts, "Artifacts")
        self._console_split.addWidget(self._bottom_tabs)

        self._terminal = TerminalPanel()
        self._terminal.setMinimumHeight(160)
        self._console_split.addWidget(self._terminal)
        self._console_split.setStretchFactor(0, 1)
        self._console_split.setStretchFactor(1, 3)

        self._page_console_split.addWidget(self._console_split)
        self._page_console_split.setStretchFactor(0, 1)
        self._page_console_split.setStretchFactor(1, 2)

        right_layout.addWidget(self._page_console_split)
        h_split.addWidget(right)
        h_split.setStretchFactor(0, 0)
        h_split.setStretchFactor(1, 1)
        h_split.setSizes([240, 1000])

        self._h_split = h_split
        self._pages: dict[str, QWidget] = {}
        self._build_nav()
        self._build_pages()

        self._target_bar.target_changed.connect(self._on_target_changed)
        self._show_page("dashboard")
        self._maybe_start_telegram_listener()

        quit_action = QAction("Quit", self)
        quit_action.setShortcut("Ctrl+Q")
        quit_action.triggered.connect(self.close)
        self.addAction(quit_action)

    def showEvent(self, event) -> None:
        super().showEvent(event)
        if self._split_sizes_applied:
            return
        self._split_sizes_applied = True
        screen = QGuiApplication.primaryScreen()
        if screen:
            avail = screen.availableGeometry()
            w = min(max(int(avail.width() * 0.88), 960), avail.width())
            h = min(max(int(avail.height() * 0.88), 640), avail.height())
            self.resize(w, h)
        h_total = max(self.height(), 640)
        bottom_h = int(h_total * 0.58)
        top_h = h_total - bottom_h
        self._page_console_split.setSizes([top_h, bottom_h])
        self._console_split.setSizes([int(bottom_h * 0.28), int(bottom_h * 0.72)])

    def _build_nav(self) -> None:
        self._tree.clear()
        self._nav_items: dict[str, QTreeWidgetItem] = {}
        cats: dict[str, QTreeWidgetItem] = {}
        for cat_id, cat_label in CATEGORIES.items():
            item = QTreeWidgetItem([cat_label])
            item.setData(0, Qt.ItemDataRole.UserRole, None)
            cats[cat_id] = item
            self._tree.addTopLevelItem(item)
        for page_id, label, parent_id in NAV_ITEMS:
            if parent_id and parent_id in cats:
                item = QTreeWidgetItem(cats[parent_id], [label])
            else:
                item = QTreeWidgetItem([label])
                self._tree.addTopLevelItem(item)
            item.setData(0, Qt.ItemDataRole.UserRole, page_id)
            self._nav_items[page_id] = item
        self._tree.expandAll()

    def _build_pages(self) -> None:
        session = self._session

        self._register("dashboard", DashboardPage(session))
        comp = ComprehensivePage(session)
        comp.run_requested.connect(self._on_worker)
        self._register("comprehensive", comp)

        for page_id, spec in PAGE_SPECS.items():
            if spec.get("kind") == "engine":
                continue
            page = ToolPage(
                session,
                title=spec["title"],
                description=spec["desc"],
                selection=spec.get("selection"),
                kind=spec.get("kind", "tool"),
            )
            page.run_requested.connect(self._on_worker)
            self._register(page_id, page)

        eng = EngineAutoPwnPage(session)
        eng.run_requested.connect(self._on_worker)
        self._register("engine_autopwn", eng)

        lan = LanScanPage(session)
        lan.device_selected.connect(self._on_lan_device)
        self._register("engine_lan", lan)

        hist = HistoryPage(session)
        hist.target_selected.connect(self._on_history_target)
        self._register("engine_history", hist)

        for factory, pid in (
            (PocScraperPage, "engine_poc"),
            (OsintPage, "engine_osint"),
            (DecepticonPage, "engine_decepticon"),
            (FrameworkUpdatePage, "engine_update"),
        ):
            p = factory(session)
            p.run_requested.connect(self._on_worker)
            self._register(pid, p)

        from gui.pages.utilities_pages import DirectCameraPage

        dc = DirectCameraPage(session)
        dc.run_requested.connect(self._on_worker)
        self._register("util_direct_cam", dc)

        ut = build_update_tools_page(session)()
        ut.run_requested.connect(self._on_worker)
        self._register("util_update", ut)

        for build_fn, pid in (
            (build_test_router_page, "util_router_test"),
            (build_test_hikvision_page, "util_hik_test"),
            (build_test_cve_page, "util_cve_test"),
        ):
            p = build_fn(session)()
            p.run_requested.connect(self._on_worker)
            self._register(pid, p)

        settings = SettingsPage(session)
        self._register("settings", settings)

    def _register(self, page_id: str, widget: QWidget) -> None:
        widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self._pages[page_id] = widget
        self._stack.addWidget(widget)

    def _on_nav(self, current: QTreeWidgetItem | None, _prev) -> None:
        if not current:
            return
        page_id = current.data(0, Qt.ItemDataRole.UserRole)
        if page_id:
            self._show_page(page_id)

    def _show_page(self, page_id: str) -> None:
        w = self._pages.get(page_id)
        if not w:
            return
        self._stack.setCurrentWidget(w)
        if isinstance(w, DashboardPage):
            w.refresh()
        elif isinstance(w, SettingsPage):
            w.refresh()
        elif isinstance(w, HistoryPage):
            w.refresh()

    def _on_target_changed(self) -> None:
        self._target_bar.sync_from_session()
        self._artifacts.set_workspace(self._session.target_dir)

    def _on_lan_device(self, url: str, ports) -> None:
        from gui.workers.scan_worker import ScanJob

        self._session.target = url
        self._target_bar._target_edit.setText(url)
        self._target_bar._apply()
        job = ScanJob(
            kind="engine",
            label="lan-autopwn",
            known_open_ports=ports,
        )
        worker = ScanWorker(self._session, job, self)
        self._on_worker(worker)
        worker.start()

    def _on_history_target(self, ip: str) -> None:
        self._session.target = ip
        self._target_bar.sync_from_session()
        self._artifacts.set_workspace(self._session.target_dir)

    def _on_worker(self, worker: ScanWorker) -> None:
        self._log.start_tailing(worker.job_id)
        self._bottom_tabs.setCurrentWidget(self._log)
        worker.finished_ok.connect(lambda *_: self._after_scan())
        worker.error.connect(
            lambda msg: QMessageBox.critical(self, "Error", msg)
        )

    def _after_scan(self) -> None:
        self._artifacts.set_workspace(self._session.target_dir)
        if isinstance(self._pages.get("dashboard"), DashboardPage):
            self._pages["dashboard"].refresh()

    def _maybe_start_telegram_listener(self) -> None:
        if os.environ.get("NUCLEI_TELEGRAM_EXTERNAL", "").strip() == "1":
            return
        if os.environ.get("TELEGRAM_AUTO", "1").strip().lower() in ("0", "false", "no", "off"):
            return
        try:
            self._telegram_thread = start_telegram_bot_background(project_root())
        except Exception:
            self._telegram_thread = None
