"""Main PyQt6 window — navigation tree + stacked pages."""

from __future__ import annotations

import os

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QMainWindow,
    QMessageBox,
    QSplitter,
    QStackedWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.notify import load_dotenv
from core.paths import project_root, setup_project_env
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
from gui.widgets.target_bar import TargetBar
from gui.widgets.tool_page import ToolPage
from gui.workers.scan_worker import ScanWorker


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        setup_project_env()
        load_dotenv(project_root())
        os.environ["AUTOPWN_LIVE_WINDOW"] = "0"
        os.environ["AUTOPWN_SCAN_SOURCE"] = "gui"

        self._session = GuiSession()
        self.setWindowTitle("AUTO-PWN UNIFIED")
        self.resize(1200, 800)

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)

        self._target_bar = TargetBar(self._session)
        root.addWidget(self._target_bar)

        split = QSplitter(Qt.Orientation.Horizontal)
        root.addWidget(split, stretch=1)

        self._tree = QTreeWidget()
        self._tree.setHeaderHidden(True)
        self._tree.setMinimumWidth(220)
        self._tree.currentItemChanged.connect(self._on_nav)
        split.addWidget(self._tree)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        self._stack = QStackedWidget()
        right_layout.addWidget(self._stack, stretch=2)

        log_split = QSplitter(Qt.Orientation.Vertical)
        self._log = LogPanel()
        self._artifacts = ArtifactPanel()
        log_split.addWidget(self._log)
        self._artifact_wrap = QWidget()
        aw = QVBoxLayout(self._artifact_wrap)
        aw.setContentsMargins(0, 0, 0, 0)
        aw.addWidget(self._artifacts)
        log_split.addWidget(self._artifact_wrap)
        log_split.setSizes([400, 180])
        right_layout.addWidget(log_split, stretch=1)
        split.addWidget(right)
        split.setSizes([240, 960])

        self._pages: dict[str, QWidget] = {}
        self._build_nav()
        self._build_pages()

        self._target_bar.target_changed.connect(self._on_target_changed)
        self._show_page("dashboard")

        quit_action = QAction("Quit", self)
        quit_action.setShortcut("Ctrl+Q")
        quit_action.triggered.connect(self.close)
        self.addAction(quit_action)

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

        ut = build_update_tools_page(session)
        ut.run_requested.connect(self._on_worker)
        self._register("util_update", ut)

        for build_fn, pid in (
            (build_test_router_page, "util_router_test"),
            (build_test_hikvision_page, "util_hik_test"),
            (build_test_cve_page, "util_cve_test"),
        ):
            p = build_fn(session)
            p.run_requested.connect(self._on_worker)
            self._register(pid, p)

        settings = SettingsPage(session)
        self._register("settings", settings)

    def _register(self, page_id: str, widget: QWidget) -> None:
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
        worker.finished_ok.connect(lambda *_: self._after_scan())
        worker.error.connect(
            lambda msg: QMessageBox.critical(self, "Error", msg)
        )

    def _after_scan(self) -> None:
        self._artifacts.set_workspace(self._session.target_dir)
        if isinstance(self._pages.get("dashboard"), DashboardPage):
            self._pages["dashboard"].refresh()
