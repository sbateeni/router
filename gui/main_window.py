"""Main PyQt6 window — docked layout: nav | tools | workspace | console."""

from __future__ import annotations

import os

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction, QGuiApplication
from PyQt6.QtWidgets import (
    QDockWidget,
    QHBoxLayout,
    QMainWindow,
    QMessageBox,
    QScrollArea,
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
from gui.widgets.workspace_panel import WorkspacePanel
from gui.workers.scan_worker import ScanWorker

# Pages that use the full center area without the bottom console dock (no overlap).
_FULL_PAGE_IDS = frozenset({"settings", "dashboard", "engine_history"})


def _tune_splitter(splitter: QSplitter) -> None:
    splitter.setChildrenCollapsible(False)
    splitter.setHandleWidth(8)
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
        self._current_page_id = "dashboard"
        self.setWindowTitle("AUTO-PWN UNIFIED")
        self.setMinimumSize(960, 600)
        self.resize(1320, 880)

        # --- Central: target bar + nav | tool pages | workspace ---
        central = QWidget()
        self.setCentralWidget(central)
        outer = QVBoxLayout(central)
        outer.setContentsMargins(8, 8, 4, 4)
        outer.setSpacing(6)
        self._target_bar = TargetBar(self._session)
        outer.addWidget(self._target_bar)

        body = QHBoxLayout()
        body.setSpacing(8)
        root = body
        outer.addLayout(body, stretch=1)

        self._tree = QTreeWidget()
        self._tree.setHeaderHidden(True)
        self._tree.setMinimumWidth(200)
        self._tree.setMaximumWidth(280)
        self._tree.currentItemChanged.connect(self._on_nav)
        root.addWidget(self._tree)

        center_split = QSplitter(Qt.Orientation.Horizontal)
        _tune_splitter(center_split)

        self._stack = QStackedWidget()
        self._stack.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        center_split.addWidget(self._stack)

        self._workspace = WorkspacePanel()
        center_split.addWidget(self._workspace)
        center_split.setStretchFactor(0, 1)
        center_split.setStretchFactor(1, 0)
        center_split.setSizes([900, 260])

        root.addWidget(center_split, stretch=1)

        # --- Bottom dock: Live Log | Artifacts | Terminal (separate from tool pages) ---
        self._console_dock = QDockWidget("Console — Live Log · Artifacts · Terminal", self)
        self._console_dock.setObjectName("ConsoleDock")
        self._console_dock.setAllowedAreas(
            Qt.DockWidgetArea.BottomDockWidgetArea | Qt.DockWidgetArea.TopDockWidgetArea
        )

        console = QWidget()
        console_layout = QVBoxLayout(console)
        console_layout.setContentsMargins(4, 4, 4, 4)
        self._bottom_tabs = QTabWidget()
        self._log = LogPanel()
        self._artifacts = ArtifactPanel()
        self._terminal = TerminalPanel()
        self._bottom_tabs.addTab(self._log, "Live Log")
        self._bottom_tabs.addTab(self._artifacts, "Artifacts")
        self._bottom_tabs.addTab(self._terminal, "Terminal")
        console_layout.addWidget(self._bottom_tabs)
        self._console_dock.setWidget(console)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, self._console_dock)

        self._pages: dict[str, QWidget] = {}
        self._build_nav()
        self._build_pages()

        self._target_bar.target_changed.connect(self._on_target_changed)
        self._show_page("dashboard")

        quit_action = QAction("Quit", self)
        quit_action.setShortcut("Ctrl+Q")
        quit_action.triggered.connect(self.close)
        self.addAction(quit_action)

        self._maybe_start_telegram_listener()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        if getattr(self, "_dock_sized", False):
            return
        self._dock_sized = True
        screen = QGuiApplication.primaryScreen()
        if screen:
            g = screen.availableGeometry()
            self.resize(min(1320, g.width() - 40), min(880, g.height() - 60))
        self.resizeDocks([self._console_dock], [int(self.height() * 0.38)], Qt.Orientation.Vertical)

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
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setWidget(settings)
        self._register("settings", scroll)

    def _register(self, page_id: str, widget: QWidget) -> None:
        widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self._pages[page_id] = widget
        self._stack.addWidget(widget)

    def _set_console_visible(self, visible: bool) -> None:
        self._console_dock.setVisible(visible)
        if visible and not self._console_dock.isFloating():
            self.resizeDocks([self._console_dock], [max(220, int(self.height() * 0.35))], Qt.Orientation.Vertical)

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
        self._current_page_id = page_id
        self._stack.setCurrentWidget(w)

        # Settings / dashboard: full height — hide console dock (no overlap with terminal).
        self._set_console_visible(page_id not in _FULL_PAGE_IDS)

        inner = w.widget() if isinstance(w, QScrollArea) else w
        if isinstance(inner, DashboardPage):
            inner.refresh()
        elif isinstance(inner, SettingsPage):
            inner.refresh()
        elif isinstance(inner, HistoryPage):
            inner.refresh()
        elif isinstance(inner, ToolPage):
            inner._banner.refresh()
        elif isinstance(inner, ComprehensivePage):
            inner._banner.refresh()

        self._refresh_workspace_panel()

    def _refresh_workspace_panel(self) -> None:
        self._workspace.refresh(self._session.target, self._session.target_dir)

    def _on_target_changed(self) -> None:
        self._target_bar.sync_from_session()
        self._artifacts.set_workspace(self._session.target_dir)
        self._refresh_workspace_panel()
        for w in self._pages.values():
            inner = w.widget() if isinstance(w, QScrollArea) else w
            if isinstance(inner, ToolPage):
                inner._banner.refresh()

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
        self._refresh_workspace_panel()

    def _on_worker(self, worker: ScanWorker) -> None:
        self._set_console_visible(True)
        self._log.start_tailing(worker.job_id)
        self._bottom_tabs.setCurrentWidget(self._log)
        worker.finished_ok.connect(lambda *_: self._after_scan())
        worker.error.connect(lambda msg: QMessageBox.critical(self, "Error", msg))

    def _after_scan(self) -> None:
        self._artifacts.set_workspace(self._session.target_dir)
        self._refresh_workspace_panel()
        dash = self._pages.get("dashboard")
        if dash:
            inner = dash.widget() if isinstance(dash, QScrollArea) else dash
            if isinstance(inner, DashboardPage):
                inner.refresh()

    def _maybe_start_telegram_listener(self) -> None:
        if os.environ.get("NUCLEI_TELEGRAM_EXTERNAL", "").strip() == "1":
            return
        if os.environ.get("TELEGRAM_AUTO", "1").strip().lower() in ("0", "false", "no", "off"):
            return
        try:
            self._telegram_thread = start_telegram_bot_background(project_root())
        except Exception:
            self._telegram_thread = None
