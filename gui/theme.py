"""Dark theme for AUTO-PWN GUI."""

from __future__ import annotations

STYLESHEET = """
QMainWindow, QWidget {
    background-color: #1a1d23;
    color: #e4e6eb;
    font-family: "Segoe UI", "Cantarell", sans-serif;
    font-size: 13px;
}
QDockWidget {
    titlebar-close-icon: none;
    color: #c8ccd4;
    font-weight: 600;
}
QDockWidget::title {
    background: #252a33;
    padding: 6px 8px;
    border-bottom: 1px solid #3d4553;
}
QTreeWidget {
    background-color: #21262d;
    border: 1px solid #3d4553;
    border-radius: 6px;
    padding: 4px;
}
QTreeWidget::item {
    padding: 4px 2px;
    border-radius: 4px;
}
QTreeWidget::item:selected {
    background-color: #2d6cdf;
    color: #ffffff;
}
QTreeWidget::item:hover:!selected {
    background-color: #2a313c;
}
QStackedWidget, QTabWidget::pane {
    border: 1px solid #3d4553;
    border-radius: 6px;
    background: #1e2229;
}
QTabBar::tab {
    background: #252a33;
    color: #a8b0bd;
    padding: 8px 16px;
    margin-right: 2px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
}
QTabBar::tab:selected {
    background: #2d6cdf;
    color: #ffffff;
}
QLineEdit, QComboBox, QTextEdit, QListWidget {
    background-color: #12151a;
    border: 1px solid #3d4553;
    border-radius: 5px;
    padding: 6px 8px;
    color: #e4e6eb;
    selection-background-color: #2d6cdf;
}
QPushButton {
    background-color: #2d6cdf;
    color: #ffffff;
    border: none;
    border-radius: 5px;
    padding: 7px 14px;
    font-weight: 600;
}
QPushButton:hover {
    background-color: #3a7af0;
}
QPushButton:pressed {
    background-color: #2458b8;
}
QPushButton:disabled {
    background-color: #3d4553;
    color: #7a828e;
}
QPushButton#secondaryBtn {
    background-color: #3d4553;
}
QPushButton#secondaryBtn:hover {
    background-color: #4a5568;
}
QPushButton#dangerBtn {
    background-color: #c0392b;
}
QGroupBox {
    border: 1px solid #3d4553;
    border-radius: 6px;
    margin-top: 10px;
    padding-top: 12px;
    font-weight: 600;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 6px;
    color: #8b95a5;
}
QSplitter::handle {
    background: #3d4553;
}
QSplitter::handle:horizontal { width: 8px; }
QSplitter::handle:vertical { height: 8px; }
QScrollArea {
    border: none;
    background: transparent;
}
QLabel#targetBanner {
    background: #252a33;
    border: 1px solid #3d4553;
    border-radius: 6px;
    padding: 10px 12px;
    color: #dce1e8;
}
QLabel#chainInfo {
    background: #1e2836;
    border-left: 3px solid #2d6cdf;
    padding: 8px 10px;
    color: #a8b8cc;
}
QStatusTip {
    color: #7a8a9e;
}
"""


def apply_theme(app) -> None:
    app.setStyleSheet(STYLESHEET)
