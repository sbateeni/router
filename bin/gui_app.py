#!/usr/bin/env python3
"""PyQt6 desktop GUI for AUTO-PWN UNIFIED."""

import sys

import _bootstrap

_bootstrap.install()

from core.paths import setup_project_env

setup_project_env()


def main() -> int:
    try:
        from PyQt6.QtWidgets import QApplication
    except ImportError:
        print("[!] PyQt6 is not installed.")
        print("[*] Install with: pip install -r requirements.txt")
        return 1

    from PyQt6.QtCore import Qt

    from gui.main_window import MainWindow
    from gui.theme import apply_theme

    app = QApplication(sys.argv)
    app.setApplicationName("AUTO-PWN UNIFIED")
    apply_theme(app)
    window = MainWindow()
    window.setWindowFlag(Qt.WindowType.Window, True)
    window.showNormal()
    window.raise_()
    window.activateWindow()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
