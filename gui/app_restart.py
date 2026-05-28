"""Relaunch the GUI application."""

from __future__ import annotations

import os
import sys

from PyQt6.QtCore import QProcess
from PyQt6.QtWidgets import QApplication, QMessageBox, QWidget

from core.paths import project_root


def gui_python() -> str:
    root = project_root()
    if sys.platform == "win32":
        venv_py = os.path.join(root, ".venv", "Scripts", "python.exe")
    else:
        venv_py = os.path.join(root, ".venv", "bin", "python")
    if os.path.isfile(venv_py):
        return venv_py
    return sys.executable


def restart_application(parent: QWidget | None = None) -> bool:
    """Start a fresh GUI process and quit the current one."""
    from gui.workers.scan_worker import ScanWorker

    if ScanWorker._active_job_id:
        QMessageBox.warning(
            parent,
            "Scan running",
            "A scan is still running. Cancel it first, then restart.",
        )
        return False

    reply = QMessageBox.question(
        parent,
        "Restart application",
        "Restart AUTO-PWN UNIFIED GUI now?\n\n"
        "Unsaved changes in open fields may be lost.",
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        QMessageBox.StandardButton.No,
    )
    if reply != QMessageBox.StandardButton.Yes:
        return False

    root = project_root()
    gui_script = os.path.join(root, "bin", "gui_app.py")
    if not os.path.isfile(gui_script):
        QMessageBox.critical(parent, "Restart failed", f"Not found: {gui_script}")
        return False

    py = gui_python()
    ok = QProcess.startDetached(py, [gui_script], root)
    if not ok:
        QMessageBox.critical(
            parent,
            "Restart failed",
            f"Could not start:\n{py} {gui_script}",
        )
        return False

    app = QApplication.instance()
    if app is not None:
        app.quit()
    return True
