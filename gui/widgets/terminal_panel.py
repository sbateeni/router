"""Simple integrated terminal panel for GUI."""

from __future__ import annotations

import os
import sys

from PyQt6.QtCore import QProcess
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


class TerminalPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        # Controls stay above the output so Run/Stop remain visible when the window is maximized.
        toolbar = QWidget()
        toolbar.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        toolbar_layout = QVBoxLayout(toolbar)
        toolbar_layout.setContentsMargins(0, 0, 0, 0)
        toolbar_layout.setSpacing(4)

        quick = QHBoxLayout()
        self._btn_update_all = QPushButton("Update GitHub + tools")
        self._btn_update_all.clicked.connect(
            lambda: self.run_preset_command(f"\"{sys.executable}\" scripts/update_tools.py")
        )
        quick.addWidget(self._btn_update_all)

        self._btn_install_gui = QPushButton("Install Python deps")
        self._btn_install_gui.clicked.connect(
            lambda: self.run_preset_command(f"\"{sys.executable}\" -m pip install -r requirements.txt")
        )
        quick.addWidget(self._btn_install_gui)

        self._btn_launcher = QPushButton("Install Kali app icon")
        self._btn_launcher.clicked.connect(
            lambda: self.run_preset_command("bash scripts/install_gui_launcher.sh")
        )
        quick.addWidget(self._btn_launcher)
        quick.addStretch()
        toolbar_layout.addLayout(quick)

        row = QHBoxLayout()
        self._input = QLineEdit()
        self._input.setPlaceholderText("Type command and press Enter, e.g. python --version")
        self._input.returnPressed.connect(self.run_command)
        row.addWidget(self._input, stretch=1)

        self._run_btn = QPushButton("Run")
        self._run_btn.setMinimumWidth(72)
        self._run_btn.clicked.connect(self.run_command)
        row.addWidget(self._run_btn)

        self._stop_btn = QPushButton("Stop")
        self._stop_btn.setMinimumWidth(72)
        self._stop_btn.clicked.connect(self.stop_command)
        self._stop_btn.setEnabled(False)
        row.addWidget(self._stop_btn)

        self._clear_btn = QPushButton("Clear")
        self._clear_btn.clicked.connect(self._output_clear)
        row.addWidget(self._clear_btn)

        self._copy_btn = QPushButton("Copy all")
        self._copy_btn.clicked.connect(self.copy_all)
        row.addWidget(self._copy_btn)
        toolbar_layout.addLayout(row)

        layout.addWidget(toolbar)

        self._output = QTextEdit()
        self._output.setReadOnly(True)
        self._output.setFont(QFont("Consolas", 10))
        self._output.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        layout.addWidget(self._output, stretch=1)

        self._proc = QProcess(self)
        self._proc.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self._proc.readyReadStandardOutput.connect(self._read_output)
        self._proc.finished.connect(self._finished)

    def run_command(self) -> None:
        if self._proc.state() != QProcess.ProcessState.NotRunning:
            return
        command = self._input.text().strip()
        if not command:
            return

        if sys.platform == "win32":
            shell = "powershell"
            args = ["-NoProfile", "-Command", command]
        else:
            shell = "/bin/bash"
            args = ["-lc", command]

        self._output.append(f"$ {command}")
        self._proc.setWorkingDirectory(os.getcwd())
        self._proc.start(shell, args)
        self._stop_btn.setEnabled(True)
        self._run_btn.setEnabled(False)

    def run_preset_command(self, command: str) -> None:
        if self._proc.state() != QProcess.ProcessState.NotRunning:
            return
        self._input.setText(command)
        self.run_command()

    def stop_command(self) -> None:
        if self._proc.state() == QProcess.ProcessState.NotRunning:
            return
        self._proc.kill()
        self._output.append("[!] Command stopped.")

    def _output_clear(self) -> None:
        self._output.clear()

    def copy_all(self) -> None:
        self._output.selectAll()
        self._output.copy()

    def _read_output(self) -> None:
        data = bytes(self._proc.readAllStandardOutput()).decode("utf-8", errors="replace")
        if data:
            self._output.moveCursor(self._output.textCursor().MoveOperation.End)
            self._output.insertPlainText(data)
            self._output.moveCursor(self._output.textCursor().MoveOperation.End)

    def _finished(self, exit_code: int, _status) -> None:
        self._output.append(f"[exit_code={exit_code}]")
        self._stop_btn.setEnabled(False)
        self._run_btn.setEnabled(True)
