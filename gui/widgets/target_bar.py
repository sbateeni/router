"""Shared target / profile controls at top of main window."""

from __future__ import annotations

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QWidget,
)

from gui.app_restart import restart_application
from gui.session import GuiSession


class TargetBar(QWidget):
    target_changed = pyqtSignal()

    def __init__(self, session: GuiSession, parent=None):
        super().__init__(parent)
        self._session = session
        layout = QHBoxLayout(self)

        layout.addWidget(QLabel("Target:"))
        self._target_edit = QLineEdit()
        self._target_edit.setPlaceholderText("IP, URL, or domain/path")
        self._target_edit.returnPressed.connect(self._apply)
        layout.addWidget(self._target_edit, stretch=2)

        layout.addWidget(QLabel("Subnet:"))
        self._subnet_edit = QLineEdit()
        self._subnet_edit.setPlaceholderText("192.168.1.0/24 (LAN discovery)")
        layout.addWidget(self._subnet_edit, stretch=1)

        layout.addWidget(QLabel("Profile:"))
        self._profile_combo = QComboBox()
        self._profile_combo.addItems(["normal", "deep"])
        self._profile_combo.currentTextChanged.connect(self._on_profile)
        layout.addWidget(self._profile_combo)

        self._keep_cb = QCheckBox("Keep artifacts")
        self._keep_cb.setChecked(True)
        self._keep_cb.toggled.connect(self._on_keep)
        layout.addWidget(self._keep_cb)

        self._apply_btn = QPushButton("Apply target")
        self._apply_btn.clicked.connect(self._apply)
        layout.addWidget(self._apply_btn)

        self._reset_btn = QPushButton("New workspace")
        self._reset_btn.setObjectName("secondaryBtn")
        self._reset_btn.clicked.connect(self._reset_workspace)
        layout.addWidget(self._reset_btn)

        self._restart_btn = QPushButton("Restart app")
        self._restart_btn.setObjectName("secondaryBtn")
        self._restart_btn.setToolTip("Close and relaunch the GUI (bin/gui_app.py)")
        self._restart_btn.clicked.connect(lambda: restart_application(self.window()))
        layout.addWidget(self._restart_btn)

        self._ws_label = QLabel("")
        layout.addWidget(self._ws_label, stretch=1)

    def sync_from_session(self) -> None:
        self._target_edit.setText(self._session.target)
        self._subnet_edit.setText(self._session.subnet)
        idx = self._profile_combo.findText(self._session.profile)
        if idx >= 0:
            self._profile_combo.setCurrentIndex(idx)
        self._keep_cb.setChecked(self._session.keep_artifacts)
        self._update_ws_label()

    def _on_profile(self, text: str) -> None:
        self._session.set_profile(text)

    def _on_keep(self, checked: bool) -> None:
        self._session.keep_artifacts = checked

    def _apply(self) -> None:
        self._session.target = self._target_edit.text().strip()
        self._session.subnet = self._subnet_edit.text().strip()
        self._session.set_profile(self._profile_combo.currentText())
        self._session.keep_artifacts = self._keep_cb.isChecked()
        self._session._prepared = False
        if self._session.target:
            self._session.prepare(force_reset=not self._session.keep_artifacts)
        self._update_ws_label()
        self.target_changed.emit()

    def _reset_workspace(self) -> None:
        self._session.keep_artifacts = False
        self._keep_cb.setChecked(False)
        self._session._prepared = False
        if self._session.target.strip():
            self._session.prepare(force_reset=True)
        self._update_ws_label()
        self.target_changed.emit()

    def _update_ws_label(self) -> None:
        if self._session.target_dir:
            self._ws_label.setText(f"→ {self._session.target_dir}")
        else:
            self._ws_label.setText("")
