"""Settings — dependency and PATH checks."""

from __future__ import annotations

import os
import shutil

from PyQt6.QtWidgets import (
    QCheckBox,
    QFormLayout,
    QGroupBox,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.notify import (
    explain_telegram_config,
    load_telegram_env,
    reload_env_from_file,
    send_telegram_message,
    telegram_configured,
    telegram_placeholder_keys_present,
)
from core.paths import project_root
from core.telegram.runner import start_telegram_bot_background
from core.utils import missing_python_modules
from gui.session import GuiSession

EXTERNAL_TOOLS = (
    "nmap", "masscan", "curl", "nuclei", "hydra", "ffuf", "gau", "nikto", "whatweb", "git",
)
CRITICAL_TOOLS = ("git", "nmap", "nuclei")
GUI_ENV_KEYS = (
    "TELEGRAM_BOT_TOKEN",
    "TELEGRAM_CHAT_ID",
    "TELEGRAM_AUTO",
    "TELEGRAM_SSL_VERIFY",
    "GEMINI_API_KEY",
    "OPENROUTER_API_KEY",
)


class SettingsPage(QWidget):
    def __init__(self, session: GuiSession, parent=None):
        super().__init__(parent)
        self._session = session
        self._telegram_thread = None
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("<h2>Settings</h2>"))
        self._status = QLabel()
        self._status.setWordWrap(True)
        layout.addWidget(self._status)
        self._preflight = QLabel()
        self._preflight.setWordWrap(True)
        layout.addWidget(self._preflight)

        env_group = QGroupBox("GUI .env Editor")
        env_form = QFormLayout(env_group)
        self._tg_token = QLineEdit()
        self._tg_token.setEchoMode(QLineEdit.EchoMode.Password)
        self._tg_chat_id = QLineEdit()
        self._tg_auto = QCheckBox("Enable TELEGRAM_AUTO")
        self._tg_ssl = QCheckBox("Disable SSL verify (Windows fallback)")
        self._gemini_key = QLineEdit()
        self._gemini_key.setEchoMode(QLineEdit.EchoMode.Password)
        self._openrouter_key = QLineEdit()
        self._openrouter_key.setEchoMode(QLineEdit.EchoMode.Password)
        env_form.addRow("TELEGRAM_BOT_TOKEN", self._tg_token)
        env_form.addRow("TELEGRAM_CHAT_ID", self._tg_chat_id)
        env_form.addRow("", self._tg_auto)
        env_form.addRow("", self._tg_ssl)
        env_form.addRow("GEMINI_API_KEY", self._gemini_key)
        env_form.addRow("OPENROUTER_API_KEY", self._openrouter_key)
        layout.addWidget(env_group)

        env_row = QHBoxLayout()
        self._env_pull_btn = QPushButton("Pull .env from file → app")
        self._env_pull_btn.setToolTip(
            "Re-read .env from disk and apply to the running app "
            "(use after editing the file manually in an external editor)."
        )
        self._env_pull_btn.clicked.connect(self._pull_env_from_disk)
        self._env_reload_form_btn = QPushButton("Refresh form from .env")
        self._env_reload_form_btn.clicked.connect(self._refresh_form_from_disk)
        self._env_save_btn = QPushButton("Save .env")
        self._env_save_btn.clicked.connect(self._save_env_from_form)
        env_row.addWidget(self._env_pull_btn)
        env_row.addWidget(self._env_reload_form_btn)
        env_row.addWidget(self._env_save_btn)
        layout.addLayout(env_row)

        all_env_group = QGroupBox("All .env Variables")
        all_env_layout = QVBoxLayout(all_env_group)
        self._env_table = QTableWidget(0, 2)
        self._env_table.setHorizontalHeaderLabels(["Key", "Value"])
        self._env_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._env_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        all_env_layout.addWidget(self._env_table)
        all_env_buttons = QHBoxLayout()
        self._env_add_row_btn = QPushButton("Add variable")
        self._env_add_row_btn.clicked.connect(self._add_env_row)
        self._env_remove_row_btn = QPushButton("Remove selected")
        self._env_remove_row_btn.clicked.connect(self._remove_selected_env_rows)
        self._env_save_all_btn = QPushButton("Save all .env")
        self._env_save_all_btn.clicked.connect(self._save_all_env_table)
        all_env_buttons.addWidget(self._env_add_row_btn)
        all_env_buttons.addWidget(self._env_remove_row_btn)
        all_env_buttons.addWidget(self._env_save_all_btn)
        all_env_layout.addLayout(all_env_buttons)
        layout.addWidget(all_env_group)

        telegram_row = QHBoxLayout()
        self._tg_send_btn = QPushButton("Telegram: Send test")
        self._tg_send_btn.clicked.connect(self._send_test_message)
        self._tg_start_btn = QPushButton("Telegram: Start listener")
        self._tg_start_btn.clicked.connect(self._start_listener)
        telegram_row.addWidget(self._tg_send_btn)
        telegram_row.addWidget(self._tg_start_btn)
        layout.addLayout(telegram_row)
        refresh = QPushButton("Refresh checks")
        refresh.clicked.connect(self.refresh)
        layout.addWidget(refresh)
        layout.addStretch()
        self._load_env_into_form()
        self._reload_env_table()

    def refresh(self) -> None:
        load_telegram_env(project_root())
        missing_critical = self._missing_critical_tools()
        tg_ready = telegram_configured() and not telegram_placeholder_keys_present()
        env_ok = os.path.isfile(os.path.join(project_root(), ".env"))

        preflight_lines = ["<b>Preflight</b>"]
        preflight_lines.append(f".env: {'OK' if env_ok else 'MISSING'}")
        preflight_lines.append(f"Critical tools: {'OK' if not missing_critical else ', '.join(missing_critical)}")
        preflight_lines.append(f"Telegram: {'READY' if tg_ready else 'NOT READY'}")
        self._preflight.setText("<br>".join(preflight_lines))

        lines = ["<b>Environment checks</b>", ""]
        missing_py = missing_python_modules()
        lines.append(
            f"Python modules: {'OK' if not missing_py else ', '.join(missing_py)}"
        )
        for tool in EXTERNAL_TOOLS:
            found = shutil.which(tool) or shutil.which(f"{tool}.exe")
            status = "OK" if found else "<span style=color:orange>not in PATH</span>"
            lines.append(f"{tool}: {status}")
        lines.append("")
        lines.append(f"AUTOPWN_SCAN_SOURCE=gui")
        lines.append(f"Keep artifacts: {self._session.keep_artifacts}")
        lines.append("")
        if telegram_configured() and not telegram_placeholder_keys_present():
            lines.append("Telegram config: OK")
        else:
            lines.append("Telegram config: invalid or placeholder in .env")
        if self._telegram_thread and self._telegram_thread.is_alive():
            lines.append("Telegram listener: running in background")
        else:
            lines.append("Telegram listener: not running")
        self._status.setText("<br>".join(lines))
        self._tg_send_btn.setEnabled(tg_ready)
        self._load_env_into_form()

    def _refresh_form_from_disk(self) -> None:
        """Update Settings fields/table from .env on disk (does not change os.environ)."""
        self._load_env_into_form()
        self._reload_env_table()

    def _pull_env_from_disk(self) -> None:
        """Apply .env file contents to the running process (after manual edits)."""
        base = project_root()
        ok, count = reload_env_from_file(base)
        if not ok:
            QMessageBox.warning(
                self,
                ".env",
                f"No .env file found at:\n{self._env_path()}",
            )
            return
        try:
            from core.ai.analyst import (
                ai_configured,
                ai_llm_available,
                ai_provider_status,
                reset_ai_session,
            )

            reset_ai_session()
        except Exception:
            pass
        load_telegram_env(base)
        self._load_env_into_form()
        self._reload_env_table()
        self.refresh()

        ai_msg = ""
        try:
            from core.ai.analyst import ai_configured, ai_llm_available, ai_provider_status

            if ai_configured():
                if ai_llm_available():
                    ai_msg = f"\n\nAI: ready ({ai_provider_status()})"
                else:
                    ai_msg = "\n\nAI: keys loaded — providers unavailable (check models/limits)"
            else:
                ai_msg = "\n\nAI: no valid API keys in .env"
        except Exception:
            pass

        QMessageBox.information(
            self,
            ".env applied",
            f"Pulled {count} variable(s) from .env into the running app.{ai_msg}",
        )

    def _load_env_into_form(self) -> None:
        values = self._read_env_values()
        self._tg_token.setText(values.get("TELEGRAM_BOT_TOKEN", ""))
        self._tg_chat_id.setText(values.get("TELEGRAM_CHAT_ID", ""))
        self._tg_auto.setChecked(values.get("TELEGRAM_AUTO", "1").strip() in ("1", "true", "yes", "on"))
        self._tg_ssl.setChecked(values.get("TELEGRAM_SSL_VERIFY", "1").strip() in ("0", "false", "no", "off"))
        self._gemini_key.setText(values.get("GEMINI_API_KEY", ""))
        self._openrouter_key.setText(values.get("OPENROUTER_API_KEY", ""))

    def _save_env_from_form(self) -> None:
        updates = {
            "TELEGRAM_BOT_TOKEN": self._tg_token.text().strip(),
            "TELEGRAM_CHAT_ID": self._tg_chat_id.text().strip(),
            "TELEGRAM_AUTO": "1" if self._tg_auto.isChecked() else "0",
            "TELEGRAM_SSL_VERIFY": "0" if self._tg_ssl.isChecked() else "1",
            "GEMINI_API_KEY": self._gemini_key.text().strip(),
            "OPENROUTER_API_KEY": self._openrouter_key.text().strip(),
        }
        try:
            self._write_env_values(updates)
            load_telegram_env(project_root())
            QMessageBox.information(self, ".env saved", "Environment values saved successfully.")
            self.refresh()
            self._reload_env_table()
        except OSError as exc:
            QMessageBox.critical(self, ".env save failed", str(exc))

    @staticmethod
    def _env_path() -> str:
        return os.path.join(project_root(), ".env")

    def _read_env_values(self) -> dict[str, str]:
        data: dict[str, str] = {}
        env_path = self._env_path()
        if not os.path.isfile(env_path):
            return data
        with open(env_path, "r", encoding="utf-8-sig", errors="ignore") as fh:
            for line in fh:
                raw = line.strip()
                if not raw or raw.startswith("#") or "=" not in raw:
                    continue
                key, value = raw.split("=", 1)
                data[key.strip()] = value.strip().strip('"').strip("'")
        return data

    def _reload_env_table(self) -> None:
        values = self._read_env_values()
        self._env_table.setRowCount(0)
        for key in sorted(values.keys()):
            self._add_env_row(key, values[key])

    def _add_env_row(self, key: str = "", value: str = "") -> None:
        row = self._env_table.rowCount()
        self._env_table.insertRow(row)
        self._env_table.setItem(row, 0, QTableWidgetItem(key))
        self._env_table.setItem(row, 1, QTableWidgetItem(value))

    def _remove_selected_env_rows(self) -> None:
        rows = sorted({idx.row() for idx in self._env_table.selectedIndexes()}, reverse=True)
        for row in rows:
            self._env_table.removeRow(row)

    def _save_all_env_table(self) -> None:
        updates: dict[str, str] = {}
        for row in range(self._env_table.rowCount()):
            key_item = self._env_table.item(row, 0)
            val_item = self._env_table.item(row, 1)
            key = (key_item.text() if key_item else "").strip()
            value = (val_item.text() if val_item else "").strip()
            if not key:
                continue
            if "=" in key or " " in key:
                QMessageBox.warning(self, "Invalid key", f"Invalid .env key: {key}")
                return
            updates[key] = value
        try:
            self._write_full_env(updates)
            load_telegram_env(project_root())
            QMessageBox.information(self, ".env saved", "All environment variables saved successfully.")
            self.refresh()
            self._reload_env_table()
            self._load_env_into_form()
        except OSError as exc:
            QMessageBox.critical(self, ".env save failed", str(exc))

    def _write_env_values(self, updates: dict[str, str]) -> None:
        env_path = self._env_path()
        lines: list[str] = []
        if os.path.isfile(env_path):
            with open(env_path, "r", encoding="utf-8-sig", errors="ignore") as fh:
                lines = fh.readlines()

        written: set[str] = set()
        out_lines: list[str] = []
        for line in lines:
            if "=" not in line or line.lstrip().startswith("#"):
                out_lines.append(line)
                continue
            key = line.split("=", 1)[0].strip()
            if key in updates:
                out_lines.append(f"{key}={updates[key]}\n")
                written.add(key)
            else:
                out_lines.append(line)

        for key in GUI_ENV_KEYS:
            if key in updates and key not in written:
                out_lines.append(f"{key}={updates[key]}\n")

        with open(env_path, "w", encoding="utf-8") as fh:
            fh.writelines(out_lines)

    def _write_full_env(self, updates: dict[str, str]) -> None:
        env_path = self._env_path()
        existing_lines: list[str] = []
        if os.path.isfile(env_path):
            with open(env_path, "r", encoding="utf-8-sig", errors="ignore") as fh:
                existing_lines = fh.readlines()

        preserved_comments: list[str] = []
        for line in existing_lines:
            raw = line.strip()
            if not raw or raw.startswith("#"):
                preserved_comments.append(line if line.endswith("\n") else f"{line}\n")

        out_lines: list[str] = []
        if preserved_comments:
            out_lines.extend(preserved_comments)
            if out_lines[-1].strip():
                out_lines.append("\n")
        for key in sorted(updates.keys()):
            out_lines.append(f"{key}={updates[key]}\n")

        with open(env_path, "w", encoding="utf-8") as fh:
            fh.writelines(out_lines)

    def _missing_critical_tools(self) -> list[str]:
        missing: list[str] = []
        for tool in CRITICAL_TOOLS:
            found = shutil.which(tool) or shutil.which(f"{tool}.exe")
            if not found:
                missing.append(tool)
        return missing

    def _send_test_message(self) -> None:
        load_telegram_env(project_root())
        if not telegram_configured() or telegram_placeholder_keys_present():
            QMessageBox.warning(
                self,
                "Telegram not configured",
                explain_telegram_config(project_root()),
            )
            return
        ok = send_telegram_message("✅ GUI test message: send path is working.")
        if ok:
            QMessageBox.information(
                self,
                "Telegram send",
                "Test message sent successfully to TELEGRAM_CHAT_ID.",
            )
        else:
            QMessageBox.critical(
                self,
                "Telegram send failed",
                "Could not send test message. Check token/chat id/network.",
            )
        self.refresh()

    def _start_listener(self) -> None:
        load_telegram_env(project_root())
        if not telegram_configured() or telegram_placeholder_keys_present():
            QMessageBox.warning(
                self,
                "Telegram not configured",
                explain_telegram_config(project_root()),
            )
            return
        if self._telegram_thread and self._telegram_thread.is_alive():
            QMessageBox.information(
                self,
                "Telegram listener",
                "Listener is already running.",
            )
            return
        self._telegram_thread = start_telegram_bot_background(project_root())
        if self._telegram_thread:
            QMessageBox.information(
                self,
                "Telegram listener",
                "Listener started. Now bot can receive commands/messages.",
            )
        else:
            QMessageBox.warning(
                self,
                "Telegram listener",
                "Could not start listener. Verify .env and logs/telegram.log.",
            )
        self.refresh()
