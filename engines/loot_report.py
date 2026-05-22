"""Collect and print final attack results (Router Scan style report)."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime


@dataclass
class LootEntry:
    ip: str
    port: int = 80
    device_type: str = "UNKNOWN"
    model: str = ""
    username: str = ""
    password: str = ""
    auth_method: str = ""
    wireless_ssid: str = ""
    wireless_key: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def has_credentials(self) -> bool:
        return bool(self.username and self.password)

    def creds_display(self) -> str:
        if self.username and self.password:
            return f"{self.username}:{self.password}"
        if self.password:
            return f"(backdoor/partial) :{self.password}"
        return "—"


class LootReport:
    def __init__(self, ip: str):
        self.ip = ip
        self.entries: list[LootEntry] = []
        self.open_ports: list[int] = []
        self.files: list[str] = []
        self.notes: list[str] = []

    def add(self, entry: LootEntry) -> None:
        for existing in self.entries:
            if (
                existing.port == entry.port
                and existing.device_type == entry.device_type
                and existing.creds_display() == entry.creds_display()
            ):
                if entry.model and not existing.model:
                    existing.model = entry.model
                existing.extra.update(entry.extra)
                return
        self.entries.append(entry)

    def add_note(self, note: str) -> None:
        if note not in self.notes:
            self.notes.append(note)

    def add_file(self, path: str) -> None:
        if os.path.exists(path) and path not in self.files:
            self.files.append(path)

    def best_entry(self) -> LootEntry | None:
        for entry in self.entries:
            if entry.has_credentials and entry.auth_method not in ("backdoor-only",):
                return entry
        for entry in self.entries:
            if entry.has_credentials:
                return entry
        return self.entries[0] if self.entries else None

    def save(self) -> str:
        os.makedirs("db", exist_ok=True)
        path = f"db/{self.ip}_loot.json"
        payload = {
            "ip": self.ip,
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "open_ports": self.open_ports,
            "entries": [asdict(e) for e in self.entries],
            "files": self.files,
            "notes": self.notes,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        return path

    def print_final(self) -> None:
        print("\n" + "=" * 70)
        print("           FINAL AUTO-PWN REPORT — CREDENTIALS & DETAILS")
        print("=" * 70)
        print(f"  Target IP     : {self.ip}")
        if self.open_ports:
            print(f"  Open Ports    : {', '.join(map(str, self.open_ports))}")

        best = self.best_entry()
        if best:
            print("\n  --- PRIMARY ACCESS ---")
            print(f"  Device Type   : {best.device_type}")
            if best.model:
                print(f"  Model         : {best.model}")
            print(f"  Port          : {best.port}")
            print(f"  Username      : {best.username or '—'}")
            print(f"  Password      : {best.password or '—'}")
            print(f"  Authorization : {best.creds_display()}")
            if best.auth_method:
                print(f"  Auth Method   : {best.auth_method}")
            if best.extra.get("backdoor_login"):
                print(f"  Backdoor      : {best.extra['backdoor_login']}")
            if best.wireless_ssid:
                print(f"  Wi-Fi SSID    : {best.wireless_ssid}")
            if best.wireless_key:
                print(f"  Wi-Fi Key     : {best.wireless_key}")

        if len(self.entries) > 1:
            print("\n  --- ALL FINDINGS ---")
            for i, entry in enumerate(self.entries, 1):
                line = f"  [{i}] {entry.port}/tcp | {entry.device_type}"
                if entry.model:
                    line += f" | {entry.model}"
                line += f" | {entry.creds_display()}"
                if entry.auth_method:
                    line += f" ({entry.auth_method})"
                print(line)

        if self.files:
            print("\n  --- SAVED FILES ---")
            for path in self.files:
                print(f"    > {path}")

        if self.notes:
            print("\n  --- NOTES ---")
            for note in self.notes:
                print(f"    * {note}")

        if not self.entries and not self.files:
            print("\n  [!] No confirmed credentials found automatically.")
            print("      Check targets/{}/ for partial loot (snapshots, config dumps).".format(self.ip))

        report_path = self.save()
        print(f"\n  Report saved  : {report_path}")
        print("=" * 70 + "\n")
