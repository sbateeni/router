"""Mutable attack state passed between AUTO-PWN phases."""

from __future__ import annotations

from dataclasses import dataclass, field

from engines.loot_report import LootReport
from engines.scanner import Scanner


@dataclass
class AttackSession:
    ip: str
    target_input: str
    manual_mode: bool
    open_ports: list[int]
    loot: LootReport
    all_users: list[str]
    all_passwords: list[str]
    scanner: Scanner = field(default_factory=Scanner)
    router_pwned: bool = False
    camera_handled: bool = False
    osint_results: dict = field(default_factory=dict)
