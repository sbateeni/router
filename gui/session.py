"""Global GUI scan session — target, workspace, profile."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from core.gui_workspace import prepare_target_workspace
from core.paths import project_root
from core.scan_config import set_scan_profile


@dataclass
class GuiSession:
    target: str = ""
    scan_host: str = ""
    workspace_name: str = ""
    target_dir: str = ""
    profile: str = "normal"
    keep_artifacts: bool = True
    subnet: str = ""
    _prepared: bool = field(default=False, repr=False)

    def prepare(self, *, force_reset: bool = False) -> bool:
        if not self.target.strip():
            return False
        keep = self.keep_artifacts and not force_reset and self._prepared
        info = prepare_target_workspace(
            self.target,
            keep_artifacts=keep,
            base_dir=project_root(),
        )
        self.scan_host = info["scan_host"]
        self.workspace_name = info["workspace_name"]
        self.target_dir = info["target_dir"]
        self._prepared = True
        set_scan_profile(self.profile)
        os.environ["AUTOPWN_SCAN_SOURCE"] = "gui"
        os.environ["ENGINE_WORKSPACE"] = self.target_dir
        try:
            from core.target_history import record_session

            record_session(
                target=self.target,
                scan_host=self.scan_host,
                workspace_name=self.workspace_name,
                target_dir=self.target_dir,
                profile=self.profile,
                status=None,
            )
        except Exception:
            pass
        return True

    def set_profile(self, profile: str) -> None:
        self.profile = profile if profile in ("normal", "deep") else "normal"
        set_scan_profile(self.profile)

    def display_label(self) -> str:
        return self.target or "(no target)"

    def workspace_exists(self) -> bool:
        return bool(self.target_dir) and os.path.isdir(self.target_dir)
