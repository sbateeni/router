"""Per-phase live logs — logs/PHASE_N.log + optional terminal window."""
from __future__ import annotations

import os
import subprocess
import threading
from datetime import datetime

from core.paths import logs_dir, project_root

_lock = threading.Lock()
_active: dict[str, str] = {}
_thread_phase = threading.local()


def phase_log_path(phase_id: str) -> str:
    safe = str(phase_id).replace("/", "_").replace(" ", "_")
    return os.path.join(logs_dir(), f"PHASE_{safe}.log")


def current_phase() -> str | None:
    return getattr(_thread_phase, "phase_id", None)


def set_thread_phase(phase_id: str | None) -> None:
    _thread_phase.phase_id = phase_id


def _open_phase_window(phase_id: str, title: str) -> None:
    if os.environ.get("AUTOPWN_PHASE_WINDOWS", "0").strip() != "1":
        return
    script = os.path.join(project_root(), "scripts", "open_phase_log.sh")
    if not os.path.isfile(script):
        return
    try:
        subprocess.Popen(
            ["bash", script, str(phase_id), title[:80]],
            cwd=project_root(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        pass


def begin_phase(phase_id: str, title: str, target_dir: str | None = None) -> None:
    path = phase_log_path(phase_id)
    with _lock:
        _active[phase_id] = path
    os.makedirs(os.path.dirname(path), exist_ok=True)
    header = [
        "=" * 60,
        f"PHASE {phase_id} — {title}",
        f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
    ]
    if target_dir:
        header.append(f"Target dir: {target_dir}")
    header.append("=" * 60)
    header.append("")
    text = "\n".join(header) + "\n"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    try:
        from core.live_scan_log import write as live_write

        live_write(f"\n>>> PHASE {phase_id}: {title}\n")
    except Exception:
        pass
    _open_phase_window(phase_id, title)


def write_phase(phase_id: str, text: str) -> None:
    if not text:
        return
    path = _active.get(phase_id) or phase_log_path(phase_id)
    line = text if text.endswith("\n") else text + "\n"
    with _lock:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
        except OSError:
            pass
    try:
        from core.live_scan_log import write as live_write

        live_write(line)
    except Exception:
        pass


def end_phase(phase_id: str, summary: str = "") -> None:
    write_phase(phase_id, "")
    write_phase(phase_id, f"Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if summary:
        write_phase(phase_id, summary)
    write_phase(phase_id, "=" * 60)
    with _lock:
        _active.pop(phase_id, None)
