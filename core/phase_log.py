"""Per-phase live logs — logs/PHASE_N.log + auto terminal window on Kali GUI."""

from __future__ import annotations

import os
import subprocess
import threading
from datetime import datetime

from core.paths import logs_dir, project_root

_lock = threading.Lock()
_active: dict[str, str] = {}
_opened_windows: set[str] = set()
_thread_phase = threading.local()


def phase_log_path(phase_id: str) -> str:
    safe = str(phase_id).replace("/", "_").replace(" ", "_")
    return os.path.join(logs_dir(), f"PHASE_{safe}.log")


def current_phase() -> str | None:
    return getattr(_thread_phase, "phase_id", None)


def set_thread_phase(phase_id: str | None) -> None:
    _thread_phase.phase_id = phase_id


def _has_gui() -> bool:
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def phase_windows_mode() -> str:
    """
    off  — no extra terminals
    main — PHASE 0–4 only (default on Kali desktop)
    all  — main + parallel batches (1-iot, 2-nuclei, …)
    """
    raw = os.environ.get("AUTOPWN_PHASE_WINDOWS", "").strip().lower()
    if raw in ("0", "off", "false", "no"):
        return "off"
    if raw in ("all", "full", "batches"):
        return "all"
    if raw in ("1", "on", "true", "yes", "main"):
        return "main"
    if _has_gui():
        return "main"
    return "off"


def _max_phase_windows() -> int:
    try:
        return max(1, int(os.environ.get("AUTOPWN_MAX_PHASE_WINDOWS", "12")))
    except ValueError:
        return 12


def _should_open_window(phase_id: str) -> bool:
    mode = phase_windows_mode()
    if mode == "off":
        return False
    if mode == "all":
        return True
    return str(phase_id) in ("0", "1", "2", "3", "4")


def _open_phase_window(phase_id: str, title: str) -> None:
    if not _should_open_window(phase_id):
        return
    with _lock:
        if phase_id in _opened_windows:
            return
        if len(_opened_windows) >= _max_phase_windows():
            return
        _opened_windows.add(phase_id)

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
        with _lock:
            _opened_windows.discard(phase_id)


def reset_phase_windows() -> None:
    """Call at scan start so re-scans can open fresh terminals."""
    with _lock:
        _opened_windows.clear()


def begin_phase(phase_id: str, title: str, target_dir: str | None = None) -> None:
    path = phase_log_path(phase_id)
    with _lock:
        _active[phase_id] = path
    os.makedirs(os.path.dirname(path), exist_ok=True)
    header = [
        "=" * 60,
        f"PHASE {phase_id} — {title}",
        f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Log file: {path}",
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

        live_write(f"\n>>> PHASE {phase_id}: {title} (see logs/PHASE_{phase_id}.log)\n")
    except Exception:
        pass
    _open_phase_window(phase_id, f"PHASE {phase_id}: {title}")


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
