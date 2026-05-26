"""Phase elapsed time + countdown heartbeat — proves scan is alive, not hung."""

from __future__ import annotations

import os
import threading
import time
from contextlib import contextmanager
from typing import Iterator

from core.phase_log import write_phase
from core.utils import valid_env_value

_print_lock = threading.Lock()
_registry: dict[str, PhaseProgress] = {}
_registry_lock = threading.Lock()


def _heartbeat_interval() -> int:
    env = os.environ.get("AUTOPWN_HEARTBEAT_INTERVAL", "").strip()
    if valid_env_value(env):
        try:
            return max(5, int(env))
        except ValueError:
            pass
    try:
        from core.scan_config import get_scan_profile

        return int(get_scan_profile().get("phase_heartbeat_interval", 15))
    except Exception:
        return 15


def _telegram_heartbeat_interval() -> int:
    env = os.environ.get("AUTOPWN_TELEGRAM_HEARTBEAT", "").strip()
    if valid_env_value(env):
        try:
            return max(30, int(env))
        except ValueError:
            pass
    try:
        from core.scan_config import get_scan_profile

        return int(get_scan_profile().get("telegram_heartbeat_interval", 90))
    except Exception:
        return 90


def format_duration(seconds: float) -> str:
    s = max(0, int(seconds))
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    if h:
        return f"{h:02d}:{m:02d}:{sec:02d}"
    return f"{m:02d}:{sec:02d}"


def get_progress(phase_id: str) -> PhaseProgress | None:
    with _registry_lock:
        return _registry.get(str(phase_id))


class PhaseProgress:
    """Background ticker: elapsed, countdown, optional job counters."""

    def __init__(self, phase_id: str, label: str, timeout: int | None = None):
        self.phase_id = str(phase_id)
        self.label = label
        self.timeout = timeout
        self.start = time.monotonic()
        self.status = "starting…"
        self.running_jobs: set[str] = set()
        self.completed_jobs = 0
        self.total_jobs = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._last_telegram = 0.0

    def set_status(self, msg: str) -> None:
        with self._lock:
            self.status = msg

    def set_job_total(self, total: int) -> None:
        with self._lock:
            self.total_jobs = total

    def job_started(self, name: str) -> None:
        with self._lock:
            self.running_jobs.add(name)
            self.status = f"running {name}"

    def job_finished(self, name: str) -> None:
        with self._lock:
            self.running_jobs.discard(name)
            self.completed_jobs += 1

    def start_heartbeat(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name=f"phase-{self.phase_id}-hb", daemon=True)
        self._thread.start()
        self._emit(self._format_line(done=False), force=True)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None
        with _registry_lock:
            _registry.pop(self.phase_id, None)

    def _format_line(self, *, done: bool = False) -> str:
        with self._lock:
            elapsed = time.monotonic() - self.start
            parts = [f"[⏱ PHASE {self.phase_id}]", self.label, f"| elapsed {format_duration(elapsed)}"]
            if self.timeout:
                remaining = max(0.0, self.timeout - elapsed)
                parts.append(f"| countdown {format_duration(remaining)}")
            if self.total_jobs:
                parts.append(f"| jobs {self.completed_jobs}/{self.total_jobs}")
            if self.running_jobs and not done:
                names = sorted(self.running_jobs)
                shown = ", ".join(names[:4])
                if len(names) > 4:
                    shown += f" +{len(names) - 4}"
                parts.append(f"| active [{shown}]")
            if not done:
                parts.append(f"| {self.status}")
            parts.append("| ✓ done" if done else "| ✓ alive")
            return " ".join(parts)

    def _loop(self) -> None:
        interval = _heartbeat_interval()
        tg_interval = _telegram_heartbeat_interval()
        while not self._stop.wait(interval):
            line = self._format_line(done=False)
            self._emit(line)
            if _telegram_scan_active() and (time.time() - self._last_telegram) >= tg_interval:
                self._last_telegram = time.time()
                _send_telegram_heartbeat(line)

    def _emit(self, line: str, *, force: bool = False) -> None:
        with _print_lock:
            print(line, flush=True)
        write_phase(self.phase_id, line)
        try:
            from core.live_scan_log import write as live_write

            live_write(line + "\n")
        except Exception:
            pass
        if not force:
            try:
                from core.scan_transcript import event as transcript_event

                transcript_event(line)
            except Exception:
                pass


def _telegram_scan_active() -> bool:
    return (
        os.environ.get("AUTOPWN_SCAN_SOURCE") == "telegram"
        and os.environ.get("AUTOPWN_HEARTBEAT_TELEGRAM", "1").strip() != "0"
    )


def _send_telegram_heartbeat(line: str) -> None:
    chat = (os.environ.get("AUTOPWN_TELEGRAM_CHAT_ID") or os.environ.get("TELEGRAM_CHAT_ID") or "").strip()
    if not chat or not valid_env_value(chat):
        return
    try:
        from core.notify import send_telegram_message

        send_telegram_message(f"🔄 {line[:350]}")
    except Exception:
        pass


@contextmanager
def track_phase(
    phase_id: str,
    label: str,
    *,
    timeout: int | None = None,
    total_jobs: int = 0,
    target_dir: str | None = None,
) -> Iterator[PhaseProgress]:
    """Context manager — phase log + terminal window + countdown heartbeat."""
    from core.phase_log import begin_phase, end_phase

    begin_phase(phase_id, label, target_dir)
    prog = PhaseProgress(phase_id, label, timeout=timeout)
    if total_jobs:
        prog.set_job_total(total_jobs)
    with _registry_lock:
        _registry[prog.phase_id] = prog
    prog.start_heartbeat()
    summary = ""
    try:
        yield prog
    finally:
        summary = prog._format_line(done=True)
        prog._emit(summary, force=True)
        prog.stop()
        end_phase(phase_id, summary.replace("| ✓ done", "").strip())
