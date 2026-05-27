"""Cooperative scan cancellation — used by Telegram parallel jobs."""
from __future__ import annotations

import os
import signal
import threading

_lock = threading.Lock()
_jobs: dict[str, dict] = {}


class ScanCancelled(Exception):
    """Raised when the user cancels a running scan."""


def start_job(job_id: str, chat_id=None, meta: dict | None = None) -> threading.Event:
    """Register a running scan job (idempotent — safe to call twice)."""
    with _lock:
        record = _jobs.get(job_id)
        if record is not None:
            if meta:
                record.setdefault("meta", {}).update(meta)
            if chat_id is not None:
                record["chat_id"] = chat_id
            return record["event"]
        event = threading.Event()
        _jobs[job_id] = {
            "event": event,
            "pids": set(),
            "chat_id": chat_id,
            "meta": dict(meta or {}),
        }
        return event


def finish_job(job_id: str) -> None:
    with _lock:
        _jobs.pop(job_id, None)


def current_job_id() -> str | None:
    value = os.environ.get("AUTOPWN_JOB_ID", "").strip()
    return value or None


def _pid_alive(pid: int) -> bool:
    if not pid:
        return False
    try:
        os.kill(int(pid), 0)
        return True
    except (ProcessLookupError, PermissionError, OSError):
        return False


def get_jobs_for_chat(chat_id) -> dict[str, dict]:
    """Return active cancel-registry jobs for a Telegram chat."""
    chat = str(chat_id)
    with _lock:
        out: dict[str, dict] = {}
        for job_id, record in _jobs.items():
            if str(record.get("chat_id")) != chat:
                continue
            pids = list(record.get("pids") or [])
            alive = [p for p in pids if _pid_alive(p)]
            out[job_id] = {
                "meta": dict(record.get("meta") or {}),
                "pids": pids,
                "alive_pids": alive,
            }
        return out


def is_cancelled() -> bool:
    job_id = current_job_id()
    if not job_id:
        return False
    with _lock:
        record = _jobs.get(job_id)
        return bool(record and record["event"].is_set())


def check_cancelled() -> None:
    if is_cancelled():
        raise ScanCancelled("Scan cancelled by user")


def register_pid(pid: int) -> None:
    if not pid:
        return
    job_id = current_job_id()
    if not job_id:
        return
    with _lock:
        record = _jobs.get(job_id)
        if record is not None:
            record["pids"].add(int(pid))


def unregister_pid(pid: int) -> None:
    if not pid:
        return
    job_id = current_job_id()
    if not job_id:
        return
    with _lock:
        record = _jobs.get(job_id)
        if record is not None:
            record["pids"].discard(int(pid))


def _terminate_pid(pid: int) -> None:
    if not pid:
        return
    if os.name != "nt":
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
            return
        except (ProcessLookupError, PermissionError, OSError):
            pass
    try:
        os.kill(pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        pass


def cancel_job(job_id: str) -> bool:
    with _lock:
        record = _jobs.get(job_id)
        if not record:
            return False
        record["event"].set()
        pids = list(record["pids"])
    for pid in pids:
        _terminate_pid(pid)
    return True


def cancel_jobs_for_chat(chat_id) -> int:
    chat = str(chat_id)
    with _lock:
        job_ids = [
            job_id
            for job_id, record in _jobs.items()
            if str(record.get("chat_id")) == chat
        ]
    stopped = 0
    for job_id in job_ids:
        if cancel_job(job_id):
            stopped += 1
    return stopped
