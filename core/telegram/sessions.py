"""Per-chat session state and status formatting."""

import os
import threading
import uuid

from core.telegram.constants import ATTACK_MODES, MAX_CONCURRENT_SCANS, MAX_QUEUE_SIZE

_chat_lock = threading.Lock()
_sessions = {}


def chat_lock():
    return _chat_lock


def new_session():
    return {
        "state": "idle",
        "ip": None,
        "pending_ip": None,
        "scanning": False,
        "current_ip": None,
        "current_mode": None,
        "active_jobs": {},
        "background_tasks": {},
        "queue": [],
        "lan_devices": [],
    }


def get_session(chat_id):
    chat_key = str(chat_id)
    if chat_key not in _sessions and chat_id in _sessions:
        _sessions[chat_key] = _sessions.pop(chat_id)
    if chat_key not in _sessions:
        _sessions[chat_key] = new_session()
    sess = _sessions[chat_key]
    if "active_jobs" not in sess:
        sess["active_jobs"] = {}
    if "background_tasks" not in sess:
        sess["background_tasks"] = {}
    return sess


def register_background_task(chat_id, label: str) -> str:
    """Track /lan, /osint, etc. that run outside the scan worker pool."""
    task_id = f"bg-{uuid.uuid4().hex[:8]}"
    with chat_lock():
        sess = get_session(chat_id)
        sess.setdefault("background_tasks", {})[task_id] = {"label": label}
    return task_id


def finish_background_task(chat_id, task_id: str) -> None:
    with chat_lock():
        sess = get_session(chat_id)
        sess.get("background_tasks", {}).pop(task_id, None)


def reconcile_session(chat_id, sess) -> None:
    """Sync session active_jobs with the cancel registry and live log files."""
    from core.live_scan_log import discover_incomplete_logs
    from core.scan_cancel import get_jobs_for_chat

    registry = get_jobs_for_chat(chat_id)
    jobs = sess.setdefault("active_jobs", {})

    for job_id, info in registry.items():
        meta = info.get("meta") or {}
        if job_id not in jobs:
            jobs[job_id] = {
                "ip": meta.get("ip", "?"),
                "mode_label": meta.get("mode_label", "?"),
                "profile": meta.get("profile"),
                "recovered": True,
            }
        alive = info.get("alive_pids") or []
        if alive:
            jobs[job_id]["alive_pids"] = len(alive)

    stale = [job_id for job_id in jobs if job_id not in registry]
    for job_id in stale:
        jobs.pop(job_id, None)

    for entry in discover_incomplete_logs(chat_id=chat_id):
        job_id = entry.get("job_id") or ""
        if not job_id or job_id in jobs:
            continue
        target = entry.get("target") or "?"
        ip = target.split("|")[0].strip() if "|" in target else target
        jobs[job_id] = {
            "ip": ip,
            "mode_label": entry.get("source") or "scan",
            "recovered": True,
            "log_path": entry.get("log_path"),
        }

    sync_session_flags(sess)


def sync_session_flags(sess):
    """Keep legacy scanning/current_* fields in sync with active_jobs."""
    jobs = sess.get("active_jobs") or {}
    sess["scanning"] = bool(jobs)
    if jobs:
        first = next(iter(jobs.values()))
        sess["current_ip"] = first.get("ip")
        sess["current_mode"] = first.get("mode_label")
        if sess.get("state") not in ("choose_mode", "choose_mode_queued"):
            sess["state"] = "scanning"
    else:
        sess["current_ip"] = None
        sess["current_mode"] = None
        if sess.get("state") == "scanning":
            sess["state"] = "idle"


def format_status(sess, chat_id=None):
    if chat_id is not None:
        reconcile_session(chat_id, sess)

    lines = []
    jobs = sess.get("active_jobs") or {}
    bg_tasks = sess.get("background_tasks") or {}

    if jobs:
        lines.append(f"▶ مسح نشط ({len(jobs)}/{MAX_CONCURRENT_SCANS} متزامن):")
        for job_id, meta in jobs.items():
            ip = meta.get("ip", "?")
            mode = meta.get("mode_label", "?")
            suffix = ""
            if meta.get("recovered"):
                suffix = " (استعادة من السجل)"
            alive = meta.get("alive_pids")
            if alive:
                suffix += f" — {alive} pid"
            lines.append(f"  • {ip} — {mode} [{job_id}]{suffix}")
    elif bg_tasks:
        lines.append("▶ لا يوجد مسح Telegram مسجّل في الجلسة.")
    else:
        lines.append("▶ لا يوجد مسح نشط.")

    if bg_tasks:
        lines.append(f"⚙ مهام خلفية ({len(bg_tasks)}):")
        for task_id, meta in bg_tasks.items():
            lines.append(f"  • {meta.get('label', '?')} [{task_id}]")

    queue = sess.get("queue") or []
    if queue:
        lines.append(f"⏳ قائمة الانتظار ({len(queue)}/{MAX_QUEUE_SIZE}):")
        for idx, job in enumerate(queue, 1):
            lines.append(f"  {idx}. {job['ip']} — {job.get('mode_label', '?')}")
    elif sess.get("pending_ip"):
        pending = sess["pending_ip"]
        label = pending.get("ip", pending) if isinstance(pending, dict) else pending
        lines.append(f"⏳ بانتظار اختيار نوع المسح: {label}")
    else:
        lines.append("⏳ قائمة الانتظار: فارغة")

    if sess.get("state") == "choose_mode" and sess.get("ip"):
        ip = sess["ip"].get("ip", sess["ip"])
        lines.append(f"📋 بانتظار اختيار وضع المسح: {ip}")

    if chat_id is not None and not jobs:
        from core.live_scan_log import discover_incomplete_logs

        cli_logs = [
            e for e in discover_incomplete_logs(chat_id=None, max_age_seconds=7200)
            if not e.get("job_id") or "-" not in str(e.get("job_id", ""))
        ]
        if cli_logs:
            lines.append("⚠ مسح محلي (CLI/menu) قد يكون جارياً — logs/LIVE_SCAN*.log")

    max_parallel = os.environ.get("AUTOPWN_TELEGRAM_MAX_PARALLEL", str(MAX_CONCURRENT_SCANS))
    lines.append(f"\n🛑 /stopscan — إيقاف كل المسوحات | /clearqueue — مسح الانتظار فقط")
    lines.append(f"⚙ متزامن: {max_parallel} (AUTOPWN_TELEGRAM_MAX_PARALLEL)")
    return "\n".join(lines)


def mode_label(selection, scan_profile):
    return next(
        (m[1] for m in ATTACK_MODES if m[0] == selection and m[2] == scan_profile),
        str(selection),
    )


def mode_keyboard():
    rows = []
    row = []
    for sel, label, prof in ATTACK_MODES:
        deep_flag = "d" if prof == "deep" else "n"
        row.append({"text": label[:40], "callback_data": f"m:{sel}:{deep_flag}"})
        if len(row) == 2:
            rows.append(row)
            row = []
    if row:
        rows.append(row)
    rows.append([{"text": "إلغاء الاختيار", "callback_data": "cancel"}])
    return {"inline_keyboard": rows}


def queue_full(sess):
    return len(sess.get("queue", [])) >= MAX_QUEUE_SIZE
