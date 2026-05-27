"""Per-chat session state and status formatting."""

import os
import threading

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
        "queue": [],
        "lan_devices": [],
    }


def get_session(chat_id):
    if chat_id not in _sessions:
        _sessions[chat_id] = new_session()
    sess = _sessions[chat_id]
    if "active_jobs" not in sess:
        sess["active_jobs"] = {}
    return sess


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


def format_status(sess):
    lines = []
    jobs = sess.get("active_jobs") or {}
    if jobs:
        lines.append(f"▶ مسح نشط ({len(jobs)}/{MAX_CONCURRENT_SCANS} متزامن):")
        for job_id, meta in jobs.items():
            ip = meta.get("ip", "?")
            mode = meta.get("mode_label", "?")
            lines.append(f"  • {ip} — {mode} [{job_id}]")
    else:
        lines.append("▶ لا يوجد مسح نشط.")

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
