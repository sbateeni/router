"""Per-chat session state and status formatting."""

import threading

from core.telegram.constants import ATTACK_MODES, MAX_QUEUE_SIZE

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
        "queue": [],
        "lan_devices": [],
    }


def get_session(chat_id):
    if chat_id not in _sessions:
        _sessions[chat_id] = new_session()
    return _sessions[chat_id]


def format_status(sess):
    lines = []
    if sess.get("scanning") and sess.get("current_ip"):
        mode = sess.get("current_mode") or "?"
        lines.append(f"▶ جاري المسح: {sess['current_ip']} ({mode})")
    else:
        lines.append("▶ لا يوجد مسح نشط.")
    queue = sess.get("queue") or []
    if queue:
        lines.append(f"⏳ قائمة الانتظار ({len(queue)}):")
        for idx, job in enumerate(queue, 1):
            lines.append(f"  {idx}. {job['ip']} — {job.get('mode_label', '?')}")
    elif sess.get("pending_ip"):
        lines.append(f"⏳ بانتظار اختيار نوع المسح: {sess['pending_ip']}")
    else:
        lines.append("⏳ قائمة الانتظار: فارغة")
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
    rows.append([{"text": "إلغاء", "callback_data": "cancel"}])
    return {"inline_keyboard": rows}


def queue_full(sess):
    return len(sess.get("queue", [])) >= MAX_QUEUE_SIZE
