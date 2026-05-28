"""Mirror GUI scan start/finish to Telegram (optional via TELEGRAM_MIRROR_GUI)."""

from __future__ import annotations

import os


def gui_mirror_enabled() -> bool:
    return os.environ.get("TELEGRAM_MIRROR_GUI", "1").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def _can_send() -> bool:
    if not gui_mirror_enabled():
        return False
    if os.environ.get("AUTOPWN_SCAN_SOURCE") != "gui":
        return False
    from core.notify import telegram_configured, telegram_placeholder_keys_present

    return telegram_configured() and not telegram_placeholder_keys_present()


def notify_gui_scan_started(
    *,
    job_id: str,
    host: str,
    label: str,
    profile: str = "normal",
) -> bool:
    if not _can_send():
        return False
    from core.notify import send_telegram_message

    text = (
        "🖥 **GUI — بدء العملية**\n"
        f"الهدف: `{host}`\n"
        f"الأداة: {label or 'scan'}\n"
        f"البروفايل: {profile}\n"
        f"Job: `{job_id}`"
    )
    return bool(send_telegram_message(text.replace("**", "")))


def notify_gui_scan_finished(
    *,
    job_id: str,
    host: str,
    label: str,
    ok: bool,
    exploited: bool = False,
    error: str = "",
) -> bool:
    if not _can_send():
        return False
    from core.notify import send_telegram_message

    if error == "cancelled":
        status = "⏹ أُلغي من الواجهة"
    elif not ok:
        status = f"❌ انتهى بخطأ{(': ' + error[:200]) if error else ''}"
    elif exploited:
        status = "✅ انتهى — نتائج / استغلال محتمل"
    else:
        status = "✓ انتهى — اكتمل بدون استغلال مؤكد"

    head = (
        f"GUI — انتهت العملية\n"
        f"الهدف: {host}\n"
        f"الأداة: {label or 'scan'}\n"
        f"الحالة: {status}\n"
        f"Job: {job_id}\n"
    )
    body = head
    try:
        from core.paths import project_root
        import os as _os

        td = _os.environ.get("ENGINE_WORKSPACE") or _os.path.join(
            project_root(), "targets", host.replace("http://", "").split("/")[0].split("@")[-1]
        )
        from gui.workspace_hub import build_telegram_digest

        body = head + "\n" + build_telegram_digest(td, host, finished_tool=label, exploited=exploited)
    except Exception:
        body = head + "\nراجع Live Log أو تبويب Results في GUI."
    return bool(send_telegram_message(body[:3900]))
