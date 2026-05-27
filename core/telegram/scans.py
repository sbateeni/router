"""Scan execution, parallel workers, queue, and real cancellation."""

import os
import threading
import uuid

from core.notify import notify_scan_complete
from core.report import generate_scan_report
from core.report.parsers import save_target_hints, sanitize_target_dir_name
from core.runner import run_selected_tool
from core.scan_cancel import ScanCancelled, cancel_jobs_for_chat, finish_job, start_job
from core.utils import reset_target_workspace

from core.telegram.api import send_to_chat
from core.telegram.constants import MAX_CONCURRENT_SCANS, MAX_QUEUE_SIZE
from core.telegram.sessions import chat_lock, get_session, mode_keyboard, queue_full, sync_session_flags
from core.telegram.targets import job_from_target, target_prompt_text


def _new_job_id(chat_id) -> str:
    return f"{chat_id}-{uuid.uuid4().hex[:8]}"


def _active_count(sess) -> int:
    return len(sess.get("active_jobs") or {})


def cancel_mode_selection(sess) -> None:
    """Abort mode-pick UI only — does not stop running scans."""
    sess["state"] = "idle"
    sess["ip"] = None
    sess["pending_ip"] = None


def cancel_all_scans(chat_id, sess, *, clear_queue: bool = True) -> tuple[int, int]:
    """Stop all running scan processes for this chat; optionally drain the queue."""
    queued = len(sess.get("queue") or [])
    if clear_queue:
        sess["queue"] = []
    stopped = cancel_jobs_for_chat(chat_id)
    cancel_mode_selection(sess)
    if sess.get("state") == "choose_mode_queued":
        sess["state"] = "idle"
    sync_session_flags(sess)
    return stopped, queued if clear_queue else 0


def force_idle(sess):
    """Legacy alias — clears UI flags only (prefer cancel_all_scans for real stop)."""
    cancel_mode_selection(sess)
    sync_session_flags(sess)


def run_scan_job(chat_id, job, base_dir, job_id=None):
    scan_host = job.get("scan_host") or job["ip"]
    workspace = job.get("workspace_name") or sanitize_target_dir_name(scan_host)
    selection = job["selection"]
    scan_profile = job["profile"]

    target_dir = os.path.join(base_dir, "targets", workspace)
    os.makedirs(target_dir, exist_ok=True)
    if job_id:
        os.environ["AUTOPWN_JOB_ID"] = job_id
    os.environ["AUTOPWN_SCAN_SOURCE"] = "telegram"
    os.environ["AUTOPWN_TELEGRAM_CHAT_ID"] = str(chat_id)
    reset_target_workspace(target_dir)

    hints = job.get("hints") or {}
    if hints:
        save_target_hints(target_dir, hints)
        if hints.get("login_path"):
            send_to_chat(
                chat_id,
                f"📌 مسار الدخول: {hints['login_path']}\n"
                f"   (Tenda وغيرها — Hydra/Nuclei يستهدف هذا المسار أولاً)",
            )

    exploited = run_selected_tool(
        selection, scan_host, target_dir, profile=scan_profile, subnet=None,
    )
    report_path, confirmed = generate_scan_report(
        scan_host, target_dir, selection, exploited,
        current_phase="Completed", profile=scan_profile,
    )

    ai_analysis = None
    if selection == 14:
        ai_path = os.path.join(target_dir, "AI_ANALYSIS.txt")
        if os.path.exists(ai_path):
            with open(ai_path, encoding="utf-8") as fh:
                ai_analysis = fh.read()

    status_ar = "نجاح — نتائج محتملة" if confirmed else "اكتمل — لا استغلال مؤكد"
    send_to_chat(
        chat_id,
        f"✅ انتهى المسح على {scan_host}\nالوضع: {status_ar}\nالتقرير يُرسل الآن...",
    )
    notify_scan_complete(
        scan_host, target_dir, report_path, confirmed,
        profile=scan_profile, ai_analysis=ai_analysis, chat_id=str(chat_id),
    )
    return confirmed


def _try_start_queued(chat_id, base_dir) -> None:
    """Start queued jobs while worker slots are free."""
    sess = get_session(chat_id)
    lock = chat_lock()
    started = []

    with lock:
        while sess.get("queue") and _active_count(sess) < MAX_CONCURRENT_SCANS:
            job = sess["queue"].pop(0)
            job_id = _new_job_id(chat_id)
            sess.setdefault("active_jobs", {})[job_id] = {
                "ip": job["ip"],
                "mode_label": job.get("mode_label"),
                "profile": job.get("profile"),
            }
            sync_session_flags(sess)
            started.append((job, job_id))

    for job, job_id in started:
        send_to_chat(
            chat_id,
            f"▶ بدء مسح من قائمة الانتظار\nالهدف: {job['ip']}\n"
            f"النوع: {job.get('mode_label')}\n"
            f"📺 Live Log: logs/LIVE_SCAN_{job_id}.log",
        )
        threading.Thread(
            target=_scan_worker,
            args=(chat_id, job, base_dir, job_id),
            daemon=True,
        ).start()


def _scan_worker(chat_id, job, base_dir, job_id):
    sess = get_session(chat_id)
    start_job(job_id, chat_id=chat_id)
    cancelled = False

    try:
        run_scan_job(chat_id, job, base_dir, job_id=job_id)
    except ScanCancelled:
        cancelled = True
        send_to_chat(chat_id, f"🛑 تم إيقاف المسح على {job['ip']}")
    except Exception as exc:
        import traceback
        tb = traceback.format_exc(limit=6)
        print(f"[!] Scan error for {job.get('ip')}: {exc}\n{tb}", flush=True)
        send_to_chat(chat_id, f"❌ خطأ أثناء مسح {job['ip']}: {exc}")
    finally:
        finish_job(job_id)
        with chat_lock():
            sess.get("active_jobs", {}).pop(job_id, None)
            sync_session_flags(sess)
        os.environ.pop("AUTOPWN_JOB_ID", None)
        os.environ.pop("AUTOPWN_SCAN_SOURCE", None)
        os.environ.pop("AUTOPWN_TELEGRAM_CHAT_ID", None)

        _try_start_queued(chat_id, base_dir)

        sess = get_session(chat_id)
        if not sess.get("active_jobs") and not sess.get("queue") and not cancelled:
            send_to_chat(chat_id, "✓ جميع المسوحات اكتملت.")


def start_scan(chat_id, job, base_dir):
    """Start a scan immediately or queue it when all worker slots are busy."""
    sess = get_session(chat_id)
    lock = chat_lock()

    with lock:
        if _active_count(sess) >= MAX_CONCURRENT_SCANS:
            if queue_full(sess):
                send_to_chat(
                    chat_id,
                    f"⚠ الحد الأقصى: {MAX_CONCURRENT_SCANS} مسح متزامن + "
                    f"{MAX_QUEUE_SIZE} في الانتظار.\n"
                    f"استخدم /stopscan أو /clearqueue.",
                )
                return
            sess.setdefault("queue", []).append(job)
            pos = len(sess["queue"])
            send_to_chat(
                chat_id,
                f"⏳ {MAX_CONCURRENT_SCANS} مسح قيد التشغيل\n"
                f"✓ أُضيف {job['ip']} للانتظار (الموقع {pos})\n"
                f"النوع: {job.get('mode_label')}",
            )
            return

        job_id = _new_job_id(chat_id)
        sess.setdefault("active_jobs", {})[job_id] = {
            "ip": job["ip"],
            "mode_label": job.get("mode_label"),
            "profile": job.get("profile"),
        }
        sync_session_flags(sess)

    active_n = _active_count(get_session(chat_id))
    send_to_chat(
        chat_id,
        f"▶ بدء المسح ({active_n}/{MAX_CONCURRENT_SCANS} متزامن)\n"
        f"الهدف: {job['ip']}\n"
        f"النوع: {job.get('mode_label')}\n"
        f"الملف الشخصي: {job['profile']}\n\n"
        f"سيصلك التقرير في تيليجرام عند الانتهاء.\n"
        f"📺 Live Log: logs/LIVE_SCAN_{job_id}.log\n"
        f"🛑 /stopscan — إيقاف فعلي",
    )

    threading.Thread(
        target=_scan_worker,
        args=(chat_id, job, base_dir, job_id),
        daemon=True,
    ).start()


def enqueue_or_prompt(chat_id, target, base_dir):
    """New IP → mode keyboard; queue only when all parallel slots are full."""
    sess = get_session(chat_id)

    if _active_count(sess) >= MAX_CONCURRENT_SCANS:
        if queue_full(sess):
            send_to_chat(
                chat_id,
                f"⚠ ممتلئ: {MAX_CONCURRENT_SCANS} مسح جاري + {MAX_QUEUE_SIZE} انتظار.\n"
                f"استخدم /status أو /stopscan.",
            )
            return

        sess["pending_ip"] = target
        sess["state"] = "choose_mode_queued"
        send_to_chat(
            chat_id,
            f"⏳ {MAX_CONCURRENT_SCANS} مسح قيد التشغيل — سيُضاف للانتظار\n"
            f"في الانتظار: {len(sess.get('queue', []))}\n\n"
            f"{target_prompt_text(target)}",
            reply_markup=mode_keyboard(),
        )
        return

    if sess.get("state") == "choose_mode" and sess.get("ip"):
        send_to_chat(
            chat_id,
            f"⚠ اختر نوع المسح أولاً للهدف {sess['ip'].get('ip', sess['ip'])} أو /cancel",
        )
        return

    sess["ip"] = target
    sess["state"] = "choose_mode"
    active = _active_count(sess)
    extra = ""
    if active:
        extra = f"\n(مسح متزامن: {active}/{MAX_CONCURRENT_SCANS} جاري — يمكنك إرسال المزيد)\n"
    send_to_chat(
        chat_id,
        target_prompt_text(target) + extra,
        reply_markup=mode_keyboard(),
    )
