"""Scan execution, queue, and target enqueue flow."""

import os
import threading

from core.notify import notify_scan_complete
from core.report import generate_scan_report
from core.report.parsers import save_target_hints, sanitize_target_dir_name
from core.runner import run_selected_tool
from core.utils import reset_target_workspace

from core.telegram.api import send_to_chat
from core.telegram.constants import MAX_QUEUE_SIZE
from core.telegram.sessions import chat_lock, get_session, mode_keyboard
from core.telegram.targets import job_from_target, target_prompt_text


def force_idle(sess):
    """Reset session after error or /stopscan (fixes stuck «مسح جاري»)."""
    sess["scanning"] = False
    sess["current_ip"] = None
    sess["current_mode"] = None
    sess["state"] = "idle"
    sess["ip"] = None
    sess["pending_ip"] = None


def run_scan_job(chat_id, job, base_dir):
    scan_host = job.get("scan_host") or job["ip"]
    workspace = job.get("workspace_name") or sanitize_target_dir_name(scan_host)
    selection = job["selection"]
    scan_profile = job["profile"]

    target_dir = os.path.join(base_dir, "targets", workspace)
    os.makedirs(target_dir, exist_ok=True)
    os.environ["AUTOPWN_SCAN_SOURCE"] = "telegram"
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
    os.environ.pop("AUTOPWN_SCAN_SOURCE", None)
    return confirmed


def process_queue(chat_id, base_dir):
    """Run queued jobs one after another (single worker per chat)."""
    sess = get_session(chat_id)

    while sess["queue"]:
        job = sess["queue"].pop(0)
        sess["scanning"] = True
        sess["current_ip"] = job["ip"]
        sess["current_mode"] = job.get("mode_label")
        sess["state"] = "scanning"

        remaining = len(sess["queue"])
        extra = f"\nبعده: {remaining} في الانتظار" if remaining else ""
        send_to_chat(
            chat_id,
            f"▶ بدء المسح التالي\nالهدف: {job['ip']}\nالنوع: {job.get('mode_label')}{extra}",
        )

        try:
            run_scan_job(chat_id, job, base_dir)
        except Exception as exc:
            send_to_chat(chat_id, f"❌ خطأ أثناء مسح {job['ip']}: {exc}")
        finally:
            os.environ.pop("AUTOPWN_SCAN_SOURCE", None)

    sess["scanning"] = False
    sess["current_ip"] = None
    sess["current_mode"] = None
    sess["state"] = "idle"
    sess["ip"] = None
    sess["pending_ip"] = None

    force_idle(sess)
    if not sess["queue"]:
        send_to_chat(chat_id, "✓ جميع المسوحات في قائمة الانتظار اكتملت.")


def start_scan(chat_id, job, base_dir):
    """Start scan worker: current job first, then queue."""
    sess = get_session(chat_id)
    lock = chat_lock()

    with lock:
        if sess.get("scanning"):
            sess["queue"].append(job)
            pos = len(sess["queue"])
            send_to_chat(
                chat_id,
                f"⏳ مسح جاري على {sess.get('current_ip')}\n"
                f"✓ أُضيف {job['ip']} للانتظار (الموقع {pos})\n"
                f"النوع: {job.get('mode_label')}",
            )
            return

        def worker():
            with lock:
                sess["scanning"] = True
                sess["current_ip"] = job["ip"]
                sess["current_mode"] = job.get("mode_label")
                sess["state"] = "scanning"

            from core.live_scan_log import path as live_log_path

            send_to_chat(
                chat_id,
                f"▶ بدء المسح\nالهدف: {job['ip']}\n"
                f"النوع: {job.get('mode_label')}\n"
                f"الملف الشخصي: {job['profile']}\n\n"
                f"سيصلك التقرير عند الانتهاء.\n\n"
                f"📺 عند بدء المسح تُفتح نافذة Live Scan تلقائياً\n"
                f"📂 أو: tail -f {live_log_path()}",
            )

            try:
                run_scan_job(chat_id, job, base_dir)
            except Exception as exc:
                send_to_chat(chat_id, f"❌ خطأ أثناء المسح: {exc}")
            finally:
                os.environ.pop("AUTOPWN_SCAN_SOURCE", None)

            try:
                process_queue(chat_id, base_dir)
            except Exception as exc:
                send_to_chat(chat_id, f"❌ خطأ في قائمة الانتظار: {exc}")
                force_idle(get_session(chat_id))

        threading.Thread(target=worker, daemon=True).start()


def enqueue_or_prompt(chat_id, target, base_dir):
    """New IP while busy → queue after mode pick, or show mode keyboard."""
    sess = get_session(chat_id)

    if sess.get("scanning") or sess.get("queue"):
        if len(sess.get("queue", [])) >= MAX_QUEUE_SIZE:
            send_to_chat(
                chat_id,
                f"⚠ قائمة الانتظار ممتلئة ({MAX_QUEUE_SIZE}).\n"
                f"الجاري: {sess.get('current_ip')}\n"
                f"استخدم /status أو انتظر.",
            )
            return

        sess["pending_ip"] = target
        sess["state"] = "choose_mode_queued"
        send_to_chat(
            chat_id,
            f"⏳ مسح جاري على: {sess.get('current_ip') or '?'}\n"
            f"في الانتظار: {len(sess.get('queue', []))} IP\n\n"
            f"{target_prompt_text(target)}\n"
            f"(يُضاف للانتظار تلقائياً):",
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
    send_to_chat(chat_id, target_prompt_text(target), reply_markup=mode_keyboard())
