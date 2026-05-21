import os
import requests

TELEGRAM_API = "https://api.telegram.org/bot{token}/{method}"
MAX_MESSAGE_LEN = 3900


def load_dotenv(base_dir):
    env_path = os.path.join(base_dir, ".env")
    if not os.path.exists(env_path):
        return False
    try:
        with open(env_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
        return True
    except OSError:
        return False


def telegram_configured():
    return bool(os.environ.get("TELEGRAM_BOT_TOKEN") and os.environ.get("TELEGRAM_CHAT_ID"))


def _telegram_request(method, token, payload=None, files=None):
    url = TELEGRAM_API.format(token=token, method=method)
    response = requests.post(url, data=payload or {}, files=files, timeout=30)
    response.raise_for_status()
    return response.json()


def _split_message(text):
    chunks = []
    current = ""
    for line in text.splitlines():
        candidate = f"{current}\n{line}".strip()
        if len(candidate) <= MAX_MESSAGE_LEN:
            current = candidate
            continue
        if current:
            chunks.append(current)
        current = line[:MAX_MESSAGE_LEN]
    if current:
        chunks.append(current)
    return chunks or [text[:MAX_MESSAGE_LEN]]


def send_telegram_message(text):
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        print("[!] Telegram is not configured. Create a .env file with TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID.")
        return False

    try:
        for chunk in _split_message(text):
            _telegram_request(
                "sendMessage",
                token,
                {"chat_id": chat_id, "text": chunk},
            )
        return True
    except Exception as exc:
        print(f"[!] Failed to send Telegram message: {exc}")
        return False


def send_telegram_document(file_path, caption=""):
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        print("[!] Telegram is not configured. Create a .env file with TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID.")
        return False
    if not os.path.exists(file_path):
        print(f"[!] Telegram report file not found: {file_path}")
        return False

    try:
        with open(file_path, "rb") as fh:
            _telegram_request(
                "sendDocument",
                token,
                {"chat_id": chat_id, "caption": caption[:1024]},
                files={"document": (os.path.basename(file_path), fh)},
            )
        return True
    except Exception as exc:
        print(f"[!] Failed to send Telegram document: {exc}")
        return False


def notify_scan_complete(ip, target_dir, report_path, exploited, profile="normal", ai_analysis=None):
    status = "SUCCESS - likely exploit/findings" if exploited else "COMPLETED - no confirmed exploit"
    summary = (
        "Router Auto-Pwn scan finished\n"
        f"Target: {ip}\n"
        f"Profile: {profile}\n"
        f"Status: {status}\n"
        f"Folder: {target_dir}\n"
        f"Report: {report_path}"
    )
    if ai_analysis:
        summary += "\n\n=== AI Analysis ===\n"
        summary += ai_analysis[:3500]

    sent_message = send_telegram_message(summary)
    sent_file = send_telegram_document(
        report_path,
        caption=f"Scan report for {ip} ({profile})",
    )
    ai_path = os.path.join(target_dir, "AI_ANALYSIS.txt")
    if os.path.exists(ai_path):
        send_telegram_document(ai_path, caption=f"AI analysis for {ip}")

    for extra_name in (
        "AI_SCAN_PLAN.json",
        "AI_HYDRA_COMMANDS.txt",
        "AI_ROUTERSPLOIT_PLAN.txt",
    ):
        extra_path = os.path.join(target_dir, extra_name)
        if os.path.exists(extra_path):
            send_telegram_document(extra_path, caption=f"{extra_name} for {ip}")

    if sent_message or sent_file:
        print("[+] Telegram notification sent.")
        return True

    return False
