import os
import re
import requests

from core.utils import looks_like_placeholder, valid_env_value

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
                    if key == "TELEGRAM_CHAT_ID":
                        value = normalize_chat_id(value)
                    os.environ[key] = value
        return True
    except OSError:
        return False


def telegram_configured():
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
    return valid_env_value(token) and valid_env_value(chat_id)


def telegram_placeholder_keys_present():
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
    return (token and looks_like_placeholder(token)) or (chat_id and looks_like_placeholder(chat_id))


def _ssl_verify():
    """CA bundle for api.telegram.org (fixes Windows Python CERTIFICATE_VERIFY_FAILED)."""
    flag = os.environ.get("TELEGRAM_SSL_VERIFY", "1").strip().lower()
    if flag in ("0", "false", "no", "off"):
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass
        return False
    try:
        import certifi
        return certifi.where()
    except ImportError:
        return True


def _telegram_request(method, token, payload=None, files=None, timeout=30):
    url = TELEGRAM_API.format(token=token, method=method)
    response = requests.post(
        url,
        data=payload or {},
        files=files,
        timeout=timeout,
        verify=_ssl_verify(),
    )
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


def normalize_chat_id(chat_id):
    """Accept 6874845252 or 'ID: 6874845252' from .env."""
    if chat_id is None:
        return ""
    text = str(chat_id).strip().strip('"').strip("'")
    if re.match(r"(?i)^id:\s*", text):
        text = re.sub(r"(?i)^id:\s*", "", text, count=1).strip()
    return text


def _resolve_chat_id(chat_id=None):
    raw = chat_id or os.environ.get("TELEGRAM_CHAT_ID", "")
    return normalize_chat_id(raw)


def send_telegram_message(text, chat_id=None):
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    resolved_chat = _resolve_chat_id(chat_id)
    if not token or not resolved_chat:
        print("[!] Telegram is not configured. Create a .env file with TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID.")
        return False

    try:
        for chunk in _split_message(text):
            _telegram_request(
                "sendMessage",
                token,
                {"chat_id": resolved_chat, "text": chunk},
            )
        return True
    except Exception as exc:
        print(f"[!] Failed to send Telegram message: {exc}")
        return False


def send_telegram_document(file_path, caption="", chat_id=None):
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    resolved_chat = _resolve_chat_id(chat_id)
    if not token or not resolved_chat:
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
                {"chat_id": resolved_chat, "caption": caption[:1024]},
                files={"document": (os.path.basename(file_path), fh)},
            )
        return True
    except Exception as exc:
        print(f"[!] Failed to send Telegram document: {exc}")
        return False


def notify_scan_complete(ip, target_dir, report_path, exploited, profile="normal", ai_analysis=None, chat_id=None):
    if telegram_placeholder_keys_present():
        print("[!] Telegram skipped: .env still has placeholder bot token or chat id.")
        return False

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

    sent_message = send_telegram_message(summary, chat_id=chat_id)
    sent_file = send_telegram_document(
        report_path,
        caption=f"Scan report for {ip} ({profile})",
        chat_id=chat_id,
    )
    ai_path = os.path.join(target_dir, "AI_ANALYSIS.txt")
    if os.path.exists(ai_path):
        send_telegram_document(ai_path, caption=f"AI analysis for {ip}", chat_id=chat_id)

    profile_path = os.path.join(target_dir, "target_profile.json")
    if os.path.exists(profile_path):
        send_telegram_document(profile_path, caption=f"Target profile for {ip}", chat_id=chat_id)

    transcript_file = os.path.join(target_dir, "SCAN_TRANSCRIPT.txt")
    if os.path.exists(transcript_file):
        send_telegram_document(
            transcript_file,
            caption=f"Scan timeline for {ip} (chronological log)",
            chat_id=chat_id,
        )

    for extra_name in (
        "AI_SCAN_PLAN.json",
        "AI_HYDRA_COMMANDS.txt",
        "AI_ROUTERSPLOIT_PLAN.txt",
        "MSF_EXPLOIT_COMMANDS.txt",
    ):
        extra_path = os.path.join(target_dir, extra_name)
        if os.path.exists(extra_path):
            send_telegram_document(extra_path, caption=f"{extra_name} for {ip}", chat_id=chat_id)

    if sent_message or sent_file:
        print("[+] Telegram notification sent.")
        return True

    return False
