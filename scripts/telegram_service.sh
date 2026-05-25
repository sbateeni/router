#!/usr/bin/env bash
# Start / stop / status for Telegram bot (used by run.sh)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"

if [[ -x "$ROOT/.venv/bin/python" ]]; then
  PY="$ROOT/.venv/bin/python"
else
  PY="python3"
fi

LOG="$ROOT/logs/telegram.log"
PIDFILE="$ROOT/logs/telegram_bot.pid"
MATCH="telegram_daemon.py"

_is_running() {
  pgrep -f "$MATCH" >/dev/null 2>&1
}

cmd="${1:-status}"

case "$cmd" in
  start)
    mkdir -p "$ROOT/logs"
    if _is_running; then
      echo "[+] Telegram bot already running"
      exit 0
    fi
    if [[ ! -f "$ROOT/.env" ]]; then
      echo "[!] No .env at $ROOT/.env (not in git — copy from your PC):"
      echo "    scp .env kali:~/router/.env"
      echo "    or: cp .env.example .env && nano .env"
      exit 1
    fi
    if [[ ! -f "$ROOT/scripts/check_telegram_env.py" ]]; then
      echo "[!] Old repo — run: git checkout -- bin/telegram_daemon.py scripts/telegram_service.sh && git pull"
      echo "    Or: bash scripts/kali_sync_telegram.sh"
      exit 1
    fi
    if ! "$PY" "$ROOT/scripts/check_telegram_env.py"; then
      exit 1
    fi
    nohup "$PY" "$ROOT/bin/telegram_daemon.py" >>"$LOG" 2>&1 &
    echo $! >"$PIDFILE"
    sleep 2
    if _is_running; then
      echo "[+] Telegram bot started (background)"
      echo "    Chat: @H_the_box_bot — send IP or /start"
      echo "    Log:  $LOG"
    else
      echo "[!] Telegram did not start — see $LOG"
      tail -15 "$LOG" 2>/dev/null || true
      "$PY" "$ROOT/scripts/check_telegram_env.py" || true
      exit 1
    fi
    ;;
  stop)
    if _is_running; then
      pkill -f "$MATCH" || true
      sleep 1
    fi
    # old entry point before telegram_daemon.py
    pkill -f "master_pwn.py --telegram" 2>/dev/null || true
    rm -f "$PIDFILE"
    echo "[+] Telegram bot stopped"
    ;;
  status)
    if _is_running; then
      echo "[+] Telegram bot: running"
      pgrep -af "$MATCH" || true
    else
      echo "[-] Telegram bot: not running"
    fi
    ;;
  *)
    echo "Usage: $0 {start|stop|status}"
    exit 1
    ;;
esac
