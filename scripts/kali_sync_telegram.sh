#!/usr/bin/env bash
# Kali: resolve git conflicts, pull latest, verify .env, start Telegram bot.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -x "$ROOT/.venv/bin/python" ]]; then
  PY="$ROOT/.venv/bin/python"
else
  echo "[!] No .venv — run: python3 -m venv .venv && .venv/bin/pip install -r requirements-kali.txt"
  exit 1
fi

echo "=== 1) Git: drop local edits on telegram files, then pull ==="
git checkout -- bin/telegram_daemon.py scripts/telegram_service.sh 2>/dev/null || true
git pull

echo
echo "=== 2) Permissions ==="
chmod +x run.sh scripts/telegram_service.sh scripts/check_telegram_env.py bin/telegram_daemon.py 2>/dev/null || true

echo
echo "=== 3) .env file ==="
if [[ ! -f "$ROOT/.env" ]]; then
  echo "[!] Missing $ROOT/.env"
  echo "    nano .env   # paste TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID"
  exit 1
fi
echo "[+] .env found ($(wc -l <"$ROOT/.env") lines)"
grep -q '^TELEGRAM_BOT_TOKEN=' "$ROOT/.env" && echo "[+] TELEGRAM_BOT_TOKEN line OK" || echo "[!] No TELEGRAM_BOT_TOKEN= in .env"
grep -q '^TELEGRAM_CHAT_ID=' "$ROOT/.env" && echo "[+] TELEGRAM_CHAT_ID line OK" || echo "[!] No TELEGRAM_CHAT_ID= in .env"

echo
echo "=== 4) Python env check (uses .venv, not system python3) ==="
"$PY" "$ROOT/scripts/check_telegram_env.py"

echo
echo "=== 5) Start Telegram daemon ==="
bash "$ROOT/scripts/telegram_service.sh" stop || true
bash "$ROOT/scripts/telegram_service.sh" start
bash "$ROOT/scripts/telegram_service.sh" status

echo
echo "=== Done. In Telegram send /start to @H_the_box_bot ==="
echo "    tail -f $ROOT/logs/telegram.log"
