#!/usr/bin/env bash
# أمر واحد: بوت تيليجرام (خلفية) + قائمة Kali (أمامية)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if [[ -x "$ROOT/.venv/bin/python" ]]; then
  PY="$ROOT/.venv/bin/python"
else
  PY="python3"
fi

if [[ ! -f "$ROOT/.env" ]]; then
  echo "[!] لا يوجد .env — انسخه من Windows: scp .env kali:~/router/.env"
  exit 1
fi

if [[ -f "$ROOT/scripts/check_telegram_env.py" ]]; then
  "$PY" "$ROOT/scripts/check_telegram_env.py" || exit 1
fi

echo "======================================================"
echo "  تشغيل مزدوج: Telegram + قائمة Kali"
echo "  • تيليجرام: @H_the_box_bot (خلفية)"
echo "  • الطرفية: القائمة أدناه — مسح من هنا أو من التيليجرام"
echo "  • مسح تيليجرام → يظهر في هذه الطرفية [SCAN] (أو tmux split)"
echo "  • ملف حي: tail -f logs/LIVE_SCAN.log"
echo "======================================================"
echo

exec bash "$ROOT/run.sh"
