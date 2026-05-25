#!/usr/bin/env bash
# AUTO-PWN — تشغيل واحد فقط:  bash run.sh
# • يبدأ تيليجرام تلقائياً (@H_the_box_bot)
# • القائمة محلياً | [9] للتحديث من GitHub
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"

if [[ -x "$ROOT/.venv/bin/python" ]]; then
  PY="$ROOT/.venv/bin/python"
else
  PY="python3"
fi

# إغلاق tmux قديم (من تجارب سابقة) حتى لا تبقى الطرفية مقسومة
tmux kill-session -t autopwn 2>/dev/null || true
tmux kill-session -t autopwn-live 2>/dev/null || true

if [[ ! -f "$ROOT/.env" ]]; then
  echo "[!] أنشئ .env:  cp .env.example .env && nano .env"
  exit 1
fi

# تيليجرام (خلفية)
mkdir -p "$ROOT/logs"
if [[ -f "$ROOT/scripts/check_telegram_env.py" ]]; then
  "$PY" "$ROOT/scripts/check_telegram_env.py" || exit 1
fi

TG_OK=0
if pgrep -f "telegram_daemon.py" >/dev/null 2>&1; then
  TG_OK=1
elif [[ -x "$ROOT/.venv/bin/python" ]] || command -v python3 &>/dev/null; then
  nohup "$PY" "$ROOT/bin/telegram_daemon.py" >>"$ROOT/logs/telegram.log" 2>&1 &
  sleep 2
  pgrep -f "telegram_daemon.py" >/dev/null 2>&1 && TG_OK=1
fi

export NUCLEI_TELEGRAM_EXTERNAL=1
TG_ARGS=(--no-telegram)

echo
echo "======================================================"
echo "   AUTO-PWN UNIFIED — router + nuclei-dev engine"
echo "======================================================"
if [[ "$TG_OK" == "1" ]]; then
  echo "  Telegram: ON  (@H_the_box_bot)"
else
  echo "  Telegram: OFF — راجع logs/telegram.log"
fi
echo
echo "  [1] Full auto scan (--auto)"
echo "  [2] Device engine only"
echo "  [3] Test router creds"
echo "  [4] Test Hikvision"
echo "  [5] CVE intelligence report"
echo "  [6] Camera snapshots"
echo "  [7] LAN scan"
echo "  [8] Interactive menu"
echo "  [9] Update from GitHub"
echo "  [0] Exit"
echo
read -rp "Select option [0-9]: " choice

case "$choice" in
  1)
    read -rp "Target IP: " target_ip
    export NUCLEI_SKIP_UPDATE=1
    "$PY" "$ROOT/bin/master_pwn.py" "${TG_ARGS[@]}" -t "$target_ip" --auto
    ;;
  2)
    export NUCLEI_SKIP_UPDATE=1
    "$PY" "$ROOT/bin/auto_pwn.py"
    ;;
  3)
    read -rp "Target IP: " target_ip
    "$PY" "$ROOT/tests/test_router_target.py" -H "$target_ip"
    ;;
  4)
    read -rp "Target IP: " target_ip
    "$PY" "$ROOT/tests/test_hikvision_target.py" -H "$target_ip"
    ;;
  5)
    read -rp "Target IP: " target_ip
    "$PY" "$ROOT/tests/test_device_cve.py" -H "$target_ip"
    ;;
  6)
    read -rp "Camera IP (empty=default): " cam_ip
    if [[ -n "$cam_ip" ]]; then
      "$PY" "$ROOT/tests/test.py" -H "$cam_ip"
    else
      "$PY" "$ROOT/tests/test.py"
    fi
    ;;
  7)
    export NUCLEI_SKIP_UPDATE=1
    "$PY" "$ROOT/bin/lan_pwn.py"
    ;;
  8)
    export NUCLEI_SKIP_UPDATE=1
    "$PY" "$ROOT/bin/master_pwn.py" "${TG_ARGS[@]}"
    ;;
  9)
    echo
    "$PY" "$ROOT/scripts/update_tools.py"
    ;;
  0)
    exit 0
    ;;
  *)
    echo "Invalid option."
    exit 1
    ;;
esac
