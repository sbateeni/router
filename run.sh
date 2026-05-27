#!/usr/bin/env bash
# AUTO-PWN — تشغيل واحد فقط:  bash run.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"

# ── إذا كنت داخل tmux مقسوم (المشكلة في الصورة) ──
if [[ -n "${TMUX:-}" ]]; then
  echo "[!] tmux مفعّل — هذا يسبب الشاشة المقسومة و [SCAN]."
  echo "[*] جاري إغلاق جلسة tmux..."
  tmux kill-session 2>/dev/null || true
  echo "[*] افتح طرفية جديدة (ليست tmux) ثم:"
  echo "    cd ~/router && bash run.sh"
  exit 0
fi

# تنظيف بقايا قديمة
pkill -f "tail.*LIVE_SCAN\.log" 2>/dev/null || true
for _s in autopwn autopwn-live; do
  tmux kill-session -t "$_s" 2>/dev/null || true
done

if [[ -x "$ROOT/.venv/bin/python" ]]; then
  PY="$ROOT/.venv/bin/python"
else
  PY="python3"
fi

if [[ ! -f "$ROOT/.env" ]]; then
  echo "[!] أنشئ .env:  cp .env.example .env && nano .env"
  exit 1
fi

mkdir -p "$ROOT/logs"

# Live log + per-phase terminal windows (Kali desktop)
if [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
  export AUTOPWN_LIVE_WINDOW="${AUTOPWN_LIVE_WINDOW:-1}"
  export AUTOPWN_PHASE_WINDOWS="${AUTOPWN_PHASE_WINDOWS:-main}"
fi

if [[ -f "$ROOT/scripts/check_telegram_env.py" ]]; then
  "$PY" "$ROOT/scripts/check_telegram_env.py" || exit 1
fi

TG_OK=0
if pgrep -f "telegram_daemon.py" >/dev/null 2>&1; then
  TG_OK=1
else
  nohup "$PY" "$ROOT/bin/telegram_daemon.py" >>"$ROOT/logs/telegram.log" 2>&1 &
  sleep 2
  pgrep -f "telegram_daemon.py" >/dev/null 2>&1 && TG_OK=1
fi

export NUCLEI_TELEGRAM_EXTERNAL=1
TG_ARGS=(--no-telegram)

echo
echo "======================================================"
echo "   AUTO-PWN UNIFIED"
echo "======================================================"
[[ "$TG_OK" == "1" ]] && echo "  Telegram: ON (@H_the_box_bot)" || echo "  Telegram: OFF — logs/telegram.log"
echo
echo "  [1] Full auto scan     [2] Device engine"
echo "  [3] Router test        [4] Hikvision test"
echo "  [5] CVE report         [6] Camera snapshots"
echo "  [7] LAN scan           [8] Interactive menu"
echo "  [9] Update GitHub      [G] PyQt6 GUI"
echo "  [0] Exit"
echo
read -rp "Select [0-9,G]: " choice

case "$choice" in
  [gG]) export NUCLEI_SKIP_UPDATE=1 AUTOPWN_LIVE_WINDOW=0
     "$PY" "$ROOT/bin/gui_app.py" ;;
  1) read -rp "Target IP: " target_ip
     export NUCLEI_SKIP_UPDATE=1
     "$PY" "$ROOT/bin/master_pwn.py" "${TG_ARGS[@]}" -t "$target_ip" --auto ;;
  2) export NUCLEI_SKIP_UPDATE=1; "$PY" "$ROOT/bin/auto_pwn.py" ;;
  3) read -rp "Target IP: " target_ip; "$PY" "$ROOT/tests/test_router_target.py" -H "$target_ip" ;;
  4) read -rp "Target IP: " target_ip; "$PY" "$ROOT/tests/test_hikvision_target.py" -H "$target_ip" ;;
  5) read -rp "Target IP: " target_ip; "$PY" "$ROOT/tests/test_device_cve.py" -H "$target_ip" ;;
  6) read -rp "Camera IP (empty=default): " cam_ip
     [[ -n "$cam_ip" ]] && "$PY" "$ROOT/tests/test.py" -H "$cam_ip" || "$PY" "$ROOT/tests/test.py" ;;
  7) export NUCLEI_SKIP_UPDATE=1; "$PY" "$ROOT/bin/lan_pwn.py" ;;
  8) export NUCLEI_SKIP_UPDATE=1; "$PY" "$ROOT/bin/master_pwn.py" "${TG_ARGS[@]}" ;;
  9) "$PY" "$ROOT/scripts/update_tools.py" ;;
  0) exit 0 ;;
  *) echo "Invalid."; exit 1 ;;
esac
