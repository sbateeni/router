#!/usr/bin/env bash
# يشغّل: (1) بوت تيليجرام في الخلفية  (2) قائمة المسح في هذه الطرفية
# أمر واحد من جذر المشروع:  bash start.sh   أو   bash run.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"

if [[ -x "$ROOT/.venv/bin/python" ]]; then
  PY="$ROOT/.venv/bin/python"
else
  PY="python3"
fi

LIVE_LOG="$ROOT/logs/LIVE_SCAN.log"
mkdir -p "$ROOT/logs"
touch "$LIVE_LOG"

_stop_live_tail() {
  if [[ -f "$ROOT/logs/live_tail.pid" ]]; then
    kill "$(cat "$ROOT/logs/live_tail.pid")" 2>/dev/null || true
    rm -f "$ROOT/logs/live_tail.pid"
  fi
}

_start_live_tail() {
  [[ "${AUTOPWN_LIVE_VIEW:-1}" == "1" ]] || return 0
  _stop_live_tail
  (
    tail -n 0 -f "$LIVE_LOG" 2>/dev/null | while IFS= read -r line; do
      printf '\033[36m[SCAN]\033[0m %s\n' "$line"
    done
  ) &
  echo $! >"$ROOT/logs/live_tail.pid"
}

# Telegram bot in background (one process for all menu options)
if [[ -z "${AUTOPWN_SKIP_TELEGRAM:-}" ]] && [[ -x "$ROOT/scripts/telegram_service.sh" ]]; then
  bash "$ROOT/scripts/telegram_service.sh" start || true
  export NUCLEI_TELEGRAM_EXTERNAL=1
fi

# tmux: pane علوي = مخرجات المسح الحية، سفلي = القائمة
if [[ -z "${AUTOPWN_NO_TMUX:-}" ]] && command -v tmux &>/dev/null && [[ -z "${TMUX:-}" ]]; then
  echo "[*] فتح tmux: أعلى = مسح تيليجرام/CLI حي | أسفل = القائمة"
  sleep 1
  exec tmux new-session -s autopwn \
    "tail -f '$LIVE_LOG' | sed -u 's/^/[SCAN] /'" \; \
    split-window -v -t autopwn \
    "export AUTOPWN_SKIP_TELEGRAM=1 AUTOPWN_NO_TMUX=1 AUTOPWN_LIVE_VIEW=0; cd '$ROOT'; exec bash '$ROOT/run.sh'"
fi

_start_live_tail
trap '_stop_live_tail' EXIT

TG_ARGS=()
if [[ "${NUCLEI_TELEGRAM_EXTERNAL:-}" == "1" ]]; then
  TG_ARGS=(--no-telegram)
fi

echo "======================================================"
echo "   AUTO-PWN UNIFIED — router + nuclei-dev engine"
echo "======================================================"
echo
echo "  [1] Full auto scan (--auto)     bin/master_pwn.py"
echo "  [2] Device engine only          bin/auto_pwn.py"
echo "  [3] Test router creds           tests/test_router_target.py"
echo "  [4] Test Hikvision              tests/test_hikvision_target.py"
echo "  [5] CVE intelligence report     tests/test_device_cve.py"
echo "  [6] Camera snapshots            tests/test.py"
echo "  [7] LAN scan                    bin/lan_pwn.py"
echo "  [8] Interactive menu            bin/master_pwn.py (CLI + Telegram already on)"
echo "  [9] Update from GitHub          project + tools + nuclei"
if [[ "${NUCLEI_TELEGRAM_EXTERNAL:-}" == "1" ]]; then
  echo
  echo "  [*] Telegram: @H_the_box_bot — المسح يظهر هنا كـ [SCAN]"
  echo "  [*] Live log: tail -f logs/LIVE_SCAN.log"
fi
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
    echo "[*] Checking GitHub for updates (repo + tools/ + nuclei templates)..."
    "$PY" "$ROOT/scripts/update_tools.py"
    ;;
  0)
    echo "Bye."
    exit 0
    ;;
  *)
    echo "Invalid option."
    exit 1
    ;;
esac
