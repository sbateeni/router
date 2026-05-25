#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# AUTO-PWN — ملف تشغيل واحد (تيليجرام + قائمة Kali)
#
#   cd ~/router && bash run.sh
#
# يشغّل تلقائياً:
#   1) بوت @H_the_box_bot في الخلفية (يستقبل IP من تيليجرام)
#   2) هذه القائمة للمسح من الطرفية
#   3) أسطر [SCAN] عند مسح من تيليجرام (ملف logs/LIVE_SCAN.log)
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"

if [[ -x "$ROOT/.venv/bin/python" ]]; then
  PY="$ROOT/.venv/bin/python"
else
  PY="python3"
fi

# ── فحص .env (لا يُرفع مع git — يجب نسخه يدوياً إلى Kali) ──
if [[ ! -f "$ROOT/.env" ]]; then
  echo "[!] ملف .env غير موجود في: $ROOT/.env"
  echo "    من Windows:  scp .env kali:~/router/.env"
  echo "    أو انسخ من:  cp .env.example .env && nano .env"
  exit 1
fi

if [[ -f "$ROOT/scripts/check_telegram_env.py" ]]; then
  if ! "$PY" "$ROOT/scripts/check_telegram_env.py"; then
    echo "[!] أصلح .env ثم أعد: bash run.sh"
    exit 1
  fi
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

# ── 1) تيليجرام (عملية واحدة في الخلفية لكل المشروع) ──
if [[ -z "${AUTOPWN_SKIP_TELEGRAM:-}" ]] && [[ -x "$ROOT/scripts/telegram_service.sh" ]]; then
  if bash "$ROOT/scripts/telegram_service.sh" start; then
    export NUCLEI_TELEGRAM_EXTERNAL=1
  else
    echo "[!] البوت لم يبدأ — راجع: tail -20 logs/telegram.log"
    echo "    يمكنك متابعة القائمة المحلية بدون تيليجرام."
  fi
fi

# tmux اختياري: AUTOPWN_USE_TMUX=1 bash run.sh
if [[ "${AUTOPWN_USE_TMUX:-}" == "1" ]] && [[ -z "${AUTOPWN_NO_TMUX:-}" ]] \
    && command -v tmux &>/dev/null && [[ -z "${TMUX:-}" ]]; then
  echo "[*] tmux: أعلى = مسح حي | أسفل = القائمة"
  sleep 1
  exec tmux new-session -s autopwn \
    "tail -f '$LIVE_LOG' | sed -u 's/^/[SCAN] /'" \; \
    split-window -v -t autopwn \
    "export AUTOPWN_SKIP_TELEGRAM=1 AUTOPWN_NO_TMUX=1 AUTOPWN_LIVE_VIEW=0; cd '$ROOT'; exec bash '$ROOT/run.sh'"
fi

_start_live_tail
trap '_stop_live_tail' EXIT

echo
echo "  [*] مخرجات المسح (تيليجرام أو [1]): أسطر [SCAN] أدناه — لا تغلق هذه النافذة"
echo "  [*] ملف حي: tail -f logs/LIVE_SCAN.log"
echo

TG_ARGS=()
if [[ "${NUCLEI_TELEGRAM_EXTERNAL:-}" == "1" ]]; then
  TG_ARGS=(--no-telegram)
fi

# ── 2) القائمة المحلية ──
echo
echo "======================================================"
echo "   AUTO-PWN — تيليجرام + Kali (ملف واحد: run.sh)"
echo "======================================================"
if [[ "${NUCLEI_TELEGRAM_EXTERNAL:-}" == "1" ]]; then
  echo "  Telegram: ON  → @H_the_box_bot"
  echo "  مسح من التيليجرام يظهر هنا: [SCAN] ..."
else
  echo "  Telegram: OFF → bash scripts/telegram_service.sh start"
fi
echo
echo "  [1] Full auto scan (--auto)"
echo "  [2] Device engine only"
echo "  [3] Test router creds"
echo "  [4] Test Hikvision"
echo "  [5] CVE intelligence report"
echo "  [6] Camera snapshots"
echo "  [7] LAN scan"
echo "  [8] Interactive menu (master_pwn)"
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
    echo "[*] Checking GitHub for updates..."
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
