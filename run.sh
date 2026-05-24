#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if [[ -x "$ROOT/.venv/bin/python" ]]; then
  PY="$ROOT/.venv/bin/python"
else
  PY="python3"
fi

echo "======================================================"
echo "   AUTO-PWN UNIFIED — router + nuclei-dev engine"
echo "======================================================"
echo
echo "[*] Syncing tools..."
"$PY" "$ROOT/scripts/update_tools.py" 2>/dev/null || true
export NUCLEI_SKIP_UPDATE=1
echo
echo "  [1] Full auto scan (--auto)     bin/master_pwn.py"
echo "  [2] Device engine only          bin/auto_pwn.py"
echo "  [3] Test router creds           tests/test_router_target.py"
echo "  [4] Test Hikvision              tests/test_hikvision_target.py"
echo "  [5] CVE intelligence report     tests/test_device_cve.py"
echo "  [6] Camera snapshots            tests/test.py"
echo "  [7] LAN scan                    bin/lan_pwn.py"
echo "  [8] Interactive menu            bin/master_pwn.py (no args)"
echo
read -rp "Select option [1-8]: " choice

case "$choice" in
  1)
    read -rp "Target IP: " target_ip
    "$PY" "$ROOT/bin/master_pwn.py" -t "$target_ip" --auto
    ;;
  2)
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
    "$PY" "$ROOT/bin/lan_pwn.py"
    ;;
  8)
    "$PY" "$ROOT/bin/master_pwn.py"
    ;;
  *)
    echo "Invalid option."
    exit 1
    ;;
esac
