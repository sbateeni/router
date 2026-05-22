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
"$PY" "$ROOT/update_tools.py" 2>/dev/null || true
export NUCLEI_SKIP_UPDATE=1
echo
echo "  [1] Full auto scan (--auto)     master_pwn.py"
echo "  [2] Device engine only          auto_pwn.py"
echo "  [3] Test router creds           test_router_target.py"
echo "  [4] Test Hikvision              test_hikvision_target.py"
echo "  [5] CVE intelligence report     test_device_cve.py"
echo "  [6] Camera snapshots            test.py"
echo "  [7] LAN scan                    lan_pwn.py"
echo "  [8] Interactive menu            master_pwn.py (no args)"
echo
read -rp "Select option [1-8]: " choice

case "$choice" in
  1)
    read -rp "Target IP: " target_ip
    "$PY" master_pwn.py -t "$target_ip" --auto
    ;;
  2)
    "$PY" auto_pwn.py
    ;;
  3)
    read -rp "Target IP: " target_ip
    "$PY" test_router_target.py -H "$target_ip"
    ;;
  4)
    read -rp "Target IP: " target_ip
    "$PY" test_hikvision_target.py -H "$target_ip"
    ;;
  5)
    read -rp "Target IP: " target_ip
    "$PY" test_device_cve.py -H "$target_ip"
    ;;
  6)
    read -rp "Camera IP (empty=default): " cam_ip
    if [[ -n "$cam_ip" ]]; then
      "$PY" test.py -H "$cam_ip"
    else
      "$PY" test.py
    fi
    ;;
  7)
    "$PY" lan_pwn.py
    ;;
  8)
    "$PY" master_pwn.py
    ;;
  *)
    echo "Invalid option."
    exit 1
    ;;
esac
