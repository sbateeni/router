#!/usr/bin/env bash
# One-shot repair for Kali .venv after conflicting pip installs (NetExec, SpiderFoot lxml, etc.)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -x "$ROOT/.venv/bin/python" ]]; then
  echo "[!] No .venv — run: python3 -m venv .venv"
  exit 1
fi

PY="$ROOT/.venv/bin/python"

echo "[*] Removing NetExec/certipy from .venv (use system: sudo apt install netexec)..."
"$PY" -m pip uninstall -y netexec certipy-ad 2>/dev/null || true

echo "[*] Reinstalling Kali-pinned packages..."
"$PY" -m pip install -q -U pip setuptools wheel
"$PY" -m pip install -r "$ROOT/requirements-kali.txt"
"$PY" -m pip install -q -c "$ROOT/constraints-kali.txt" \
  paramiko beautifulsoup4 dnspython lxml requests

if [[ -d "$ROOT/tools/theHarvester" ]]; then
  echo "[*] theHarvester (--no-deps)..."
  "$PY" -m pip install -q --no-deps "$ROOT/tools/theHarvester" || true
fi

echo
echo "[*] Verify versions:"
"$PY" -m pip check 2>&1 | head -20 || true
"$PY" - <<'PY'
import paramiko, bs4, dns, lxml, requests
print("paramiko", paramiko.__version__)
print("beautifulsoup4", bs4.__version__)
print("dnspython", dns.__version__)
print("lxml", lxml.__version__)
print("requests", requests.__version__)
PY

if command -v nxc &>/dev/null; then
  echo "[+] System nxc: $(command -v nxc)"
else
  echo "[i] Install NetExec on Kali: sudo apt install -y netexec"
fi

echo "[+] Done. Run: source .venv/bin/activate && ./run.sh"
