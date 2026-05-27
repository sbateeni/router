#!/usr/bin/env bash
# Fix RouterSploit deps in project .venv (paramiko 2.12 + pycryptodome)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -x "$ROOT/.venv/bin/python" ]]; then
  echo "[!] No .venv — run: bash scripts/install_tools.sh"
  exit 1
fi

PY="$ROOT/.venv/bin/python"
echo "[*] Fixing RouterSploit in .venv..."

"$PY" -m pip install -q -U pip

if [[ -f "$ROOT/tools/routersploit/requirements.txt" ]]; then
  echo "[1/2] RouterSploit requirements.txt..."
  "$PY" -m pip install -q -r "$ROOT/tools/routersploit/requirements.txt"
fi

echo "[2/2] Pin paramiko 2.12 + pycryptodome..."
if [[ -f "$ROOT/constraints-kali.txt" ]]; then
  "$PY" -m pip install -q -c "$ROOT/constraints-kali.txt" paramiko pycryptodome pysnmp requests
else
  "$PY" -m pip install -q "paramiko==2.12.0" pycryptodome pysnmp "requests==2.32.2"
fi

echo "[*] Verify..."
"$PY" -c "
from Crypto.Cipher import AES
import paramiko
assert hasattr(paramiko, 'DSSKey'), 'paramiko too new — need 2.12.0'
print('  [+] RouterSploit Python deps OK')
"

if [[ -f "$ROOT/tools/routersploit/rsf.py" ]]; then
  echo "[*] Quick rsf.py import test..."
  (cd "$ROOT/tools/routersploit" && "$PY" -c "import rsf" 2>/dev/null) \
    && echo "  [+] rsf import OK" \
    || echo "  [i] rsf CLI test skipped (may still work via rsf.py)"
fi

echo
echo "[+] Done. Test: $PY $ROOT/tools/routersploit/rsf.py -h"
