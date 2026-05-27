#!/usr/bin/env bash
# Fix RouterSploit deps in project .venv (setuptools/pkg_resources + paramiko 2.12 + pycryptodome)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -x "$ROOT/.venv/bin/python" ]]; then
  echo "[!] No .venv — run: bash scripts/install_tools.sh"
  exit 1
fi

PY="$ROOT/.venv/bin/python"
echo "[*] Fixing RouterSploit in .venv..."

"$PY" -m pip install -q -U pip setuptools wheel

if [[ -f "$ROOT/tools/routersploit/requirements.txt" ]]; then
  echo "[1/3] RouterSploit requirements.txt..."
  "$PY" -m pip install -q -r "$ROOT/tools/routersploit/requirements.txt"
fi

echo "[2/3] Pin paramiko 2.12 + pycryptodome..."
if [[ -f "$ROOT/constraints-kali.txt" ]]; then
  "$PY" -m pip install -q -c "$ROOT/constraints-kali.txt" paramiko pycryptodome pysnmp requests
else
  "$PY" -m pip install -q "paramiko==2.12.0" pycryptodome pysnmp "requests==2.32.2"
fi

echo "[3/3] Verify pkg_resources + paramiko + rsf import..."
"$PY" -c "
import pkg_resources
from Crypto.Cipher import AES
import paramiko
assert hasattr(paramiko, 'DSSKey'), 'paramiko too new — need 2.12.0'
print('  [+] setuptools/pkg_resources OK')
print('  [+] paramiko + pycryptodome OK')
"

if [[ -f "$ROOT/tools/routersploit/rsf.py" ]]; then
  (cd "$ROOT/tools/routersploit" && "$PY" -c "
import sys
sys.path.insert(0, '.')
from routersploit.interpreter import RoutersploitInterpreter  # noqa: F401
print('  [+] RouterSploit rsf import OK')
")
fi

echo
echo "[+] Done. Test: $PY $ROOT/tools/routersploit/rsf.py -h"
