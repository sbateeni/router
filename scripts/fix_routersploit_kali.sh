#!/usr/bin/env bash
# Fix RouterSploit deps in project .venv (paramiko 2.12 + pycryptodome + wordlists patch)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -x "$ROOT/.venv/bin/python" ]]; then
  echo "[!] No .venv — run: bash scripts/install_tools.sh"
  exit 1
fi

PY="$ROOT/.venv/bin/python"
echo "[*] Fixing RouterSploit in .venv..."

"$PY" -m pip install -q -U pip wheel

echo "[0/4] Patch wordlists (setuptools 82+ removed pkg_resources)..."
"$PY" "$ROOT/scripts/patch_routersploit_wordlists.py"

echo "[1/4] setuptools<81 (pkg_resources) — optional fallback..."
"$PY" -m pip install -q "setuptools>=65,<81" || true

if [[ -f "$ROOT/tools/routersploit/requirements.txt" ]]; then
  echo "[2/4] RouterSploit requirements.txt..."
  "$PY" -m pip install -q -r "$ROOT/tools/routersploit/requirements.txt"
fi

echo "[3/4] Pin paramiko 2.12 + pycryptodome..."
if [[ -f "$ROOT/constraints-kali.txt" ]]; then
  "$PY" -m pip install -q -c "$ROOT/constraints-kali.txt" paramiko pycryptodome pysnmp requests
else
  "$PY" -m pip install -q "paramiko==2.12.0" pycryptodome pysnmp "requests==2.32.2"
fi

echo "[4/4] Verify paramiko + rsf import..."
"$PY" -c "
from Crypto.Cipher import AES
import paramiko
assert hasattr(paramiko, 'DSSKey'), 'paramiko too new — need 2.12.0'
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
