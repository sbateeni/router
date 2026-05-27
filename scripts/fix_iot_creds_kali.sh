#!/usr/bin/env bash
# Fix changeme + Default-Hunter in project .venv (Kali)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -x "$ROOT/.venv/bin/python" ]]; then
  echo "[!] No .venv — run: bash scripts/install_tools.sh"
  exit 1
fi

PY="$ROOT/.venv/bin/python"
echo "[*] Fixing IoT credential scanners in .venv..."

"$PY" -m pip install -q -U pip

echo "[1/3] changeme deps (cerberus, pymysql, …)..."
"$PY" -m pip install -q \
  "cerberus>=1.3.0" "PyYAML>=6.0" "pymysql>=1.0.0" \
  "psycopg2-binary>=2.9.0" "shodan>=1.0.0" "python-nmap>=0.7.0"

if [[ -d "$ROOT/tools/changeme" ]] && [[ -f "$ROOT/tools/changeme/requirements.txt" ]]; then
  "$PY" -m pip install -q -r "$ROOT/tools/changeme/requirements.txt" || true
fi

echo "[2/3] Default-Hunter (editable)..."
if [[ -d "$ROOT/tools/default-hunter" ]]; then
  "$PY" -m pip install -q -e "$ROOT/tools/default-hunter"
else
  echo "  [!] Clone missing — run: bash scripts/install_tools.sh"
fi

echo "[3/3] Verify..."
"$PY" -c "import cerberus; print('  [+] cerberus OK')"
"$PY" -c "import default_hunter; print('  [+] default_hunter OK')" \
  || echo "  [!] default_hunter still missing"

echo
echo "[+] Done. Re-run scan or: bash run.sh"
