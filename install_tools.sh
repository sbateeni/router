#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

echo "======================================================"
echo "       DOWNLOADING EXTERNAL SECURITY TOOLS"
echo "======================================================"
echo

mkdir -p tools
cd tools

sync_tool() {
  local dir="$1"
  local url="$2"
  local depth="${3:-}"

  if [[ -d "$dir/.git" ]]; then
    echo "[*] Updating $dir..."
    git -C "$dir" pull --ff-only
    return
  fi

  if [[ -n "$depth" ]]; then
    git clone --depth 1 "$url" "$dir"
  else
    git clone "$url" "$dir"
  fi
  echo "[+] $dir downloaded!"
}

echo "[1/5] RouterSploit..."
sync_tool routersploit https://github.com/threat9/routersploit.git

echo "[2/5] Ingram..."
sync_tool ingram https://github.com/jorhelp/Ingram.git

echo "[3/5] DefaultCreds..."
sync_tool DefaultCreds-cheat-sheet https://github.com/ihebski/DefaultCreds-cheat-sheet.git

echo "[4/5] Dirsearch..."
sync_tool dirsearch https://github.com/maurosoria/dirsearch.git 1

echo "[5/5] Sqlmap..."
sync_tool sqlmap https://github.com/sqlmapproject/sqlmap.git 1

cd "$ROOT"
if [[ -x "$ROOT/.venv/bin/python" ]]; then
  PY="$ROOT/.venv/bin/python"
else
  PY="python3"
fi

echo
echo "[*] Installing Python dependencies for external tools..."
"$PY" -m pip install -q setuptools
for req in tools/routersploit/requirements.txt tools/ingram/requirements.txt; do
  if [[ -f "$req" ]]; then
    "$PY" -m pip install -q -r "$req"
  fi
done

echo
echo "======================================================"
echo "       ALL TOOLS DOWNLOADED SUCCESSFULLY!"
echo "======================================================"
echo "Tools installed in: $ROOT/tools/"
