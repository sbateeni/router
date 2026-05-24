#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ensure_project_venv() {
  if [[ ! -x "$ROOT/.venv/bin/python" ]]; then
    echo "[*] Creating project virtualenv at .venv (Kali blocks system pip — PEP 668)..."
    if ! python3 -m venv "$ROOT/.venv"; then
      echo "[!] Failed to create venv. Install: sudo apt install python3-venv"
      exit 1
    fi
  fi
  PY="$ROOT/.venv/bin/python"
  echo "[*] Using Python: $PY"
}

install_python_deps() {
  ensure_project_venv
  echo
  echo "[*] Installing Python dependencies into .venv..."
  "$PY" -m pip install -q -U pip setuptools wheel

  local req failed=0
  for req in \
    "$ROOT/requirements.txt" \
    tools/routersploit/requirements.txt \
    tools/ingram/requirements.txt \
    tools/netexec/requirements.txt \
    tools/spiderfoot/requirements.txt \
    tools/theHarvester/requirements/base.txt; do
    if [[ -f "$req" ]]; then
      echo "  [*] $req"
      if ! "$PY" -m pip install -q -r "$req"; then
        echo "  [!] Warning: pip install failed for $req (continuing)"
        failed=1
      fi
    fi
  done

  if [[ "$failed" -eq 1 ]]; then
    echo "[!] Some optional tool dependencies failed — clones are still usable."
  fi
}

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

echo "[4/10] Dirsearch..."
sync_tool dirsearch https://github.com/maurosoria/dirsearch.git 1

echo "[5/10] Sqlmap..."
sync_tool sqlmap https://github.com/sqlmapproject/sqlmap.git 1

echo "[6/10] NetExec..."
sync_tool netexec https://github.com/Pennyw0rth/NetExec.git 1

echo "[7/10] Nikto..."
sync_tool nikto https://github.com/sullo/nikto.git 1

echo "[8/10] SpiderFoot..."
sync_tool spiderfoot https://github.com/smicallef/spiderfoot.git 1

echo "[9/10] theHarvester..."
sync_tool theHarvester https://github.com/laramies/theHarvester.git 1

echo "[10/10] Amass..."
sync_tool amass https://github.com/owasp-amass/amass.git 1

cd "$ROOT"
install_python_deps

echo
echo "======================================================"
echo "       ALL TOOLS DOWNLOADED SUCCESSFULLY!"
echo "======================================================"
echo "Tools installed in: $ROOT/tools/"
echo "Python venv:        $ROOT/.venv/"
echo
echo "Activate before running:"
echo "  source .venv/bin/activate"
echo "  ./run.sh"
