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

install_pip_req() {
  local label="$1"
  local req="$2"
  if [[ ! -f "$req" ]]; then
    return 0
  fi
  echo "  [*] $label"
  if ! "$PY" -m pip install -q -r "$req"; then
    echo "  [!] Warning: pip install failed for $label (continuing)"
    return 1
  fi
  return 0
}

install_pip_path() {
  local label="$1"
  local path="$2"
  if [[ ! -d "$path" ]]; then
    return 0
  fi
  if [[ ! -f "$path/pyproject.toml" && ! -f "$path/setup.py" ]]; then
    return 0
  fi
  echo "  [*] $label (editable install from clone)"
  if ! "$PY" -m pip install -q "$path"; then
    echo "  [!] Warning: pip install failed for $label (continuing)"
    return 1
  fi
  return 0
}

install_python_deps() {
  ensure_project_venv
  echo
  echo "[*] Installing Python dependencies into .venv..."
  "$PY" -m pip install -q -U pip setuptools wheel

  local failed=0

  # Master list — covers project + Dirsearch + RouterSploit + Ingram + OSINT + recon tools
  install_pip_req "requirements.txt" "$ROOT/requirements.txt" || failed=1

  # Tool-specific pins / extras (after clone)
  for req in \
    "$ROOT/tools/routersploit/requirements.txt" \
    "$ROOT/tools/ingram/requirements.txt" \
    "$ROOT/tools/dirsearch/requirements.txt" \
    "$ROOT/tools/spiderfoot/requirements.txt"; do
    install_pip_req "$req" "$req" || failed=1
  done

  # theHarvester moved to pyproject.toml (no requirements/base.txt on main)
  install_pip_path "theHarvester" "$ROOT/tools/theHarvester" || failed=1

  # NetExec — heavy AD tooling; may upgrade paramiko (RouterSploit needs 2.12)
  install_pip_path "NetExec (nxc)" "$ROOT/tools/netexec" || failed=1

  # RouterSploit requires paramiko 2.x (DSSKey); restore after NetExec if needed
  "$PY" -m pip install -q "paramiko==2.12.0" || failed=1

  if [[ "$failed" -eq 1 ]]; then
    echo "[!] Some optional tool dependencies failed — core framework should still run."
    echo "    Retry: source .venv/bin/activate && pip install -r requirements.txt"
  else
    echo "[+] Python dependencies installed into .venv"
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

echo "[1/10] RouterSploit..."
sync_tool routersploit https://github.com/threat9/routersploit.git

echo "[2/10] Ingram..."
sync_tool ingram https://github.com/jorhelp/Ingram.git

echo "[3/10] DefaultCreds..."
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
echo "  chmod +x run.sh && ./run.sh"
echo
