#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

is_kali() {
  [[ -f /etc/os-release ]] && grep -qiE 'kali|debian' /etc/os-release
}

install_kali_apt_deps() {
  if ! is_kali; then
    return 0
  fi
  echo "[*] Kali: optional system packages (lxml wheels, NetExec, venv)..."
  if command -v sudo &>/dev/null; then
    sudo apt-get update -qq
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
      python3-venv python3-lxml libxml2-dev libxslt1-dev \
      2>/dev/null || true
    if ! command -v nxc &>/dev/null; then
      echo "  [i] NetExec not found — install with: sudo apt install -y netexec"
    else
      echo "  [+] nxc on system: $(command -v nxc)"
    fi
  else
    echo "  [i] Run as root/sudo: apt install python3-venv python3-lxml libxml2-dev libxslt1-dev netexec"
  fi
}

ensure_project_venv() {
  if [[ ! -x "$ROOT/.venv/bin/python" ]]; then
    echo "[*] Creating project virtualenv at .venv (PEP 668)..."
    if ! python3 -m venv "$ROOT/.venv"; then
      echo "[!] Failed. Install: sudo apt install python3-venv"
      exit 1
    fi
  fi
  PY="$ROOT/.venv/bin/python"
  echo "[*] Using Python: $PY ($("$PY" --version))"
}

install_python_deps() {
  ensure_project_venv
  install_kali_apt_deps

  echo
  echo "[*] Installing Python dependencies into .venv..."

  # Remove packages that break RouterSploit / theHarvester pins
  "$PY" -m pip uninstall -y netexec certipy-ad 2>/dev/null || true

  "$PY" -m pip install -q -U pip setuptools wheel

  local req="$ROOT/requirements.txt"
  if is_kali && [[ -f "$ROOT/requirements-kali.txt" ]]; then
    req="$ROOT/requirements-kali.txt"
    echo "  [*] Kali detected — using requirements-kali.txt (upstream pins)"
  fi

  local failed=0
  if ! "$PY" -m pip install -q -r "$req"; then
    echo "  [!] pip install -r $(basename "$req") failed"
    failed=1
  fi

  # theHarvester: CLI only; deps already in requirements-kali.txt
  if [[ -d "$ROOT/tools/theHarvester" ]] && [[ -f "$ROOT/tools/theHarvester/pyproject.toml" ]]; then
    echo "  [*] theHarvester (--no-deps)"
    "$PY" -m pip install -q --no-deps "$ROOT/tools/theHarvester" || failed=1
  fi

  # Enforce pins (RouterSploit paramiko 2.12 + theHarvester bs4/dnspython/lxml)
  if [[ -f "$ROOT/constraints-kali.txt" ]]; then
    echo "  [*] Applying constraints-kali.txt"
    "$PY" -m pip install -q -c "$ROOT/constraints-kali.txt" \
      paramiko beautifulsoup4 dnspython lxml requests || failed=1
  fi

  echo
  if command -v nxc &>/dev/null || command -v netexec &>/dev/null; then
    echo "  [+] NetExec: use system nxc (not .venv) — $(command -v nxc 2>/dev/null || command -v netexec)"
  else
    echo "  [i] NetExec: sudo apt install -y netexec  (conflicts with paramiko==2.12 in .venv)"
  fi

  echo "  [i] SpiderFoot: do NOT pip tools/spiderfoot/requirements.txt on Kali"
  echo "      Use: sudo apt install spiderfoot  OR deps in requirements-kali.txt"

  if [[ "$failed" -eq 1 ]]; then
    echo
    echo "[!] Pip had errors. Try: bash scripts/fix_venv_kali.sh"
  else
    echo
    echo "[+] Python dependencies OK in .venv"
    "$PY" -m pip check 2>&1 | grep -i conflict && echo "[i] See conflicts above — run: bash scripts/fix_venv_kali.sh" || true
  fi

  echo
  echo "[*] Optional IoT Python packages (CamOver, CamRaptor, upnpfuzz)..."
  "$PY" -m pip install -q upnpfuzz 2>/dev/null || echo "  [i] upnpfuzz pip skipped (optional)"
  "$PY" -m pip install -q "git+https://github.com/EntySec/CamOver.git" 2>/dev/null \
    || echo "  [i] CamOver pip skipped (optional)"
  "$PY" -m pip install -q "git+https://github.com/EntySec/CamRaptor.git" 2>/dev/null \
    || echo "  [i] CamRaptor pip skipped (optional)"

  if [[ -d "$ROOT/tools/changeme" ]] && [[ -f "$ROOT/tools/changeme/requirements.txt" ]]; then
    echo "  [*] changeme requirements..."
    "$PY" -m pip install -q -r "$ROOT/tools/changeme/requirements.txt" 2>/dev/null || true
  fi

  if [[ -d "$ROOT/tools/default-hunter" ]] && [[ -f "$ROOT/tools/default-hunter/pyproject.toml" ]]; then
    echo "  [*] Default-Hunter (pip editable)..."
    "$PY" -m pip install -q -e "$ROOT/tools/default-hunter" 2>/dev/null \
      || echo "  [i] Default-Hunter pip skipped (optional)"
  fi

  if [[ -d "$ROOT/tools/iotscan" ]] && [[ -f "$ROOT/tools/iotscan/pyproject.toml" ]]; then
    echo "  [*] IoTScan (pip editable)..."
    "$PY" -m pip install -q -e "$ROOT/tools/iotscan" 2>/dev/null \
      || echo "  [i] IoTScan pip skipped (optional)"
  fi

  if [[ -d "$ROOT/tools/iotbreaker" ]] && [[ -f "$ROOT/tools/iotbreaker/requirements.txt" ]]; then
    echo "  [*] IoTBreaker requirements (optional — may conflict; use separate venv if needed)..."
    "$PY" -m pip install -q -r "$ROOT/tools/iotbreaker/requirements.txt" 2>/dev/null \
      || echo "  [i] IoTBreaker deps skipped — run from tools/iotbreaker/.venv if needed"
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

echo "[6/10] NetExec (reference clone — use apt on Kali)..."
sync_tool netexec https://github.com/Pennyw0rth/NetExec.git 1

echo "[7/10] Nikto..."
sync_tool nikto https://github.com/sullo/nikto.git 1

echo "[8/10] SpiderFoot (reference clone — do not pip its requirements.txt)..."
sync_tool spiderfoot https://github.com/smicallef/spiderfoot.git 1

echo "[9/10] theHarvester..."
sync_tool theHarvester https://github.com/laramies/theHarvester.git 1

echo "[10/14] Amass..."
sync_tool amass https://github.com/owasp-amass/amass.git 1

echo "[11/14] changeme (default IoT creds)..."
sync_tool changeme https://github.com/ztgrace/changeme.git 1

echo "[12/14] jeanphorn IoT wordlists..."
sync_tool jeanphorn-wordlist https://github.com/jeanphorn/wordlist.git 1

echo "[13/18] IoTBreaker (CVE --check modules)..."
sync_tool iotbreaker https://github.com/servais1983/IoTBreaker.git 1

echo "[14/18] Default-Hunter (SySS changeme fork)..."
sync_tool default-hunter https://github.com/SySS-Research/Default-Hunter.git 1

echo "[15/18] IoTScan (AI IoT assessment CLI)..."
sync_tool iotscan https://github.com/sundi133/iotscan.git 1

echo "[16/18] Rustsploit (Rust RouterSploit — build optional)..."
sync_tool rustsploit https://github.com/s-b-repo/r-routersploit.git 1
if command -v cargo &>/dev/null && [[ -d "$ROOT/tools/rustsploit" ]]; then
  echo "  [*] Building rustsploit release binary (optional)..."
  (cd "$ROOT/tools/rustsploit" && cargo build --release 2>/dev/null) && \
    ln -sf "$ROOT/tools/rustsploit/target/release/rustsploit" "$ROOT/tools/rustsploit/rustsploit" 2>/dev/null || \
    echo "  [i] Rustsploit build skipped — add target/release/rustsploit to PATH manually"
else
  echo "  [i] Install Rust (cargo) to build rustsploit, or download release from GitHub"
fi

echo "[17/18] Genzai (optional Go binary — see docs/TOOLS.md)..."
if command -v genzai &>/dev/null; then
  echo "  [+] genzai already installed: $(command -v genzai)"
else
  echo "  [i] Install Genzai from: https://github.com/umair9747/genzai/releases"
  echo "      Or: go install github.com/umair9747/genzai@latest"
fi

echo "[18/18] dom-one/router_analysis (firmware reference — manual use)..."
if [[ ! -d "router_analysis" ]]; then
  sync_tool router_analysis https://github.com/dom-one/router_analysis.git 1 || true
else
  sync_tool router_analysis https://github.com/dom-one/router_analysis.git 1 || true
fi

cd "$ROOT"
install_python_deps

# Symlink rustsploit into .venv-friendly PATH hint
if [[ -x "$ROOT/tools/rustsploit/target/release/rustsploit" ]] && [[ ! -x "$ROOT/.venv/bin/rustsploit" ]]; then
  ln -sf "$ROOT/tools/rustsploit/target/release/rustsploit" "$ROOT/.venv/bin/rustsploit" 2>/dev/null || true
fi

echo
echo "======================================================"
echo "       ALL TOOLS DOWNLOADED SUCCESSFULLY!"
echo "======================================================"
echo "Tools:  $ROOT/tools/"
echo "venv:   $ROOT/.venv/"
echo
echo "  source .venv/bin/activate"
echo "  chmod +x run.sh scripts/*.sh"
echo "  ./run.sh"
echo
