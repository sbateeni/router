#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="${HOME}/.local/share/applications"
DESKTOP_FILE="${APP_DIR}/router-gui.desktop"

mkdir -p "${APP_DIR}"

cat > "${DESKTOP_FILE}" <<EOF
[Desktop Entry]
Type=Application
Name=AUTO-PWN GUI
Comment=Launch AUTO-PWN Unified GUI
Exec=bash -lc 'cd "${ROOT}" && source .venv/bin/activate && python bin/gui_app.py'
Path=${ROOT}
Terminal=false
Categories=Utility;Security;
EOF

chmod +x "${DESKTOP_FILE}"
echo "[+] Desktop launcher installed: ${DESKTOP_FILE}"
echo "[*] Open applications menu and search for: AUTO-PWN GUI"
