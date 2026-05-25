#!/usr/bin/env bash
# Opens a NEW terminal when a scan starts (called from Python live_scan_log.begin)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIVE_LOG="$ROOT/logs/LIVE_SCAN.log"

mkdir -p "$ROOT/logs"
touch "$LIVE_LOG"

if [[ "${AUTOPWN_LIVE_WINDOW:-1}" == "0" ]]; then
  exit 0
fi

# Reuse existing tail window if still running
if pgrep -af "tail.*LIVE_SCAN\.log" >/dev/null 2>&1; then
  exit 0
fi

_watch_cmd="cd '$ROOT' && clear && echo '=== AUTO-PWN — Live Scan (auto) ===' && echo 'Target log: $LIVE_LOG' && echo 'Started when scan began (Telegram or Kali menu)' && echo && tail -n 5 -f '$LIVE_LOG'"

_open_gui_terminal() {
  local title="AUTO-PWN Live Scan"
  [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]] || return 1

  if command -v gnome-terminal &>/dev/null; then
    gnome-terminal --title="$title" -- bash -c "$_watch_cmd; echo; read -rp 'Scan ended — Enter to close...'"
    return 0
  fi
  if command -v xfce4-terminal &>/dev/null; then
    xfce4-terminal --title="$title" -e "bash -c \"$_watch_cmd; echo; read -rp 'Scan ended — Enter to close...'\""
    return 0
  fi
  if command -v qterminal &>/dev/null; then
    qterminal -e bash -c "$_watch_cmd; echo; read -rp 'Scan ended — Enter to close...'"
    return 0
  fi
  if command -v konsole &>/dev/null; then
    konsole --new-tab -p tabtitle="$title" -e bash -c "$_watch_cmd; echo; read -rp 'Scan ended — Enter to close...'"
    return 0
  fi
  if command -v mate-terminal &>/dev/null; then
    mate-terminal --title="$title" -e "bash -c \"$_watch_cmd; echo; read -rp 'Scan ended — Enter to close...'\""
    return 0
  fi
  if command -v lxterminal &>/dev/null; then
    lxterminal --title="$title" -e "bash -c \"$_watch_cmd; echo; read -rp 'Scan ended — Enter to close...'\""
    return 0
  fi
  if command -v xterm &>/dev/null; then
    xterm -title "$title" -e bash -c "$_watch_cmd; echo; read -rp 'Scan ended — Enter to close...'" &
    return 0
  fi
  if command -v x-terminal-emulator &>/dev/null; then
    x-terminal-emulator -T "$title" -e bash -c "$_watch_cmd; echo; read -rp 'Scan ended — Enter to close...'" &
    return 0
  fi
  return 1
}

_open_tmux_pane() {
  command -v tmux &>/dev/null || return 1
  if [[ -n "${TMUX:-}" ]]; then
    tmux split-window -h -t "$TMUX_PANE" "bash -c \"$_watch_cmd\""
    tmux select-pane -t "$TMUX_PANE"
    return 0
  fi
  if tmux has-session -t autopwn-live 2>/dev/null; then
    return 0
  fi
  tmux new-session -d -s autopwn-live "bash -c \"$_watch_cmd\""
  return 0
}

_open_gui_terminal || _open_tmux_pane || true
