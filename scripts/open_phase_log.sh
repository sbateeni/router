#!/usr/bin/env bash
# Opens a terminal tailing logs/PHASE_N.log (set AUTOPWN_PHASE_WINDOWS=1 to auto-open)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PHASE="${1:-1}"
TITLE="${2:-AUTO-PWN Phase $PHASE}"
LIVE_LOG="$ROOT/logs/PHASE_${PHASE}.log"

mkdir -p "$ROOT/logs"
touch "$LIVE_LOG"

_watch="cd '$ROOT' && echo '=== $TITLE ===' && echo '$LIVE_LOG' && echo && tail -n 30 -f '$LIVE_LOG'"

_open_gui() {
  [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]] || return 1
  if command -v gnome-terminal &>/dev/null; then
    gnome-terminal --title="$TITLE" -- bash -c "$_watch"
    return 0
  fi
  if command -v xfce4-terminal &>/dev/null; then
    xfce4-terminal --title="$TITLE" -e "bash -c \"$_watch\""
    return 0
  fi
  if command -v qterminal &>/dev/null; then
    qterminal -e bash -c "$_watch"
    return 0
  fi
  if command -v konsole &>/dev/null; then
    konsole --new-tab -p tabtitle="$TITLE" -e bash -c "$_watch"
    return 0
  fi
  if command -v xterm &>/dev/null; then
    xterm -title "$TITLE" -e bash -c "$_watch" &
    return 0
  fi
  return 1
}

_open_gui || true
