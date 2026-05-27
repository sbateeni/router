#!/usr/bin/env bash
# Opens a dedicated terminal: tail -f a phase log (per-job path when arg 3 passed)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PHASE="${1:-1}"
TITLE="${2:-AUTO-PWN Phase $PHASE}"
LIVE_LOG="${3:-$ROOT/logs/PHASE_${PHASE//\//_}.log}"

mkdir -p "$(dirname "$LIVE_LOG")"
touch "$LIVE_LOG"

_watch="cd '$ROOT' && clear && echo '╔══════════════════════════════════════════════════════╗' && echo '║  AUTO-PWN — ${TITLE}' && echo '╚══════════════════════════════════════════════════════╝' && echo && echo 'Log: $LIVE_LOG' && echo 'Close this window when phase finishes.' && echo && tail -n 40 -f '$LIVE_LOG'"

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
