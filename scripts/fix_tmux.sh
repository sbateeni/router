#!/usr/bin/env bash
# مرة واحدة — أغلق tmux المقسوم
pkill -f "tail.*LIVE_SCAN\.log" 2>/dev/null || true
tmux kill-session -t autopwn 2>/dev/null || true
tmux kill-session -t autopwn-live 2>/dev/null || true
if [[ -n "${TMUX:-}" ]]; then
  tmux kill-session 2>/dev/null || true
fi
echo "[+] tmux/tail cleaned. Open a NEW terminal:  cd ~/router && bash run.sh"
