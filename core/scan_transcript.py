"""Append-only scan narrative — mirrors terminal flow for humans and AI review."""
import os
import re
from datetime import datetime

TRANSCRIPT_FILENAME = "SCAN_TRANSCRIPT.txt"

_active_path = None

SPINNER_RE = re.compile(r"^\[[⣾⣷⣯⣟⡿⢿⣻⣽]")
NOISE_SUBSTRINGS = (
    "telegram poll",
    "cryptographydeprecationwarning",
    "pkg_resources is deprecated",
)


def transcript_path(target_dir):
    return os.path.join(target_dir, TRANSCRIPT_FILENAME)


def begin(target_dir, header=None, live_source="cli"):
    global _active_path
    _active_path = transcript_path(target_dir)
    os.makedirs(target_dir, exist_ok=True)
    # Live log + terminal window: core.runner.run_selected_tool → live_scan_log.begin
    with open(_active_path, "w", encoding="utf-8") as fh:
        fh.write("============================================================\n")
        fh.write(" SCAN TRANSCRIPT (chronological — like terminal output)\n")
        fh.write("============================================================\n")
        fh.write(f"Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        fh.write(f"Folder  : {target_dir}\n")
        if header:
            fh.write(f"{header}\n")
        fh.write("\n")


def end(note=None):
    global _active_path
    if not _active_path:
        return
    with open(_active_path, "a", encoding="utf-8") as fh:
        fh.write("\n============================================================\n")
        fh.write(f"Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        if note:
            fh.write(f"{note}\n")
        fh.write("============================================================\n")
    try:
        from core.live_scan_log import end as live_end

        live_end(note)
    except Exception:
        pass
    _active_path = None


def _append(text):
    if not _active_path:
        return
    with open(_active_path, "a", encoding="utf-8") as fh:
        fh.write(text)
        if not text.endswith("\n"):
            fh.write("\n")
    try:
        from core.live_scan_log import write as live_write

        live_write(text if text.endswith("\n") else text + "\n")
    except Exception:
        pass


def phase(title):
    _append(f"\n{'=' * 54}\n>>> {title}\n{'=' * 54}")


def event(message):
    if message:
        _append(str(message))


def command(cmd):
    cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
    _append(f"\n[>] Executing: {cmd_str}")


def output(text, max_lines=60):
    if not text:
        return
    kept = []
    skipped_spinners = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if SPINNER_RE.match(stripped):
            skipped_spinners += 1
            continue
        lower = stripped.lower()
        if any(noise in lower for noise in NOISE_SUBSTRINGS):
            continue
        kept.append(line.rstrip())
    if skipped_spinners:
        kept.append(f"... ({skipped_spinners} progress spinner lines omitted)")
    if len(kept) > max_lines:
        extra = len(kept) - max_lines
        kept = kept[:max_lines] + [f"... ({extra} more lines — see tool log file in target folder)"]
    _append("\n".join(kept))


def read_transcript(target_dir, max_chars=120000):
    path = transcript_path(target_dir)
    if not os.path.exists(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read(max_chars)
    except OSError:
        return ""
