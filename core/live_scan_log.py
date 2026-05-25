"""Mirror scan output to logs/LIVE_SCAN.log for tail -f in the Kali terminal."""
import os
from datetime import datetime

from core.paths import logs_dir

_active = False
_log_path = None


def path():
    return os.path.join(logs_dir(), "LIVE_SCAN.log")


def begin(target_label, source="scan"):
    global _active, _log_path
    _log_path = path()
    _active = True
    os.makedirs(os.path.dirname(_log_path), exist_ok=True)
    with open(_log_path, "w", encoding="utf-8") as fh:
        fh.write("=" * 60 + "\n")
        fh.write(f"LIVE SCAN — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        fh.write(f"Source : {source}\n")
        fh.write(f"Target : {target_label}\n")
        fh.write("=" * 60 + "\n\n")


def write(text):
    if not _active or not _log_path:
        return
    try:
        with open(_log_path, "a", encoding="utf-8") as fh:
            fh.write(text)
            if text and not text.endswith("\n"):
                fh.write("\n")
            fh.flush()
    except OSError:
        pass


def end(note=None):
    global _active
    if not _active:
        return
    write("\n" + "=" * 60)
    write(f"Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if note:
        write(note)
    write("=" * 60 + "\n")
    _active = False


def is_active():
    return _active
