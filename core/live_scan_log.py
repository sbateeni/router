"""Mirror scan output to logs/LIVE_SCAN.log; auto-open tail window on scan start."""
import os
import subprocess
import sys
from contextlib import contextmanager
from datetime import datetime

from core.paths import logs_dir, project_root

_active = False
_log_path = None


def path():
    return os.path.join(logs_dir(), "LIVE_SCAN.log")


def _open_tail_window(title: str):
    if os.environ.get("AUTOPWN_LIVE_WINDOW", "1").strip() == "0":
        return
    script = os.path.join(project_root(), "scripts", "open_live_log.sh")
    if not os.path.isfile(script):
        return
    try:
        subprocess.Popen(
            ["bash", script, title[:80]],
            cwd=project_root(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        pass


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
    _open_tail_window(f"Scan: {target_label}")


def write(text):
    log = _log_path or path()
    if not _active and not os.environ.get("AUTOPWN_SCAN_SOURCE"):
        return
    try:
        os.makedirs(os.path.dirname(log), exist_ok=True)
        with open(log, "a", encoding="utf-8") as fh:
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


class _StdoutTee:
    """Mirror stdout writes to LIVE_SCAN.log while preserving the real terminal."""

    def __init__(self, original):
        self._original = original

    def write(self, data):
        if not data:
            return 0
        try:
            self._original.write(data)
        except Exception:
            pass
        write(data)
        return len(data)

    def flush(self):
        try:
            self._original.flush()
        except Exception:
            pass

    def fileno(self):
        return self._original.fileno()

    def isatty(self):
        try:
            return self._original.isatty()
        except Exception:
            return False

    @property
    def encoding(self):
        return getattr(self._original, "encoding", "utf-8")


@contextmanager
def mirror_stdout():
    """Tee sys.stdout to LIVE_SCAN.log for the duration of a scan."""
    if not _active:
        yield
        return
    original = sys.stdout
    sys.stdout = _StdoutTee(original)
    try:
        yield
    finally:
        sys.stdout = original
