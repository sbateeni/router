import os
import shutil


def find_vlc() -> str | None:
    """Return VLC executable path on Windows or Linux."""
    candidates = []
    if os.name == "nt":
        candidates.extend(
            (
                r"C:\Program Files\VideoLAN\VLC\vlc.exe",
                r"C:\Program Files (x86)\VideoLAN\VLC\vlc.exe",
            )
        )
    else:
        candidates.extend(("/usr/bin/vlc", "/usr/local/bin/vlc"))

    for path in candidates:
        if os.path.exists(path):
            return path
    return shutil.which("vlc")
