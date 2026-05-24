import sys

import _bootstrap

_bootstrap.install()

from core.paths import setup_project_env

setup_project_env()

from engines.utils import log, extract_ip, extract_credentials
from engines.camera_viewer import CameraViewer


def direct_view(url):
    ip = extract_ip(url)
    if not ip:
        log("Invalid URL/IP provided.", "ERROR")
        return

    user, pwd = extract_credentials(url)
    if not user:
        user = "admin"
    if not pwd:
        pwd = "12345"

    log(f"DIRECT MODE: Targeting {ip} with {user}:{pwd}", "SUCCESS")

    cam = CameraViewer(ip, user, pwd)
    channels = cam.discover_channels()

    if not channels:
        log("No active channels found. Device might be offline or credentials wrong.", "ERROR")
        return

    cam.take_snapshots()
    cam.print_summary()
    cam.open_in_vlc(use_sub_stream=True)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        print("\n" + "=" * 50)
        print("      DIRECT CAMERA VIEW - VLC MODE")
        print("=" * 50)
        target = input("\n[?] Enter Full URL (e.g., http://admin:pass@ip): ").strip()

    if target:
        if not target.startswith("http"):
            target = "http://" + target
        direct_view(target)
    else:
        print("No target entered.")
