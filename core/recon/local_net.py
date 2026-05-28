"""Local connection snapshot (ss/netstat) on the attack workstation."""

from __future__ import annotations

import json
import os
import shutil
from datetime import datetime, timezone

from core.utils import ensure_parent_dir, run_cmd


def snapshot_local_connections(target_dir: str) -> dict:
    """Capture active sockets on this machine; save LOCAL_CONNECTIONS.json + .txt."""
    if shutil.which("ss"):
        cmd = ["ss", "-tunap"]
        tool = "ss"
    elif shutil.which("netstat"):
        cmd = ["netstat", "-tunap"]
        tool = "netstat"
    else:
        print("[!] Neither ss nor netstat found — skip local connection snapshot")
        return {"ok": False, "error": "ss/netstat missing"}

    print(f"\n[*] Local connection snapshot ({tool})...")
    ok, output = run_cmd(cmd, capture=True, timeout=30)
    text = output or ""

    txt_path = os.path.join(target_dir, "local_connections.txt")
    json_path = os.path.join(target_dir, "LOCAL_CONNECTIONS.json")
    ensure_parent_dir(txt_path)

    with open(txt_path, "w", encoding="utf-8") as fh:
        fh.write(text)
        if not text.endswith("\n"):
            fh.write("\n")

    payload = {
        "tool": tool,
        "ok": ok,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "line_count": len(text.splitlines()),
        "log": txt_path,
    }
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)

    print(f"[+] Local connections saved → {txt_path}")
    return payload
