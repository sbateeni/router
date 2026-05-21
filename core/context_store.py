import json
import os
from datetime import datetime

CONTEXT_FILE = "scan_context.json"


def save_scan_context(target_dir, context, phase, profile_name, exploited=False):
    payload = {
        "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "phase": phase,
        "profile": profile_name,
        "exploited": exploited,
        "open_ports": [p for p in context.open_ports if isinstance(p, dict)],
        "web_ports": context.web_ports,
        "login_ports": context.login_ports,
        "discovered_paths": context.discovered_paths,
        "discovered_urls": context.discovered_urls,
        "gau_urls": context.gau_urls,
        "ffuf_candidates": context.ffuf_candidates,
        "ai_scan_plan": getattr(context, "ai_scan_plan", {}),
        "ai_hydra_plan": getattr(context, "ai_hydra_plan", {}),
    }
    path = os.path.join(target_dir, CONTEXT_FILE)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    return path


def load_scan_context(target_dir):
    path = os.path.join(target_dir, CONTEXT_FILE)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)
