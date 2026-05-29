#!/usr/bin/env python3
"""CLI entry: AI Guided Scan (orchestrator loop + comprehensive report)."""

from __future__ import annotations

import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from core.gui_workspace import prepare_target_workspace
from core.notify import load_dotenv
from core.paths import project_root
from core.scan_config import set_scan_profile
from engines.utils import log


def main() -> int:
    load_dotenv(project_root())
    p = argparse.ArgumentParser(description="AI Guided Scan — autonomous tool loop")
    p.add_argument(
        "target",
        help="IP or http://user:pass@IP/",
    )
    p.add_argument("--profile", default="normal", choices=("quick", "normal", "deep"))
    p.add_argument("--max-steps", type=int, default=None, help="Override AI_ORCHESTRATOR_MAX_STEPS")
    p.add_argument(
        "--reset",
        action="store_true",
        help="Clear prior artifacts in targets/<workspace>/ before scan",
    )
    args = p.parse_args()

    raw = args.target.strip()
    info = prepare_target_workspace(raw, keep_artifacts=not args.reset)
    ip = info["scan_host"]
    target_dir = info["target_dir"]
    set_scan_profile(args.profile)

    from core.ai.orchestrator import run_ai_guided_scan

    try:
        run_ai_guided_scan(
            ip,
            target_dir,
            raw_target=raw,
            profile=args.profile,
            max_steps=args.max_steps,
        )
    except KeyboardInterrupt:
        log("Cancelled", "WARNING")
        return 130

    report = os.path.join(target_dir, "AI_COMPREHENSIVE_REPORT.txt")
    log(f"Done — report: {report}", "SUCCESS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
