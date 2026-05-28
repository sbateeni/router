"""Run tests/ utilities in-process so Live Log captures all output."""

from __future__ import annotations

import sys
from typing import Callable


def _run_main(main_fn: Callable[[], int], argv: list[str]) -> bool:
    old = sys.argv
    sys.argv = argv
    try:
        code = main_fn()
        return code == 0
    finally:
        sys.argv = old


def run_hikvision_test(host: str, *, password: str = "", full: bool = False) -> bool:
    import tests.test_hikvision_target as mod

    args = ["test_hikvision_target.py", "-H", host.strip()]
    if password:
        args.extend(["-p", password])
    if full:
        args.append("--full")
    return _run_main(mod.main, args)


def run_router_test(host: str) -> bool:
    import tests.test_router_target as mod

    return _run_main(mod.main, ["test_router_target.py", "-H", host.strip()])


def run_cve_test(host: str) -> bool:
    import tests.test_device_cve as mod

    return _run_main(mod.main, ["test_device_cve.py", "-H", host.strip()])
