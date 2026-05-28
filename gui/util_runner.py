"""Run tests/ utilities in-process so Live Log captures all output."""

from __future__ import annotations

import os
import sys
from typing import Callable

_TESTS_ENV_READY = False


def _prepare_tests_env() -> None:
    """Match CLI: ``python tests/test_*.py`` adds tests/ to path for ``import bootstrap``."""
    global _TESTS_ENV_READY
    if _TESTS_ENV_READY:
        return
    from core.paths import project_root

    root = project_root()
    tests_dir = os.path.join(root, "tests")
    for path in (root, tests_dir):
        if path not in sys.path:
            sys.path.insert(0, path)
    if "bootstrap" not in sys.modules:
        import bootstrap  # noqa: F401  # tests/bootstrap.py
    _TESTS_ENV_READY = True


def _run_main(main_fn: Callable[[], int], argv: list[str]) -> bool:
    _prepare_tests_env()
    old = sys.argv
    sys.argv = argv
    try:
        code = main_fn()
        return code == 0
    except Exception as exc:
        import traceback

        print(f"[!] Test error: {exc}")
        traceback.print_exc()
        return False
    finally:
        sys.argv = old


def run_hikvision_test(host: str, *, password: str = "", full: bool = False) -> bool:
    _prepare_tests_env()
    import tests.test_hikvision_target as mod

    args = ["test_hikvision_target.py", "-H", host.strip()]
    if password:
        args.extend(["-p", password])
    if full:
        args.append("--full")
    return _run_main(mod.main, args)


def run_router_test(host: str) -> bool:
    _prepare_tests_env()
    import tests.test_router_target as mod

    return _run_main(mod.main, ["test_router_target.py", "-H", host.strip()])


def run_cve_test(host: str) -> bool:
    _prepare_tests_env()
    import tests.test_device_cve as mod

    return _run_main(mod.main, ["test_device_cve.py", "-H", host.strip()])
