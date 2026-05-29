"""Re-export device tests for GUI utilities (Live Log captures stdout)."""

from core.device_tests import run_cve_test, run_hikvision_test, run_router_test

__all__ = ["run_cve_test", "run_hikvision_test", "run_router_test"]
