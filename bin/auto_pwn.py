#!/usr/bin/env python3
"""Standalone device AUTO-PWN (cameras + routers)."""

import runpy

import _bootstrap

_bootstrap.install()

from core.paths import setup_project_env

if __name__ == "__main__":
    setup_project_env()
    runpy.run_module("engines.auto_pwn_main", run_name="__main__")
