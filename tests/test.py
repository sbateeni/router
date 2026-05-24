#!/usr/bin/env python3
"""Quick Hikvision snapshot capture."""

import bootstrap  # noqa: F401

from engines.hikvision_snapshots import main

if __name__ == "__main__":
    raise SystemExit(main())
