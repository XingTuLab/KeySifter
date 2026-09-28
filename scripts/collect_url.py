#!/usr/bin/env python3
"""Collect browser-visible resources, optionally detect and classify them."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from stage0_collect.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
