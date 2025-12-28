#!/usr/bin/env python3
"""Compatibility wrapper for invoking the pytest-based test suite."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest


def main(argv: list[str] | None = None) -> int:
    args = list(argv or sys.argv[1:])
    root = Path(__file__).resolve().parent.parent
    if "-c" not in args and not any(arg.startswith("-c") for arg in args):
        args.extend(["-c", str(root / "pytest.ini")])
    return pytest.main(args)


if __name__ == "__main__":
    sys.exit(main())
