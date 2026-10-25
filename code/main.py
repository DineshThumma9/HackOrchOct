#!/usr/bin/env python3
"""Entry point for the deletion-audit agent.

The implementation lives in the ``ghostaudit`` package next to this file; this
shim keeps the documented ``python3 code/main.py`` command working and
re-exports the public API for the evaluation harness.

Run:
    python3 code/main.py                 # writes output.csv
    python3 code/main.py --sample        # also scores sample_output.csv
"""

from __future__ import annotations

from ghostaudit import *  # noqa: F401,F403 - public API for importers
from ghostaudit.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
