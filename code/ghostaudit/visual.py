"""Load the facts transcribed from PDF and screenshot evidence."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

DATA_FILE = Path(__file__).with_name("data") / "visual_evidence.json"


@lru_cache(maxsize=1)
def load_visual_evidence() -> dict[str, list[dict[str, Any]]]:
    """Return ``file_id`` -> transcribed observations.

    The data lives in JSON rather than Python so it can be diffed, validated
    and regenerated without touching the parser.
    """
    with DATA_FILE.open(encoding="utf-8") as handle:
        return json.load(handle)
