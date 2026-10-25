"""Filesystem anchors resolved relative to the repository root."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATASET = ROOT / "dataset"
EVIDENCE_DIR = DATASET / "evidence"
