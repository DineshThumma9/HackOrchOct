"""Unit tests for the audit agent."""
import sys
from pathlib import Path

# Ensure code/ is on sys.path when running tests from repo root or code/
_code_dir = str(Path(__file__).resolve().parent.parent)
if _code_dir not in sys.path:
    sys.path.insert(0, _code_dir)

