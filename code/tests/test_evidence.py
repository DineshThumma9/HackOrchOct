"""Evidence loading, manifest handling and log parsing."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ghostaudit.evidence import EvidenceStore, parse_log_line
from ghostaudit.taxonomy import ACCOUNT, SEARCH
from tests.fixtures import evidence_dataset


class EvidenceStoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = evidence_dataset(Path(self.tmp.name))
        self.store = EvidenceStore(self.root)
        self.store.load_all()

    def test_parses_json_and_log(self) -> None:
        categories = {obs.category for obs in self.store.obs}
        self.assertIn(ACCOUNT, categories)
        self.assertIn(SEARCH, categories)

    def test_missing_file_is_reported_not_swallowed(self) -> None:
        self.assertTrue(any("evidence_03" in message for message in self.store.errors))

    def test_activity_link_is_indexed(self) -> None:
        links = self.store.activity_links["account_001"]
        self.assertEqual(links[0]["user_id"], "user_1")


class LogFormatTest(unittest.TestCase):
    def test_bracket_format(self) -> None:
        parsed = parse_log_line(
            '2026-03-01T10:05:00Z [INFO] [search_service] [trace_1] index_query_completed: '
            'resource_id=search_001 result=hit email="ada@example.com"'
        )
        assert parsed is not None
        self.assertEqual(parsed["service"], "search_service")
        self.assertEqual(parsed["event"], "index_query_completed")
        self.assertEqual(parsed["resource_id"], "search_001")
        self.assertEqual(parsed["email"], "ada@example.com")

    def test_pipe_format(self) -> None:
        parsed = parse_log_line(
            "2026-03-01T10:05:00Z | INFO | account_service | trace_2 | profile_lookup_completed | rows=0"
        )
        assert parsed is not None
        self.assertEqual(parsed["service"], "account_service")
        self.assertEqual(parsed["trace_id"], "trace_2")
        self.assertEqual(parsed["event"], "profile_lookup_completed")
        self.assertEqual(parsed["rows"], "0")

    def test_json_lines_format(self) -> None:
        parsed = parse_log_line('2026-03-01T10:05:00Z {"event": "record_lookup", "resource_id": "r1"}')
        assert parsed is not None
        self.assertEqual(parsed["event"], "record_lookup")

    def test_non_log_line(self) -> None:
        self.assertIsNone(parse_log_line("hello world"))


if __name__ == "__main__":
    unittest.main()
