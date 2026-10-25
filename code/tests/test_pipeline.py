"""End-to-end orchestration and CSV contract for a tiny fixture."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ghostaudit.evidence import EvidenceStore
from ghostaudit.identities import Identities
from ghostaudit.model import read_csv
from ghostaudit.pipeline import build_rows, write_output
from tests.fixtures import identity_dataset


def case() -> dict[str, str]:
    return {
        "case_id": "case_1",
        "email": "ada@example.com",
        "requested_at": "2026-03-01T09:00:00Z",
        "reported_status": "COMPLETE",
        "reported_at": "2026-03-01T11:00:00Z",
        "audit_at": "2026-03-02T00:00:00Z",
        "request_text": "Please delete my account.",
    }


class PipelineTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = identity_dataset(Path(self.tmp.name))
        self.store = EvidenceStore(self.root)
        self.identities = Identities(self.root)

    def test_rows_are_sorted_and_serialised(self) -> None:
        rows = build_rows([case()], self.store, self.identities, dataset=self.root)
        self.assertEqual([row["case_id"] for row in rows], ["case_1"])
        self.assertEqual(rows[0]["deletion_status"], "COMPLETE")
        steps = json.loads(rows[0]["steps_json"])
        self.assertEqual(steps[0]["step_no"], 1)
        self.assertEqual(list(steps[0]), ["step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"])

    def test_csv_round_trip(self) -> None:
        output = Path(self.tmp.name) / "out.csv"
        rows = build_rows([case()], self.store, self.identities, dataset=self.root)
        write_output(rows, output)

        back = read_csv(output)
        self.assertEqual(list(back[0]), ["case_id", "deletion_status", "steps_json"])
        self.assertEqual(back, rows)

    def test_no_dataset_csv_leak(self) -> None:
        """The fixture directory has no request CSVs, so only the input is used."""
        self.assertFalse((self.root / "sample_deletion_requests.csv").exists())
        rows = build_rows([case()], self.store, self.identities, dataset=self.root)
        self.assertEqual(len(rows), 1)


if __name__ == "__main__":
    unittest.main()
