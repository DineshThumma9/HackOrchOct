"""Case-level policy decisions."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ghostaudit.evidence import EvidenceStore
from ghostaudit.identities import Identities
from ghostaudit.policy import evaluate_case
from tests.fixtures import evidence_dataset, identity_dataset


def case(email: str, text: str) -> dict[str, str]:
    return {
        "case_id": "case_1",
        "email": email,
        "requested_at": "2026-03-01T09:00:00Z",
        "reported_status": "COMPLETE",
        "reported_at": "2026-03-01T11:00:00Z",
        "audit_at": "2026-03-02T00:00:00Z",
        "request_text": text,
    }


class EvaluateCaseTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = identity_dataset(Path(self.tmp.name))
        self.store = EvidenceStore(self.root)
        self.identities = Identities(self.root)

    def test_non_deletion_is_not_applicable(self) -> None:
        status, steps = evaluate_case(case("ada@example.com", "Send me a copy of my data."), self.store, self.identities)
        self.assertEqual((status, steps), ("NOT_APPLICABLE", []))

    def test_unknown_subject_is_incomplete(self) -> None:
        status, steps = evaluate_case(case("ghost@example.com", "Delete my account."), self.store, self.identities)
        self.assertEqual((status, steps), ("INCOMPLETE", []))

    def test_known_subject_without_remaining_records_is_complete(self) -> None:
        status, steps = evaluate_case(case("ada@example.com", "Delete my account."), self.store, self.identities)
        self.assertEqual(status, "COMPLETE")
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0]["operation"], "VERIFY_RECORD_ABSENT")
        self.assertEqual(steps[0]["resource_id"], "account_001")
        self.assertEqual(steps[0]["evidence_id"], "")

    def test_historical_email_resolves(self) -> None:
        status, _ = evaluate_case(case("ada.old@example.com", "Delete my account."), self.store, self.identities)
        self.assertEqual(status, "COMPLETE")

    def test_remaining_record_produces_findings_and_ordered_plan(self) -> None:
        evidence_dataset(self.root)
        store = EvidenceStore(self.root)
        store.load_all()

        status, steps = evaluate_case(case("ada@example.com", "Delete my account."), store, self.identities)

        self.assertEqual(status, "INCOMPLETE")
        self.assertEqual(
            [step["phase"] for step in steps],
            ["FINDING", "FINDING", "REMEDIATION", "REMEDIATION", "VERIFICATION", "VERIFICATION"],
        )
        self.assertEqual([step["step_no"] for step in steps], [1, 2, 3, 4, 5, 6])
        self.assertEqual(
            [step["operation"] for step in steps],
            [
                "REPORT_REMAINING_RECORD",
                "REPORT_REMAINING_RECORD",
                "DELETE_RECORD",
                "DELETE_RECORD",
                "VERIFY_RECORD_ABSENT",
                "VERIFY_RECORD_ABSENT",
            ],
        )
        self.assertEqual([step["resource_id"] for step in steps[:2]], ["account_001", "search_001"])
        self.assertEqual([step["evidence_id"] for step in steps[:2]], ["evidence_01", "evidence_02"])
        self.assertTrue(all(step["evidence_id"] == "" for step in steps[2:]))


if __name__ == "__main__":
    unittest.main()
