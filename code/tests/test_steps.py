"""Step construction and contract ordering."""

from __future__ import annotations

import unittest

from ghostaudit.steps import (
    FINDING_ORDER,
    REMEDIATION_ORDER,
    VERIFICATION_ORDER,
    finding_operation,
    make_step,
    number_steps,
)


class FindingOperationTest(unittest.TestCase):
    def test_mapping_is_total(self) -> None:
        self.assertEqual(finding_operation("DELETE_RECORD"), "REPORT_REMAINING_RECORD")
        self.assertEqual(finding_operation("ANONYMIZE_RECORD"), "REPORT_EXPOSED_PII")
        self.assertEqual(finding_operation("DISABLE_DATA_FLOW"), "REPORT_ACTIVE_DATA_FLOW")
        self.assertEqual(finding_operation("BLOCK_RESTORE"), "REPORT_RESTORE_RISK")
        self.assertEqual(finding_operation("something_new"), "REPORT_REMAINING_RECORD")


class NumberingTest(unittest.TestCase):
    def test_dedupes_orders_and_numbers(self) -> None:
        steps = [
            make_step("VERIFICATION", "b", "2", "VERIFY_RECORD_PRESENT", "PRESENT", ""),
            make_step("FINDING", "a", "1", "REPORT_EXPOSED_PII", "PRESENT", "evidence_1"),
            make_step("REMEDIATION", "b", "2", "DELETE_RECORD", "ABSENT", ""),
            make_step("FINDING", "a", "1", "REPORT_REMAINING_RECORD", "PRESENT", "evidence_2"),
            make_step("FINDING", "a", "1", "REPORT_EXPOSED_PII", "PRESENT", "evidence_1"),
        ]
        ordered = number_steps(steps)

        self.assertEqual([step["step_no"] for step in ordered], [1, 2, 3, 4])
        self.assertEqual(
            [step["operation"] for step in ordered],
            [
                FINDING_ORDER[0],
                FINDING_ORDER[1],
                REMEDIATION_ORDER[2],
                VERIFICATION_ORDER[1],
            ],
        )

    def test_field_order_is_stable(self) -> None:
        step = number_steps([make_step("FINDING", "s", "r", "REPORT_REMAINING_RECORD", "PRESENT", "e")])[0]
        self.assertEqual(
            list(step),
            ["step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"],
        )


if __name__ == "__main__":
    unittest.main()
