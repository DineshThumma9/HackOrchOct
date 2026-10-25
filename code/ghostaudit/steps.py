"""Step construction, deduplication and contract ordering."""
from __future__ import annotations

from typing import Any

def finding_operation(remediation_operation: str) -> str:
    return {
        "DELETE_RECORD": "REPORT_REMAINING_RECORD",
        "REDACT_RECORD": "REPORT_EXPOSED_PII",
        "ANONYMIZE_RECORD": "REPORT_EXPOSED_PII",
        "DISABLE_DATA_FLOW": "REPORT_ACTIVE_DATA_FLOW",
        "BLOCK_RESTORE": "REPORT_RESTORE_RISK",
    }.get(remediation_operation, "REPORT_REMAINING_RECORD")


FINDING_ORDER = [
    "REPORT_REMAINING_RECORD",
    "REPORT_EXPOSED_PII",
    "REPORT_ACTIVE_DATA_FLOW",
    "REPORT_RESTORE_RISK",
]
REMEDIATION_ORDER = [
    "DISABLE_DATA_FLOW",
    "BLOCK_RESTORE",
    "DELETE_RECORD",
    "REDACT_RECORD",
    "ANONYMIZE_RECORD",
]
VERIFICATION_ORDER = [
    "VERIFY_RECORD_ABSENT",
    "VERIFY_RECORD_PRESENT",
    "VERIFY_RECORD_REDACTED",
    "VERIFY_RECORD_ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED",
    "VERIFY_RESTORE_BLOCKED",
]
PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OP_ORDER = {
    **{op: i for i, op in enumerate(FINDING_ORDER)},
    **{op: i for i, op in enumerate(REMEDIATION_ORDER)},
    **{op: i for i, op in enumerate(VERIFICATION_ORDER)},
}


def make_step(
    phase: str,
    system_id: str,
    resource_id: str,
    operation: str,
    state: str,
    evidence_id: str,
) -> dict[str, Any]:
    return {
        "phase": phase,
        "system_id": system_id,
        "resource_id": resource_id,
        "operation": operation,
        "state": state,
        "evidence_id": evidence_id,
    }


def number_steps(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # Deduplicate identical verification entries.
    seen = set()
    unique = []
    for step in steps:
        signature = (
            step["phase"],
            step["system_id"],
            step["resource_id"],
            step["operation"],
            step["state"],
        )
        if signature in seen:
            continue
        seen.add(signature)
        unique.append(step)
    unique.sort(
        key=lambda step: (
            PHASE_ORDER.get(step["phase"], 9),
            OP_ORDER.get(step["operation"], 99),
            step["system_id"],
            step["resource_id"],
        )
    )
    for index, step in enumerate(unique, start=1):
        step["step_no"] = index
    # Stable field order for readability.
    return [
        {
            "step_no": step["step_no"],
            "phase": step["phase"],
            "system_id": step["system_id"],
            "resource_id": step["resource_id"],
            "operation": step["operation"],
            "state": step["state"],
            "evidence_id": step["evidence_id"],
        }
        for step in unique
    ]
