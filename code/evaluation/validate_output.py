#!/usr/bin/env python3
"""Validate ``output.csv`` against the challenge output contract.

Run from the repository root:

    python3 code/evaluation/validate_output.py

The check is independent of the solver's own scoring code.  It verifies row
coverage, ordering, step numbering, allowed operations and states, phase order,
evidence eligibility, and the required remediation/verification coverage.
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "code"))

import main as solver  # noqa: E402

FIELDS = ["step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"]
PHASES = ["FINDING", "REMEDIATION", "VERIFICATION"]
STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}

ALLOWED = {
    ("FINDING", "REPORT_REMAINING_RECORD", "PRESENT"),
    ("FINDING", "REPORT_EXPOSED_PII", "PRESENT"),
    ("FINDING", "REPORT_ACTIVE_DATA_FLOW", "ACTIVE"),
    ("FINDING", "REPORT_RESTORE_RISK", "ACTIVE"),
    ("REMEDIATION", "DISABLE_DATA_FLOW", "DISABLED"),
    ("REMEDIATION", "BLOCK_RESTORE", "BLOCKED"),
    ("REMEDIATION", "DELETE_RECORD", "ABSENT"),
    ("REMEDIATION", "REDACT_RECORD", "REDACTED"),
    ("REMEDIATION", "ANONYMIZE_RECORD", "ANONYMIZED"),
    ("VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT"),
    ("VERIFICATION", "VERIFY_RECORD_PRESENT", "PRESENT"),
    ("VERIFICATION", "VERIFY_RECORD_REDACTED", "REDACTED"),
    ("VERIFICATION", "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
    ("VERIFICATION", "VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
    ("VERIFICATION", "VERIFY_RESTORE_BLOCKED", "BLOCKED"),
}

VERIFY_FOR = {
    "DELETE_RECORD": "VERIFY_RECORD_ABSENT",
    "REDACT_RECORD": "VERIFY_RECORD_REDACTED",
    "ANONYMIZE_RECORD": "VERIFY_RECORD_ANONYMIZED",
    "DISABLE_DATA_FLOW": "VERIFY_DATA_FLOW_DISABLED",
    "BLOCK_RESTORE": "VERIFY_RESTORE_BLOCKED",
}

RECORD_OPERATIONS = {"DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD"}
FLOW_OPERATIONS = {"DISABLE_DATA_FLOW", "BLOCK_RESTORE"}


def validate() -> list[str]:
    errors: list[str] = []
    requests = {row["case_id"]: row for row in solver.read_csv(solver.DATASET / "deletion_requests.csv")}
    manifest = {
        row["file_id"]: solver.parse_ts(row["captured_at"])
        for row in solver.read_csv(solver.DATASET / "evidence_files.csv")
    }

    path = ROOT / "output.csv"
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.reader(handle)
        header = next(reader, [])
        if header != ["case_id", "deletion_status", "steps_json"]:
            errors.append(f"header is {header!r}")
        rows = list(csv.DictReader(path.open(newline="", encoding="utf-8")))

    if len(rows) != len(requests):
        errors.append(f"{len(rows)} rows for {len(requests)} requests")
    ids = [row["case_id"] for row in rows]
    if ids != sorted(ids, key=lambda case_id: int(case_id.split("_")[1])):
        errors.append("rows are not sorted by case_id")
    if len(set(ids)) != len(ids):
        errors.append("duplicate case_id values")
    missing = sorted(set(requests) - set(ids))
    extra = sorted(set(ids) - set(requests))
    if missing:
        errors.append(f"missing case ids: {missing[:10]}")
    if extra:
        errors.append(f"unknown case ids: {extra[:10]}")

    for row in rows:
        case_id = row["case_id"]
        case = requests.get(case_id)
        if case is None:
            continue
        audit_at = solver.parse_ts(case["audit_at"])
        status = row["deletion_status"]
        if status not in STATUSES:
            errors.append(f"{case_id}: invalid status {status!r}")
        try:
            steps = json.loads(row["steps_json"])
        except json.JSONDecodeError as exc:
            errors.append(f"{case_id}: invalid JSON ({exc})")
            continue
        if not isinstance(steps, list):
            errors.append(f"{case_id}: steps_json is not an array")
            continue

        if status == "NOT_APPLICABLE":
            if steps:
                errors.append(f"{case_id}: NOT_APPLICABLE with {len(steps)} steps")
            continue
        if not steps:
            errors.append(f"{case_id}: {status} with no steps")

        phase_rank = -1
        signatures: set[tuple] = set()
        for index, step in enumerate(steps, start=1):
            if list(step) != FIELDS:
                errors.append(f"{case_id} step {index}: fields are {list(step)!r}")
                continue
            if step["step_no"] != index:
                errors.append(f"{case_id} step {index}: step_no is {step['step_no']}")
            if step["phase"] not in PHASES:
                errors.append(f"{case_id} step {index}: invalid phase {step['phase']!r}")
                continue
            rank = PHASES.index(step["phase"])
            if rank < phase_rank:
                errors.append(f"{case_id} step {index}: phase order regressed")
            phase_rank = max(phase_rank, rank)

            key = (step["phase"], step["operation"], step["state"])
            if key not in ALLOWED:
                errors.append(f"{case_id} step {index}: invalid operation/state {key!r}")
            signature = (
                step["phase"],
                step["system_id"],
                step["resource_id"],
                step["operation"],
                step["state"],
            )
            if signature in signatures:
                errors.append(f"{case_id} step {index}: duplicate step")
            signatures.add(signature)

            evidence = step["evidence_id"]
            if step["phase"] in {"FINDING", "REMEDIATION"}:
                required = step["phase"] == "FINDING"
                if required != bool(evidence):
                    errors.append(
                        f"{case_id} step {index}: evidence_id={evidence!r} for {step['phase']}"
                    )
            elif status == "COMPLETE" and not evidence:
                errors.append(f"{case_id} step {index}: COMPLETE verification has no evidence")
            elif status == "INCOMPLETE" and evidence:
                errors.append(f"{case_id} step {index}: future verification cites evidence")

            if evidence:
                captured = manifest.get(evidence)
                if captured is None:
                    errors.append(f"{case_id} step {index}: unknown evidence {evidence!r}")
                elif captured > audit_at:
                    errors.append(f"{case_id} step {index}: evidence {evidence} is post-audit")

        if status == "COMPLETE":
            if any(step["phase"] != "VERIFICATION" for step in steps):
                errors.append(f"{case_id}: COMPLETE contains a non-verification step")
            continue

        findings = [step for step in steps if step["phase"] == "FINDING"]
        remediation = [step for step in steps if step["phase"] == "REMEDIATION"]
        verification = [step for step in steps if step["phase"] == "VERIFICATION"]
        if not findings or not remediation or not verification:
            errors.append(f"{case_id}: INCOMPLETE is missing a phase")

        seen_record_change = False
        for step in remediation:
            if step["operation"] in FLOW_OPERATIONS and seen_record_change:
                errors.append(f"{case_id}: {step['operation']} after a record change")
            if step["operation"] in RECORD_OPERATIONS:
                seen_record_change = True

        finding_resources = {(step["system_id"], step["resource_id"]) for step in findings}
        remediation_resources = {(step["system_id"], step["resource_id"]) for step in remediation}
        for system, resource in sorted(remediation_resources - finding_resources):
            errors.append(f"{case_id}: remediation without a finding for {system}/{resource}")
        for system, resource in sorted(finding_resources - remediation_resources):
            errors.append(f"{case_id}: finding without remediation for {system}/{resource}")

        verified = {
            (step["system_id"], step["resource_id"], step["operation"]) for step in verification
        }
        for step in remediation:
            expected = VERIFY_FOR.get(step["operation"])
            if expected and (step["system_id"], step["resource_id"], expected) not in verified:
                errors.append(
                    f"{case_id}: no {expected} for {step['system_id']}/{step['resource_id']}"
                )

    return errors


def main() -> int:
    errors = validate()
    if errors:
        for error in errors:
            print(f"FAIL {error}")
        print(f"{len(errors)} contract errors")
        return 1
    print("OK output.csv satisfies the contract checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
