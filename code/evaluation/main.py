"""Offline evaluation for the Ghost Data audit agent.

Run from the repository root:

    python3 code/evaluation/main.py

The script scores the public sample, then runs a small suite of participant
authored cases that exercise behaviours the sample does not cover directly.
"""

from __future__ import annotations

import difflib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "code"))

import ghostaudit as solver  # noqa: E402


FIELDS = ["phase", "system_id", "resource_id", "operation", "state", "evidence_id"]


def load_sample_predictions() -> tuple[dict[str, dict], dict[str, dict]]:
    want = {row["case_id"]: row for row in solver.read_csv(solver.DATASET / "sample_output.csv")}
    cases = solver.read_csv(solver.DATASET / "sample_deletion_requests.csv")
    store = solver.EvidenceStore()
    store.load_all()
    identities = solver.Identities()
    rows = solver.build_rows(cases, store, identities)
    got = {row["case_id"]: row for row in rows}
    return want, got


def step_key(step: dict) -> tuple:
    return (
        step["phase"],
        step["system_id"],
        step["resource_id"],
        step["operation"],
        step["state"],
    )


def score_sample(want: dict[str, dict], got: dict[str, dict]) -> dict:
    status_ok = 0
    exact = 0
    sequence_ok = 0
    lcs: list[float] = []
    tp = fp = fn = 0
    positional = {field: [0, 0] for field in FIELDS}
    step_count_ok = 0

    for case_id, expected in want.items():
        predicted = got.get(case_id)
        if predicted is None:
            continue
        if predicted["deletion_status"] == expected["deletion_status"]:
            status_ok += 1
        gold = json.loads(expected["steps_json"])
        pred = json.loads(predicted["steps_json"])
        if gold == pred:
            exact += 1
        if len(gold) == len(pred):
            step_count_ok += 1
        gold_keys = [step_key(step) for step in gold]
        pred_keys = [step_key(step) for step in pred]
        if gold_keys == pred_keys:
            sequence_ok += 1
        lcs.append(difflib.SequenceMatcher(a=gold_keys, b=pred_keys).ratio())

        matched: set[int] = set()
        for pred_step in pred:
            for index, gold_step in enumerate(gold):
                if index in matched:
                    continue
                if step_key(pred_step) == step_key(gold_step):
                    matched.add(index)
                    break
        tp += len(matched)
        fn += len(gold) - len(matched)
        fp += len(pred) - len(matched)

        for gold_step, pred_step in zip(gold, pred):
            for field in FIELDS:
                positional[field][1] += 1
                if gold_step[field] == pred_step[field]:
                    positional[field][0] += 1

    total = len(want)
    return {
        "cases": total,
        "status_accuracy": status_ok / total,
        "exact_steps": exact / total,
        "sequence_accuracy": sequence_ok / total,
        "mean_lcs": sum(lcs) / len(lcs) if lcs else 0.0,
        "step_precision": tp / (tp + fp) if tp + fp else 0.0,
        "step_recall": tp / (tp + fn) if tp + fn else 0.0,
        "step_count_accuracy": step_count_ok / total,
        "positional_field_accuracy": {
            field: values[0] / values[1] if values[1] else 0.0
            for field, values in positional.items()
        },
    }


def make_case(case_id: str, email: str, text: str, audit_at: str) -> dict[str, str]:
    return {
        "case_id": case_id,
        "email": email,
        "requested_at": "2026-09-01T09:00:00Z",
        "reported_status": "COMPLETE",
        "reported_at": "2026-09-02T09:00:00Z",
        "audit_at": audit_at,
        "request_text": text,
    }


def _attachment_linked(steps: list[dict]) -> bool:
    """A support attachment linked only through its uploader email."""
    return any(
        step["operation"] == "REPORT_REMAINING_RECORD"
        and step["system_id"] == "support_platform"
        and step["resource_id"] == "support_4665"
        and step["evidence_id"] == "evidence_45"
        for step in steps
    )


def _block_accounts_match(
    store: solver.EvidenceStore, identities: solver.Identities
) -> tuple[int, int, bool]:
    """Compare block attribution with the labelled sample accounts."""
    sample_cases = solver.read_csv(solver.DATASET / "sample_deletion_requests.csv")
    sample_gold = {
        row["case_id"]: row
        for row in solver.read_csv(solver.DATASET / "sample_output.csv")
    }
    expected: dict[str, str] = {}
    for case_id, row in sample_gold.items():
        for step in json.loads(row["steps_json"]):
            if step["system_id"] == "account_service":
                expected[case_id] = step["resource_id"]
                break

    predicted_rows = solver.build_rows(sample_cases, store, identities)
    actual: dict[str, str] = {}
    for row in predicted_rows:
        for step in json.loads(row["steps_json"]):
            if step["system_id"] == "account_service":
                actual[row["case_id"]] = step["resource_id"]
                break

    matched = sum(1 for case_id, resource in expected.items() if actual.get(case_id) == resource)
    unique = len(set(actual.values())) == len(actual)
    return matched, len(expected), unique


def custom_cases(store: solver.EvidenceStore, identities: solver.Identities) -> list[dict]:
    attachment_envelope = dict(
        next(
            row
            for row in solver.read_csv(solver.DATASET / "deletion_requests.csv")
            if row["case_id"] == "case_479"
        )
    )
    attachment_envelope["case_id"] = "custom_06"
    cases = [
        (
            make_case(
                "custom_01",
                "keiko.nakamura@gmail.com",
                "Please remove me from marketing lists only. I still want receipts and service messages.",
                "2026-09-15T12:00:00Z",
            ),
            "NOT_APPLICABLE",
            lambda steps: steps == [],
            "marketing opt-out is not a deletion request",
        ),
        (
            make_case(
                "custom_02",
                "almeida.mariana@gmail.com",
                "Could you send me a copy of the information held on my account? I still use it.",
                "2026-09-15T12:00:00Z",
            ),
            "NOT_APPLICABLE",
            lambda steps: steps == [],
            "access request is not a deletion request",
        ),
        (
            make_case(
                "custom_03",
                "noor-khalil@proton.me",
                "Solicito a exclusão permanente da conta associada a este e-mail. "
                "Verifiquem os identificadores atuais e anteriores.",
                "2026-10-01T12:00:00Z",
            ),
            "INCOMPLETE",
            lambda steps: bool(steps),
            "Portuguese deletion request is authorised",
        ),
        (
            make_case(
                "custom_04",
                "addo.kofi@gmail.com",
                "Please permanently delete the account associated with this email address.",
                "2026-09-15T12:00:00Z",
            ),
            "INCOMPLETE",
            lambda steps: any(
                step["operation"] == "REDACT_RECORD"
                and step["resource_id"] == "tombstone_9178"
                for step in steps
            ),
            "tombstone keeps its reference but loses direct identifiers",
        ),
        (
            make_case(
                "custom_05",
                "mori.ren@gmail.com",
                "Please delete my account and remove anything that can recreate my profile.",
                "2026-09-26T11:00:00Z",
            ),
            "INCOMPLETE",
            lambda steps: _ordered_remediation(steps),
            "active flow is disabled before records change",
        ),
        (
            attachment_envelope,
            "INCOMPLETE",
            _attachment_linked,
            "support attachment linked only by its uploader email is a remaining record",
        ),
    ]
    results = []
    for case, expected_status, predicate, note in cases:
        status, steps = solver.evaluate_case(case, store, identities)
        results.append(
            {
                "case_id": case["case_id"],
                "expected_status": expected_status,
                "actual_status": status,
                "steps": len(steps),
                "note": note,
                "passed": status == expected_status and predicate(steps),
            }
        )

    matched, total, unique = _block_accounts_match(store, identities)
    results.append(
        {
            "case_id": "custom_07",
            "expected_status": f"{total}/{total} accounts",
            "actual_status": f"{matched}/{total} accounts",
            "steps": 0,
            "note": "block account attribution is one-to-one and status-compatible",
            "passed": matched == total and unique,
        }
    )
    return results


def _ordered_remediation(steps: list[dict]) -> bool:
    remediation = [step["operation"] for step in steps if step["phase"] == "REMEDIATION"]
    if "DISABLE_DATA_FLOW" not in remediation:
        return False
    flow_at = remediation.index("DISABLE_DATA_FLOW")
    record_ops = {"DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD"}
    return all(
        operation not in record_ops or index > flow_at
        for index, operation in enumerate(remediation)
    )


def main() -> int:
    want, got = load_sample_predictions()
    metrics = score_sample(want, got)
    store = solver.EvidenceStore()
    store.load_all()
    identities = solver.Identities()
    custom = custom_cases(store, identities)

    print(json.dumps({"sample": metrics, "custom": custom}, indent=2))
    failures = [case for case in custom if not case["passed"]]
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
