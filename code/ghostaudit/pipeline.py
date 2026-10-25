"""Case orchestration: attribution, evaluation and CSV output."""
from __future__ import annotations

import csv
import json
from pathlib import Path

from .attribution import assign_block_accounts, assign_unlinked_analytics
from .config import DATASET
from .evidence import EvidenceStore
from .identities import Identities
from .model import read_csv
from .policy import evaluate_case


def build_rows(
    cases: list[dict[str, str]],
    store: EvidenceStore,
    identities: Identities,
    dataset: Path = DATASET,
) -> list[dict[str, str]]:
    # Blocks are a property of the whole request stream, so include both the
    # public sample requests and the evaluation requests when attributing
    # block-wide analytics records.
    universe: dict[str, dict[str, str]] = {}
    for filename in ("sample_deletion_requests.csv", "deletion_requests.csv"):
        path = dataset / filename
        if not path.exists():
            continue
        for row in read_csv(path):
            universe[row["case_id"]] = row
    for row in cases:
        universe[row["case_id"]] = row
    universe_cases = list(universe.values())

    account_hints = assign_block_accounts(universe_cases, store, identities)
    initial_eval = {
        case["case_id"]: evaluate_case(
            case, store, identities, (), account_hints.get(case["case_id"])
        )
        for case in universe_cases
    }
    statuses = {case_id: res[0] for case_id, res in initial_eval.items()}
    assignment = assign_unlinked_analytics(universe_cases, store, identities, statuses)
    rows: list[dict[str, str]] = []
    for case in sorted(cases, key=lambda item: int(item["case_id"].split("_")[1])):
        cid = case["case_id"]
        extra = assignment.get(cid, ())
        if extra or cid not in initial_eval:
            status, steps = evaluate_case(
                case,
                store,
                identities,
                extra,
                account_hints.get(cid),
            )
        else:
            status, steps = initial_eval[cid]
        rows.append(
            {
                "case_id": cid,
                "deletion_status": status,
                "steps_json": json.dumps(steps, separators=(",", ":"), ensure_ascii=False),
            }
        )
    return rows


def write_output(rows: list[dict[str, str]], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader()
        writer.writerows(rows)
