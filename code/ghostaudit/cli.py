"""Command line entry point."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from .config import DATASET, ROOT
from .evidence import EvidenceStore
from .identities import Identities
from .intent import check_tev_available
from .model import read_csv
from .pipeline import build_rows, write_output


def score_sample(rows: list[dict[str, str]], dataset: Path = DATASET) -> None:
    expected = {row["case_id"]: row for row in read_csv(dataset / "sample_output.csv")}
    predicted = {row["case_id"]: row for row in rows}
    status_ok = 0
    steps_ok = 0
    for case_id, want in expected.items():
        got = predicted.get(case_id)
        if not got:
            continue
        if got["deletion_status"] == want["deletion_status"]:
            status_ok += 1
        if json.loads(got["steps_json"]) == json.loads(want["steps_json"]):
            steps_ok += 1
    total = len(expected)
    print(f"sample status accuracy: {status_ok}/{total} = {status_ok / total:.1%}")
    print(f"sample exact steps:     {steps_ok}/{total} = {steps_ok / total:.1%}")
    for case_id in sorted(expected, key=lambda cid: int(cid.split("_")[1])):
        want = expected[case_id]
        got = predicted.get(case_id)
        if not got:
            continue
        mark = "OK " if got["deletion_status"] == want["deletion_status"] else "BAD"
        if got["deletion_status"] != want["deletion_status"] or json.loads(got["steps_json"]) != json.loads(want["steps_json"]):
            print(f"  {mark} {case_id}: want {want['deletion_status']:9} got {got['deletion_status']:9}")
            print(f"       want {want['steps_json']}")
            print(f"       got  {got['steps_json']}")


def main() -> int:
    if "--regex" in sys.argv:
        import os
        os.environ["USE_REGEX"] = "1"
        print("Using deterministic regex engine (--regex specified)...", file=sys.stderr)
    elif check_tev_available():
        print("Primary intent engine active: tev1:4b via Ollama /v1/systemone (with deterministic fallback)", file=sys.stderr)
    else:
        print("Tev decision model not detected on localhost:11434; active engine: deterministic fallback", file=sys.stderr)

    store = EvidenceStore()
    print("Loading evidence...", file=sys.stderr)
    store.load_all()
    print(f"  {len(store.obs)} observations from {len(store.by_file)} files", file=sys.stderr)
    for message in store.errors:
        print(f"  WARN {message}", file=sys.stderr)
    identities = Identities()

    if "--sample" in sys.argv:
        cases = read_csv(DATASET / "sample_deletion_requests.csv")
        rows = build_rows(cases, store, identities)
        write_output(rows, ROOT / "sample_output_pred.csv")
        score_sample(rows)
        return 0

    cases = read_csv(DATASET / "deletion_requests.csv")
    rows = build_rows(cases, store, identities)
    write_output(rows, ROOT / "output.csv")
    print(f"Wrote {len(rows)} rows to {ROOT / 'output.csv'}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
