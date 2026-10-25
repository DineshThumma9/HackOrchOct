# Ghost Data Still Exists — Deletion Audit Agent

A deterministic deletion-audit agent for the HackerRank Orchestrate October 2026
challenge. For each request it decides whether deletion was authorised, reconstructs the
true state of every relevant record at the case's `audit_at`, applies the supplied
deletion policy, and emits findings, an ordered remediation plan, and verification
checks.

## Requirements

- Python 3.10 or newer (developed and tested on Python 3.14).
- No third-party packages. Everything uses the standard library (`csv`, `json`,
  `sqlite3`, `re`, `dataclasses`, `pathlib`).
- No API keys, environment variables, or network access are required.

## Setup

From the repository root:

```bash
cd hackerrank-orchestrate-october26
# Nothing to install.
```

The solver expects the participant dataset at `dataset/`, including
`dataset/deletion_requests.csv` and `dataset/evidence/`. Paths are resolved relative to
the repository root, so the code works on Linux, macOS, and Windows without edits.

## Run

```bash
python3 code/main.py
```

This writes `output.csv` at the repository root with the exact columns:

```text
case_id,deletion_status,steps_json
```

- One row per `case_id` in `dataset/deletion_requests.csv` (518 rows).
- Rows sorted by `case_id`.
- `deletion_status` is `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`.
- `steps_json` is a compact JSON array ordered `FINDING` → `REMEDIATION` →
  `VERIFICATION`, with consecutive `step_no` values starting at 1.

Optional sample scoring (writes `sample_output_pred.csv` and prints metrics):

```bash
python3 code/main.py --sample
```

Evaluation harness and contract checks:

```bash
python3 code/evaluation/main.py
python3 code/evaluation/validate_output.py
```

## How it works

1. **Identity resolution** (`Identities`). Loads `user_identities.csv` and
   `user_audit_log.csv`, then maps current and historical emails, phones, email hashes,
   and the stable `user_id` to one subject. A request email may be an old address.
2. **Evidence parsing** (`EvidenceStore`). Reads every file listed in
   `evidence_files.csv`:
   - SQL snapshots are executed in an in-memory SQLite database; every table row becomes
     an observation with its own timestamp.
   - JSON/JSONL, CSV, and plain-text logs are parsed into records.
   - PDFs and PNG screenshots are represented as transcribed facts in
     `visual_evidence.py`, keyed by `file_id`.
   Each observation records system, resource id, data category, identifiers, state,
   observation time, and file capture time.
3. **State reconstruction**. Only observations at or before `audit_at` are eligible.
   Observations are collapsed per resource to their latest state. Workflow statuses and
   activity `result` fields are treated as claims, not proof.
4. **Policy application**. `deletion_rules.csv` decides, per category and condition,
   whether a record must be deleted, redacted, anonymised, retained, or preserved as an
   account tombstone. Tombstones keep the stable reference and lose direct identifiers.
5. **Findings and remediation**. Surviving records become `REPORT_REMAINING_RECORD` or
   `REPORT_EXPOSED_PII` findings. Active sync/import connectors become
   `REPORT_ACTIVE_DATA_FLOW`, unsafe backup paths become `REPORT_RESTORE_RISK`.
   Remediation disables flows and blocks restores before record changes, then deletes,
   redacts, or anonymises the affected records. Verification covers each final state.
   Support attachments are linked through `uploaded_by`, `matched_value`, and `scan_key`
   as well as the usual email, phone, and subject-reference fields.
6. **Intent classification**. Refusal/retention phrases win first, then account-directed
   deletion phrases, then non-deletion intents (access, correction, export, marketing
   opt-out, login help), then multilingual deletion stems. Non-deletion requests are
   `NOT_APPLICABLE` with `steps_json=[]`.
7. **Citation selection**. Findings and `COMPLETE`-case verification cite the
   participant-visible `file_id`, `activity_id`, or `audit_id` that proves the state,
   preferring records captured at or before `audit_at`. Remediation and future
   verification steps for `INCOMPLETE` cases use an empty `evidence_id`.

## Files

```text
code/
├── main.py                  # solver: parsing, identity linking, policy engine, output
├── visual_evidence.py       # transcribed facts from PDFs and PNG screenshots
├── evaluation/
│   ├── main.py              # sample scorer + participant-authored cases
│   ├── validate_output.py   # independent contract checks for output.csv
│   ├── evaluation_report.md # required evaluation report
│   └── usage_report.md      # required usage report
└── README.md
```

`code/build_evidence_db.py` is an optional development helper that indexes raw evidence
into SQLite for exploration. It is **not** used by the solver and is not required at
runtime.

## Output contract

Each step has exactly these fields:

```json
{
  "step_no": 1,
  "phase": "FINDING",
  "system_id": "account_service",
  "resource_id": "account_005",
  "operation": "REPORT_REMAINING_RECORD",
  "state": "PRESENT",
  "evidence_id": "evidence_01"
}
```

Allowed phases: `FINDING`, `REMEDIATION`, `VERIFICATION`. Operations and states follow
the challenge tables exactly; no additional values are invented.

## Determinism

All iteration is sorted before it affects output, identifiers are normalised to
lowercase, and timestamps are parsed to UTC. Running the solver twice on the same
dataset produces byte-identical `output.csv`.

## Evaluation summary

On the 32 public sample cases:

- deletion-status accuracy: **32/32 (100%)**
- exact `steps_json`: **30/32 (93.8%)**
- mean step-sequence LCS ratio: **0.9968**
- step precision / recall: **100% / 98.96%**
- positional field accuracy: **97.9%–100%** per field

The two remaining exact-match differences are missing retained audit-record ids
(`audit_record_6645` and `audit_record_5569`) that do not appear in any
participant-visible file. All account ids, including the previously uncertain
`case_21`–`case_23`, now match. See `evaluation/evaluation_report.md` for details,
seven participant-authored cases, and the failure/improvement log.

## Submission

Challenge and submission URL:

https://www.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists

The submission uses `code.zip` (this directory, excluding `dataset/`, caches, and
`master_evidence.db`), the generated `output.csv`, and the root `log.txt` transcript.
