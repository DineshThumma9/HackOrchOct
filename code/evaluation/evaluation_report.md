# Evaluation Report — Ghost Data Still Exists

## 1. What was evaluated

The public calibration set contains 32 labelled cases (`dataset/sample_deletion_requests.csv`)
with reference answers in `dataset/sample_output.csv`. The final run covers all 518
evaluation requests in `dataset/deletion_requests.csv`.

The solver is deterministic. It loads every participant-visible evidence file, normalises
each record into an observation with a system, resource, category, observation time and
capture time, links observations to subjects through current and historical identifiers,
and then evaluates each case at its `audit_at` cutoff.

Run the evaluation harness from the repository root:

```bash
python3 code/evaluation/main.py
python3 code/evaluation/validate_output.py
```

`main.py` scores the public sample and runs the participant-authored cases.
`validate_output.py` independently checks `output.csv` against the submission contract:
row coverage, ordering, step numbering, allowed operations and states, phase order,
evidence eligibility, remediation order, and verification coverage.

## 2. Sample results

| Metric | Result |
|---|---|
| Case-level deletion-status accuracy | **32 / 32 = 100.0%** |
| Exact `steps_json` match | **30 / 32 = 93.8%** |
| Exact ordered step sequence (phase, system, resource, operation, state) | 30 / 32 = 93.8% |
| Step count match | 30 / 32 = 93.8% |
| Step precision (aligned by full step key) | 100.0% |
| Step recall (aligned by full step key) | 98.96% |
| Mean longest-common-subsequence ratio | 0.9968 |
| Positional field accuracy — `phase` | 100.0% |
| Positional field accuracy — `system_id` | 97.9% |
| Positional field accuracy — `resource_id` | 97.9% |
| Positional field accuracy — `operation` | 97.9% |
| Positional field accuracy — `state` | 97.9% |
| Positional field accuracy — `evidence_id` | 100.0% |

The two remaining exact-match failures are both missing retained audit records:

| Case | Difference | Cause |
|---|---|---|
| `case_18` | One missing `VERIFY_RECORD_PRESENT` step for `audit_record_6645` | The record id is not present in any participant-visible file. |
| `case_20` | One missing `VERIFY_RECORD_PRESENT` step for `audit_record_5569` | Same: the record exists only in the private truth. |

All statuses remain correct. Every other field of those two cases matches the reference,
and all account resource ids — including the previously uncertain `case_21`, `case_22`
and `case_23` — now match.

## 3. Full-dataset run

| Metric | Result |
|---|---|
| Requests processed | 518 |
| Output rows written | 518 |
| `COMPLETE` | 169 |
| `INCOMPLETE` | 339 |
| `NOT_APPLICABLE` | 10 |
| Steps emitted | 3,056 |
| Valid JSON rows | 518 / 518 |
| Rows sorted by `case_id` | Yes (numeric order) |
| Consecutive `step_no` values | Yes |
| Phase order `FINDING → REMEDIATION → VERIFICATION` | Yes |
| Contract validator | Pass (0 errors) |
| Evidence observations parsed | 2,472 from 88 files |
| Wall-clock runtime | ~2.45 seconds |
| Output size | 611,762 bytes |

The ten `NOT_APPLICABLE` rows are exactly `case_533`–`case_542`: a profile correction,
a marketing opt-out, a data-portability download, a login reset, a surname correction,
a marketing-only removal, an access request, an invoice copy, an email change, and a
copy request. None authorises deletion.

## 4. Participant-authored evaluation cases

Seven additional checks exercise behaviour that the sample does not cover directly.
Each is constructed from real participant evidence. `custom_06` replays the real
`case_479` envelope; `custom_07` compares block account attribution with the 32 labelled
sample accounts. The harness reports all seven as passing.

| Case | Scenario | Expected | Observed | Result |
|---|---|---|---|---|
| `custom_01` | Marketing opt-out: "remove me from marketing lists only" | `NOT_APPLICABLE`, `[]` | `NOT_APPLICABLE`, `[]` | Pass |
| `custom_02` | Access request: "send me a copy of the information held on my account" | `NOT_APPLICABLE`, `[]` | `NOT_APPLICABLE`, `[]` | Pass |
| `custom_03` | Portuguese deletion request ("Solicito a exclusão permanente…") | Authorised deletion; `INCOMPLETE` with findings | `INCOMPLETE`, 8 steps | Pass |
| `custom_04` | Account tombstone that still holds name, email, phone and email hash | `INCOMPLETE`; `REDACT_RECORD` on the tombstone, never `DELETE_RECORD` | `INCOMPLETE`, 5 steps, `REDACT_RECORD` for `tombstone_9178` | Pass |
| `custom_05` | Deletion with an active integration connector | `INCOMPLETE`; `DISABLE_DATA_FLOW` before record-level remediation | `INCOMPLETE`, 13 steps, flow disabled before `DELETE_RECORD` | Pass |
| `custom_06` | Support attachment whose only subject link is `uploaded_by` | `INCOMPLETE`; finding for `support_4665` citing `evidence_45` | `INCOMPLETE`, 5 steps, matching finding | Pass |
| `custom_07` | One-to-one account attribution inside workflow blocks | 32/32 sample accounts, no duplicates | 32/32 accounts, all unique | Pass |

## 5. Failures found and improvements made

1. **Non-deletion requests were being treated as deletion requests.**
   The first intent classifier looked for a deletion verb anywhere in the text. Phrases
   such as "not asking for deletion", "do not close the account" and "remove me from
   marketing lists only" therefore produced deletion cases. The classifier now checks
   retention/refusal phrases first, then account-directed deletion phrases, then
   non-deletion intent, and only then a generic deletion stem.

2. **Portuguese deletion requests were being marked `NOT_APPLICABLE`.**
   The Portuguese template uses the noun *exclusão*, which the original `excluir`
   pattern did not match. Multilingual stems (`exclusão`, `eliminar`, `löschen`,
   `supprimer`, `削除`, `삭제`, `删除`, …) are now recognised. This restored the 14
   Portuguese evaluation cases that had been incorrectly excluded.

3. **Pre-request evidence was being attributed to a later deletion.**
   `object_19` (a support attachment captured 2026-02-13) and `tombstone_17`
   (captured 2026-03-10) predate their subjects' requests. They are now ignored when
   the observation is older than `requested_at`.

4. **Anonymised analytics records with no identifier were unassigned.**
   Snapshot bundles and readback logs preserve the block's subject order. The solver
   now attributes an unlinked anonymised analytics record to the block's compliant
   cases in that order, which fixed `case_03 → analytics_9406` and
   `case_04 → analytics_901`.

5. **Accounts were being confused across subjects in the same workflow batch.**
   A nearest-event heuristic could hand one subject's surviving account to another.
   The solver now builds an account-owner index from every identifier-bearing record
   and assigns a block's unclaimed account events one-to-one. The candidate window is
   the observed `-90..-30` minute offset before `reported_at`; cases are matched in
   reverse request order and the event result must agree with the reported status
   (`COMPLETE→SUCCESS`, `PARTIALLY_COMPLETE→PARTIAL/SUCCESS`,
   `NOT_STARTED→FAILED`). This fixed the `case_18` / `case_20` account split,
   corrected `case_21`–`case_23` (`account_6440`, `account_4990`, `account_410`),
   corrected the `case_417` / `case_418` swap (`case_417` is now `INCOMPLETE` because
   its `FAILED` account was still present at audit), and removed 100+ incorrect
   account verification ids. The public sample scores 32/32 on account ids.

6. **Post-audit files could be cited as proof.**
   State reconstruction and citation selection now require both the record observation
   time and the manifest capture time to be at or before `audit_at`. A post-audit file
   may still be used for discovery (for example a later readback that reveals the
   account id), but it never changes the reconstructed state and is never cited as
   evidence for the answer. This fixed `case_126`, where a stale 2026-08-11 snapshot
   inside a bundle exported on 2026-08-19 was overriding the empty account snapshot
   captured at `audit_at`; the case now correctly resolves to `COMPLETE`.

7. **`reported_status` and activity results were not accepted as proof.**
   The state is reconstructed from record-level evidence. A `SUCCESS` deletion event
   does not by itself prove absence, and a `COMPLETE` workflow status does not override
   a surviving record.

8. **Support attachments linked only through uploader or scan identifiers were missed.**
   `obs_from_record` only extracted identifiers from a short list of email fields, so
   attachments that carried the subject only in `uploaded_by`, `matched_value` or
   `scan_key` were invisible. Those fields are now parsed (with a phone guard so a
   numeric scan key is not mistaken for an email). This linked 13 attachments:
   `support_8903`, `support_4952`, `support_2537`, `support_3802` and `support_2055`
   gained `REPORT_REMAINING_RECORD` findings, while `case_479` and `case_503` moved
   from `COMPLETE` to `INCOMPLETE` because their subject-owned attachment was still
   present at audit. `custom_06` locks this behaviour in.

9. **The output contract was only checked by ad-hoc scripts.**
   `code/evaluation/validate_output.py` now performs an independent contract pass over
   all 518 rows: exact header, one row per request, numeric ordering, unique case ids,
   consecutive step numbers, allowed operation/state pairs, phase order, finding and
   remediation evidence rules, post-audit citation rejection, flow/restore ordering,
   remediation-to-finding coverage, and remediation-to-verification coverage. It reports
   zero errors on the submitted `output.csv`.

## 6. Known limitations

- Two retained audit record ids (`audit_record_6645`, `audit_record_5569`) are only in
  the private truth. The solver reports the correct state and operation for `case_18`
  and `case_20` but cannot name those two records, so one verification step is missing
  from each case. This is the only remaining sample difference.
- Account ids for subjects with no identifier-bearing account record are recovered from
  workflow-block events. The rule is validated on all 32 sample accounts, but a hidden
  block whose request order or event-result mix differs from the observed generator
  pattern could still be attributed incorrectly.
- Anonymised analytics records that carry no identifier are attributed by block order.
  When a block contains more compliant cases than unlinked records, the remaining cases
  simply receive no analytics verification step.
- The solver is rule-based and does not call an external model at inference time, so
  there is no token or cost variance between runs. Local models were used only during
  development to cross-check multilingual intent and visual evidence; see
  `usage_report.md`.
