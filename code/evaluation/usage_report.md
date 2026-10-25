# Usage Report — Ghost Data Still Exists

## 1. Final full-dataset run

| Item | Value |
|---|---|
| Run command | `python3 code/main.py` |
| Run date | 2026-10-25 |
| Python version | 3.14.8 |
| Input file | `dataset/deletion_requests.csv` |
| Requests processed | 518 |
| Output file | `output.csv` (repository root) |
| Output rows | 518 (header + 518 data rows) |
| Steps emitted | 3,056 |
| Evidence observations parsed | 2,472 from 88 files |
| Wall-clock runtime | 2.45 s |
| Output size | 611,762 bytes |

Status distribution: **169 `COMPLETE`**, **339 `INCOMPLETE`**, **10 `NOT_APPLICABLE`**.

The contract validator also passes on this output:

```bash
python3 code/evaluation/validate_output.py
# OK output.csv satisfies the contract checks
```

## 2. Model usage in the submitted run

The submitted solver does **not** call a language model at inference time. It is a
deterministic, rule-based audit pipeline built on the Python standard library: CSV and
JSON parsing, SQL snapshot execution through `sqlite3`, regular-expression identity
matching, and a policy engine driven by `dataset/deletion_rules.csv`.

| Provider | Model | Calls | Input tokens | Output tokens | Total tokens | Estimated cost |
|---|---|---|---|---|---|---|
| none | none | 0 | 0 | 0 | 0 | $0.00 |
| **Total** | | **0** | **0** | **0** | **0** | **$0.00** |

Per-request usage:

| Metric | Value |
|---|---|
| Model calls per request | 0 |
| Average input tokens per request | 0 |
| Average output tokens per request | 0 |
| Average total tokens per request | 0 |
| Average cost per request | $0.00 |

Because no model provider is configured, there is no API key, no network access, no
rate limit, and no token or cost variance between runs. Repeated runs over the same
dataset produce byte-identical output.

## 3. Development-time model checks

Local Ollama models were used only to validate design decisions; they are not part of
the runtime and are not required to reproduce `output.csv`.

| Model | Use | Calls | Result |
|---|---|---|---|
| `tev1:4b` | Multilingual intent cross-check on the 12 distinct request texts that contain retention or non-deletion wording | 12 | 12/12 agreement with the deterministic classifier, including two deletion requests that quote "download" or "access" wording |
| `d3:4b` | Vision capability test on one 1920 px screenshot | 1 | Accepted the image and returned an answer, but took ~221 s and ~3.3 k input tokens; too slow for routine use |

The tev1 run took ~119 seconds in total on local hardware. These calls belong to the
authoring session, not to the full-dataset run, so they are not attributed to any
request in section 2. No API keys, cloud providers, or paid tokens were used.

## 4. Why the runtime has no model calls

The hidden evaluation has to run without Ollama, PaddleOCR, or network access, and the
answer must be reproducible. The final design therefore keeps models out of the
critical path:

- intent is decided by a deterministic multilingual classifier, with tev1 used only to
  confirm the ambiguous cases during development;
- screenshots and PDFs are represented as explicit transcribed facts in
  `code/visual_evidence.py`, so the grader does not need an OCR engine;
- policy application, resource linking, remediation ordering, and verification are
  deterministic and driven by participant-visible evidence.

## 5. Reproducing the numbers

```bash
# From the repository root
python3 code/main.py                     # writes output.csv
python3 code/evaluation/main.py          # sample metrics + participant-authored cases
python3 code/evaluation/validate_output.py  # independent contract checks
```

The evaluation harness re-runs the solver in memory and reports the metrics recorded in
`evaluation/evaluation_report.md`. None of these commands performs a model call.
