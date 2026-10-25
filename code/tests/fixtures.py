"""Shared fixtures for the unit tests (standard library only)."""

from __future__ import annotations

import csv
import json
from pathlib import Path

UTC = "+00:00"


def write_csv(path: Path, header: list[str], rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        writer.writerows(rows)


def identity_dataset(root: Path) -> Path:
    """Two users, one of whom changed address in the audit log."""
    write_csv(
        root / "user_identities.csv",
        ["user_id", "name", "email", "phone", "email_hash", "updated_at"],
        [
            ["user_1", "Ada Example", "ada@example.com", "+1 555 010 1000", "a" * 64, "2026-01-02T00:00:00Z"],
            ["user_2", "Bea Example", "bea@example.com", "+1 555 010 2000", "b" * 64, "2026-01-03T00:00:00Z"],
        ],
    )
    write_csv(
        root / "user_audit_log.csv",
        ["audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"],
        [
            ["audit_1", "user_1", "2025-06-01T00:00:00Z", "email", "ada.old@example.com", "ada@example.com"],
            ["audit_2", "user_2", "2025-06-02T00:00:00Z", "phone", "+1 555 010 9999", "+1 555 010 2000"],
        ],
    )
    return root


def evidence_dataset(root: Path) -> Path:
    """One JSON snapshot, one log line, and one manifest entry for each."""
    (root / "evidence").mkdir(parents=True, exist_ok=True)
    snapshot = {
        "snapshots": [
            {
                "captured_at": "2026-03-01T10:00:00Z",
                "data_store": "account_service",
                "collection": "customer_profiles",
                "records": [
                    {
                        "resource_id": "account_001",
                        "email": "ada@example.com",
                        "user_id": "user_1",
                    }
                ],
            }
        ]
    }
    (root / "evidence" / "snapshot.json").write_text(json.dumps(snapshot), encoding="utf-8")
    (root / "evidence" / "events.log").write_text(
        "2026-03-01T10:05:00Z [INFO] [search_service] [trace_1] index_query_completed: "
        'resource_id=search_001 result=hit email="ada@example.com"\n',
        encoding="utf-8",
    )
    write_csv(
        root / "evidence_files.csv",
        ["file_id", "file_path", "origin", "captured_at"],
        [
            ["evidence_01", "evidence/snapshot.json", "records_assurance_snapshot_bundle", "2026-03-01T10:00:00Z"],
            ["evidence_02", "evidence/events.log", "central_observability_export", "2026-03-01T10:05:00Z"],
            ["evidence_03", "evidence/missing.json", "client_capture", "2026-03-01T10:06:00Z"],
        ],
    )
    write_csv(
        root / "system_activity.csv",
        ["activity_id", "event_time", "event_type", "source_system", "target_system", "resource_id", "reported_result", "details"],
        [
            [
                "activity_1",
                "2026-03-01T10:10:00Z",
                "LINK_RESOURCE_IDENTITY",
                "data_catalog",
                "account_service",
                "account_001",
                "SUCCESS",
                "Linked account_001 to user_1 (ada@example.com).",
            ]
        ],
    )
    return root
