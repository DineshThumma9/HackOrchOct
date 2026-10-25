"""Development helper: index evidence into ``master_evidence.db``.

Run:
    python3 code/build_evidence_db.py

Output:
    master_evidence.db  (SQLite, repository root)

This file used to carry its own SQL/JSON/log parsers, which drifted from the
solver's.  It now reuses :class:`ghostaudit.EvidenceStore` and only projects the
normalised observations into a flat table for ad-hoc SQL exploration.  The
solver never imports this module.
"""

from __future__ import annotations

import csv
import json
import sqlite3
from pathlib import Path

from ghostaudit import DATASET, EvidenceStore, Obs, boolish

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "master_evidence.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS evidence_records (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id         TEXT NOT NULL,
    captured_at     TEXT NOT NULL,
    resource_id     TEXT,
    system_id       TEXT,
    collection      TEXT,
    user_ref        TEXT,
    email           TEXT,
    phone           TEXT,
    email_hash      TEXT,
    enabled         INTEGER,
    restore_allowed INTEGER,
    retention_until TEXT,
    record_json     TEXT
);
CREATE INDEX IF NOT EXISTS idx_email      ON evidence_records(email);
CREATE INDEX IF NOT EXISTS idx_user_ref   ON evidence_records(user_ref);
CREATE INDEX IF NOT EXISTS idx_email_hash ON evidence_records(email_hash);
CREATE INDEX IF NOT EXISTS idx_resource   ON evidence_records(resource_id);
CREATE INDEX IF NOT EXISTS idx_captured   ON evidence_records(captured_at);
CREATE INDEX IF NOT EXISTS idx_file_id    ON evidence_records(file_id);

CREATE TABLE IF NOT EXISTS deletion_requests (
    case_id TEXT PRIMARY KEY, email TEXT, requested_at TEXT,
    reported_status TEXT, reported_at TEXT, audit_at TEXT, request_text TEXT
);
CREATE TABLE IF NOT EXISTS user_identities (
    user_id TEXT PRIMARY KEY, name TEXT, email TEXT, phone TEXT,
    email_hash TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS user_audit_log (
    audit_id TEXT PRIMARY KEY, user_id TEXT, event_time TEXT,
    field_name TEXT, old_value TEXT, new_value TEXT
);
CREATE TABLE IF NOT EXISTS system_activity (
    activity_id TEXT PRIMARY KEY, event_time TEXT, event_type TEXT,
    source_system TEXT, target_system TEXT, resource_id TEXT,
    reported_result TEXT, details TEXT
);
CREATE TABLE IF NOT EXISTS deletion_rules (
    rule_id TEXT PRIMARY KEY, data_category TEXT, condition TEXT, required_action TEXT
);
"""

FLAG_COLUMNS = ("enabled", "restore_allowed")


def flag(obs: Obs, name: str) -> int | None:
    value = boolish(obs.attrs.get(name))
    return None if value is None else int(value)


def first(values: set[str]) -> str | None:
    return sorted(values)[0] if values else None


def collection_of(obs: Obs) -> str:
    attrs = obs.attrs
    return str(attrs.get("collection_name") or attrs.get("collection") or obs.category)


def insert_observation(cur: sqlite3.Cursor, obs: Obs) -> None:
    cur.execute(
        """
        INSERT INTO evidence_records
        (file_id, captured_at, resource_id, system_id, collection, user_ref,
         email, phone, email_hash, enabled, restore_allowed, retention_until,
         record_json)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            obs.file_id,
            obs.observed_at.isoformat(),
            obs.resource_id,
            obs.system,
            collection_of(obs),
            obs.user_ref or None,
            first(obs.emails),
            first(obs.phones),
            first(obs.hashes),
            flag(obs, "enabled"),
            flag(obs, "restore_allowed"),
            obs.attrs.get("retention_until"),
            json.dumps(obs.attrs, default=str),
        ),
    )


def load_csv_table(conn: sqlite3.Connection, path: Path, table: str) -> int:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        return 0
    columns = list(rows[0])
    placeholders = ",".join("?" for _ in columns)
    conn.executemany(
        f'INSERT OR REPLACE INTO "{table}" ({",".join(columns)}) VALUES ({placeholders})',
        [[row[column] for column in columns] for row in rows],
    )
    conn.commit()
    print(f"  Loaded {len(rows):>5} rows  ->  {table}")
    return len(rows)


def main() -> int:
    print(f"Building {DB_PATH} ...")
    if DB_PATH.exists():
        DB_PATH.unlink()
        print("  Removed old DB.")

    store = EvidenceStore()
    print("Parsing evidence ...")
    store.load_all()
    for message in store.errors:
        print(f"  WARN {message}")

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    conn.executescript(SCHEMA)

    print("\n[1/3] Loading dataset CSVs ...")
    for filename, table in (
        ("deletion_requests.csv", "deletion_requests"),
        ("user_identities.csv", "user_identities"),
        ("user_audit_log.csv", "user_audit_log"),
        ("system_activity.csv", "system_activity"),
        ("deletion_rules.csv", "deletion_rules"),
    ):
        path = DATASET / filename
        if path.exists():
            load_csv_table(conn, path, table)

    print("\n[2/3] Projecting parsed observations ...")
    for obs in store.obs:
        insert_observation(cur, obs)
    conn.commit()

    total = cur.execute("SELECT COUNT(*) FROM evidence_records").fetchone()[0]
    print(f"\n[3/3] Done.  {len(store.by_file)} files, {total:,} evidence rows")
    print(f"\nDB written -> {DB_PATH}")
    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
