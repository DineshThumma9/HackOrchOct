"""
ETL: Load all evidence files + dataset CSVs into master_evidence.db

Run:  python3 code/build_evidence_db.py
Out:  master_evidence.db  (SQLite, at repo root)
"""

import sqlite3, json, csv, re, glob, os, subprocess
from pathlib import Path

ROOT = Path(__file__).parent.parent
DATASET = ROOT / "dataset"
DB_PATH = ROOT / "master_evidence.db"


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
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


def init_db(conn):
    conn.executescript(SCHEMA)
    conn.commit()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def insert_record(cur, file_id, captured_at, resource_id, system_id,
                  collection, user_ref, email, phone, email_hash,
                  enabled, restore_allowed, retention_until, record_json):
    cur.execute("""
        INSERT INTO evidence_records
        (file_id, captured_at, resource_id, system_id, collection,
         user_ref, email, phone, email_hash, enabled, restore_allowed,
         retention_until, record_json)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        file_id, captured_at,
        resource_id, system_id, collection,
        user_ref,
        email.lower().strip() if email else None,
        phone,
        email_hash.lower().strip() if email_hash else None,
        enabled, restore_allowed, retention_until,
        json.dumps(record_json) if not isinstance(record_json, str) else record_json
    ))


def load_evidence_manifest():
    manifest = {}
    with open(DATASET / "evidence_files.csv") as f:
        for row in csv.DictReader(f):
            manifest[row["file_id"]] = {
                "file_path": DATASET / row["file_path"],
                "captured_at": row["captured_at"],
            }
    return manifest


# ---------------------------------------------------------------------------
# SQL loaders
# ---------------------------------------------------------------------------
def load_sql_file(conn, cur, file_id, captured_at, sql_path):
    tmp = sqlite3.connect(":memory:")
    try:
        with open(sql_path) as f:
            sql = f.read()
        tmp.executescript(sql)
    except Exception as e:
        print(f"  [WARN] SQL parse error in {sql_path.name}: {e}")
        tmp.close()
        return

    tables = [r[0] for r in
              tmp.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]

    for table in tables:
        if table == "snapshot_scope":
            continue
        try:
            rows = tmp.execute(f'SELECT * FROM "{table}"').fetchall()
            cols = [d[0] for d in tmp.execute(f'SELECT * FROM "{table}" LIMIT 0').description]
        except Exception as e:
            print(f"  [WARN] reading table {table}: {e}")
            continue
        for row in rows:
            rec = dict(zip(cols, row))
            _ingest_sql_row(cur, file_id, captured_at, table, rec)

    tmp.close()
    conn.commit()


def _ingest_sql_row(cur, file_id, captured_at, table, rec):
    resource_id = rec.get("resource_id")

    # JSON-blob tables
    if "record_json" in rec and "origin_system" in rec:
        try:
            inner = json.loads(rec["record_json"])
        except Exception:
            inner = {}
        _ingest_inner_json(cur, file_id, captured_at,
                           inner.get("resource_id", resource_id),
                           rec.get("origin_system"),
                           rec.get("collection_name"),
                           inner, rec["record_json"])
        return

    # Flat account profile tables
    if table in ("customer_profiles_failover_replica", "customer_profiles_primary"):
        insert_record(cur, file_id, captured_at,
                      resource_id, "account_service", "customer_profiles",
                      rec.get("user_id"), rec.get("email"), rec.get("phone"),
                      None, None, None, None, json.dumps(rec))
        return

    _map = {
        "customer_profiles":
            ("account_service", "customer_profiles",
             rec.get("customer_reference"), rec.get("email"), rec.get("phone"), rec.get("email_hash"),
             None, None, None),
        "customer_search_documents":
            ("search_service", "customer_search_documents",
             rec.get("customer_reference"), rec.get("email"), rec.get("phone"), rec.get("email_hash"),
             None, None, None),
        "customer_analytics_profiles":
            ("analytics_platform", "customer_analytics_profiles",
             rec.get("customer_reference"), rec.get("email"), rec.get("phone"), rec.get("email_hash"),
             None, None, None),
        "support_records":
            ("support_platform", "support_conversations",
             rec.get("customer_reference"), rec.get("requester_email"), rec.get("requester_phone"),
             None, None, None, None),
        "customer_exports":
            ("export_service", "customer_exports",
             rec.get("customer_reference"), rec.get("owner_email"), rec.get("owner_phone"),
             None, None, None, None),
        "connector_subscriptions":
            ("integration_service", "connector_subscriptions",
             rec.get("customer_reference"), rec.get("customer_email"), None,
             None, rec.get("enabled"), None, None),
        "backup_restore_entries":
            ("backup_service", "backup_restore_entries",
             rec.get("customer_reference"), rec.get("customer_email"), None,
             None, None, rec.get("restore_allowed"), None),
        "security_audit_records":
            ("security_service", "security_audit_events",
             rec.get("subject_reference"), None, None,
             None, None, None, rec.get("retention_until")),
        "search_documents_primary":
            ("search_service", "customer_search_documents",
             None, rec.get("email"), None, None, None, None, None),
    }

    if table in _map:
        vals = _map[table]
        system_id, collection = vals[0], vals[1]
        user_ref, email, phone, email_hash = vals[2], vals[3], vals[4], vals[5]
        enabled, restore_allowed, retention_until = vals[6], vals[7], vals[8]
        insert_record(cur, file_id, captured_at, resource_id, system_id, collection,
                      user_ref, email, phone, email_hash, enabled, restore_allowed,
                      retention_until, json.dumps(rec))


def _ingest_inner_json(cur, file_id, captured_at, resource_id, system_id, collection, inner, raw):
    user_ref = (inner.get("customer_reference") or inner.get("user_id")
                or inner.get("subject_reference"))
    email = (inner.get("email") or inner.get("owner_email")
             or inner.get("customer_email") or inner.get("requester_email")
             or inner.get("subject_selector"))
    phone = (inner.get("phone") or inner.get("requester_phone") or inner.get("owner_phone"))
    email_hash = inner.get("email_hash")

    enabled = None
    if "enabled" in inner:
        v = inner["enabled"]
        enabled = 1 if v is True or v == 1 else 0

    restore_allowed = None
    if "restore_allowed" in inner:
        v = inner["restore_allowed"]
        restore_allowed = 1 if v is True or v == 1 else 0

    retention_until = inner.get("retention_until")
    insert_record(cur, file_id, captured_at, resource_id, system_id, collection,
                  user_ref, email, phone, email_hash, enabled, restore_allowed,
                  retention_until, raw)


# ---------------------------------------------------------------------------
# JSON loaders
# ---------------------------------------------------------------------------
def load_json_file(cur, file_id, captured_at, json_path):
    with open(json_path) as f:
        data = json.load(f)

    # snapshot bundles
    if "snapshots" in data:
        for snap in data["snapshots"]:
            snap_ts = snap.get("captured_at", captured_at)
            system_id = snap.get("data_store")
            collection = snap.get("collection")
            for rec in snap.get("records", []):
                _ingest_inner_json(cur, file_id, snap_ts,
                                   rec.get("resource_id"), system_id, collection,
                                   rec, json.dumps(rec))

    # analytics / export jobs with collection key
    elif "collection" in data and "records" in data:
        system_id = data.get("source", "analytics_platform")
        collection = data.get("collection")
        for rec in data.get("records", []):
            resource_id = rec.get("resource_id")
            email = rec.get("owner_email") or rec.get("email")
            _ingest_inner_json(cur, file_id, captured_at,
                               resource_id, system_id, collection, rec, json.dumps(rec))

    # security ledger / connector manifest (has "origin" key)
    elif "records" in data and "origin" in data:
        for rec in data.get("records", []):
            resource_id = rec.get("resource_id")
            system_id = rec.get("system")
            subject = rec.get("subject_reference", "")
            email = subject if "@" in (subject or "") else None
            user_ref = subject if "@" not in (subject or "") else None
            insert_record(cur, file_id, rec.get("recorded_at", captured_at),
                          resource_id, system_id, rec.get("record_type"),
                          user_ref, email, None, None, None, None, None, json.dumps(rec))

    # service_resource_export
    elif "service_exports" in data:
        for system_id, payloads in data["service_exports"].items():
            if not isinstance(payloads, dict):
                continue
            for collection, records in payloads.items():
                if not isinstance(records, list):
                    continue
                for rec in records:
                    if not isinstance(rec, dict):
                        continue
                    observed_at = rec.get("observed_at", captured_at)
                    resource_id = rec.get("resource_id")
                    inner = rec.get("profile") or rec
                    if inner is None:
                        inner = {}
                    _ingest_inner_json(cur, file_id, observed_at,
                                       resource_id, system_id, collection,
                                       inner, json.dumps(rec))


# ---------------------------------------------------------------------------
# Log loader
# ---------------------------------------------------------------------------
LOG_KV  = re.compile(r'(\w+)="([^"]*)"')
LOG_KV2 = re.compile(r'(\w+)=(\S+)')

def load_log_file(cur, file_id, captured_at, log_path):
    with open(log_path, errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            kv = dict(LOG_KV.findall(line))
            kv.update({k: v for k, v in LOG_KV2.findall(line) if k not in kv})

            resource_id = kv.get("resource_id")
            if not resource_id:
                continue

            ts_match = re.match(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)', line)
            ts = ts_match.group(1) if ts_match else captured_at
            system_id = kv.get("service")
            email = (kv.get("matched_value") or kv.get("match_key")
                     or kv.get("correlation_key") or kv.get("lookup_key"))
            if email and "@" not in email:
                email = None

            insert_record(cur, file_id, ts, resource_id, system_id,
                          kv.get("event"), None, email, None, None,
                          None, None, None, json.dumps(kv))


# ---------------------------------------------------------------------------
# PDF loader
# ---------------------------------------------------------------------------
def load_pdf_file(cur, file_id, captured_at, pdf_path):
    try:
        import fitz
        doc = fitz.open(str(pdf_path))
        text = "\n".join(page.get_text() for page in doc)
    except ImportError:
        result = subprocess.run(["pdftotext", str(pdf_path), "-"],
                                capture_output=True, text=True)
        text = result.stdout if result.returncode == 0 else ""
    except Exception as e:
        print(f"  [WARN] PDF {pdf_path.name}: {e}")
        return

    if not text.strip():
        return

    emails     = re.findall(r'[\w.+-]+@[\w.-]+\.\w+', text)
    user_refs  = re.findall(r'\buser_\d+\b', text)
    res_ids    = re.findall(
        r'\b(?:account|search|analytics|support|export|backup|tombstone|audit_record|data_flow)_\w+\b',
        text)

    targets = list(dict.fromkeys(res_ids)) or [None]
    seen = set()
    for rid in targets:
        if rid in seen:
            continue
        seen.add(rid)
        insert_record(cur, file_id, captured_at, rid, "document", pdf_path.stem,
                      user_refs[0] if user_refs else None,
                      emails[0] if emails else None,
                      None, None, None, None, None,
                      json.dumps({"text_excerpt": text[:2000]}))


# ---------------------------------------------------------------------------
# CSV loader
# ---------------------------------------------------------------------------
def load_csv(conn, csv_path, table):
    with open(csv_path) as f:
        rows = list(csv.DictReader(f))
    if not rows:
        return
    cols = list(rows[0].keys())
    ph   = ",".join("?" * len(cols))
    conn.executemany(
        f'INSERT OR REPLACE INTO "{table}" ({",".join(cols)}) VALUES ({ph})',
        [[r[c] for c in cols] for r in rows]
    )
    conn.commit()
    print(f"  Loaded {len(rows):>5} rows  →  {table}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    print(f"Building {DB_PATH} ...")

    if DB_PATH.exists():
        DB_PATH.unlink()
        print("  Removed old DB.")

    conn = sqlite3.connect(DB_PATH)
    cur  = conn.cursor()
    init_db(conn)

    # 1. Dataset CSVs
    print("\n[1/3] Loading dataset CSVs ...")
    for fname, table in [
        ("deletion_requests.csv",  "deletion_requests"),
        ("user_identities.csv",    "user_identities"),
        ("user_audit_log.csv",     "user_audit_log"),
        ("system_activity.csv",    "system_activity"),
        ("deletion_rules.csv",     "deletion_rules"),
    ]:
        load_csv(conn, DATASET / fname, table)

    # 2. Evidence files
    print("\n[2/3] Loading evidence files ...")
    manifest = load_evidence_manifest()
    counts   = {"sql": 0, "json": 0, "log": 0, "pdf": 0, "png": 0}

    for file_id, meta in sorted(manifest.items()):
        path       = Path(meta["file_path"])
        captured_at = meta["captured_at"]
        ext        = path.suffix.lower()

        if not path.exists():
            print(f"  [WARN] Missing: {path}")
            continue

        print(f"  {file_id:12}  {path.name}")

        if ext == ".sql":
            load_sql_file(conn, cur, file_id, captured_at, path)
            counts["sql"] += 1
        elif ext == ".json":
            load_json_file(cur, file_id, captured_at, path)
            counts["json"] += 1
        elif ext == ".log":
            load_log_file(cur, file_id, captured_at, path)
            counts["log"] += 1
        elif ext == ".pdf":
            load_pdf_file(cur, file_id, captured_at, path)
            counts["pdf"] += 1
        elif ext == ".png":
            counts["png"] += 1  # skipped

    conn.commit()

    # 3. Summary
    total = cur.execute("SELECT COUNT(*) FROM evidence_records").fetchone()[0]
    print(f"\n[3/3] Done.  Files: {counts}")
    print(f"  evidence_records rows: {total:,}")

    # Sanity check
    print("\nSanity — records for user_01 / amina.elmasri@gmail.com:")
    rows = cur.execute("""
        SELECT file_id, system_id, resource_id, collection
        FROM evidence_records
        WHERE LOWER(email) = 'amina.elmasri@gmail.com' OR user_ref = 'user_01'
        LIMIT 10
    """).fetchall()
    for r in rows:
        print("  ", r)

    conn.close()
    print(f"\nDB written → {DB_PATH}")


if __name__ == "__main__":
    main()
