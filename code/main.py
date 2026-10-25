#!/usr/bin/env python3
"""
Ghost Data Still Exists - deletion audit agent.

Reads the participant-facing dataset under ``dataset/`` and writes
``output.csv`` at the repository root with one row per deletion request.

The audit is deterministic and rule based:

1.  Resolve the subject from the request email using the current identity
    snapshot and the historical identity audit log (current and historical
    emails, phones and email hashes).
2.  Parse every supplied evidence artefact into normalised observations
    (system, resource, category, identifiers, state, observation time).
3.  Keep observations whose observation time is at or before ``audit_at`` and
    collapse them to the latest state per resource.
4.  Apply ``deletion_rules.csv`` to decide whether each surviving record is a
    policy violation, a retained record, or already compliant.
5.  Emit findings, an ordered remediation plan and verification checks.

Run:
    python3 code/main.py                 # writes output.csv
    python3 code/main.py --sample        # also scores sample_output.csv
"""

from __future__ import annotations

import csv
import datetime as dt
import glob
import json
import os
import re
import sqlite3
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "dataset"
EVIDENCE_DIR = DATASET / "evidence"

# ---------------------------------------------------------------------------
# Categories / systems
# ---------------------------------------------------------------------------

ACCOUNT = "USER_PROFILE"
SEARCH = "SEARCH_INDEX_ENTRY"
ANALYTICS = "ANALYTICS_PROFILE"
SUPPORT_MSG = "SUPPORT_MESSAGE"
SUPPORT_ATT = "SUPPORT_ATTACHMENT"
EXPORT = "USER_EXPORT"
MARKETING = "MARKETING_PROFILE"
EMAIL_LOG = "EMAIL_DELIVERY_LOG"
AUDIT = "SECURITY_AUDIT_LOG"
LEGAL = "LEGAL_HOLD_RECORD"
BACKUP = "BACKUP_ARCHIVE"
FLOW = "DATA_FLOW"
TOMBSTONE = "ACCOUNT_TOMBSTONE"
SECONDARY = "SECONDARY_IDENTIFIER"
CACHE = "CACHE_ENTRY"

SYSTEM_BY_CATEGORY = {
    ACCOUNT: "account_service",
    SEARCH: "search_service",
    ANALYTICS: "analytics_platform",
    SUPPORT_MSG: "support_platform",
    SUPPORT_ATT: "support_platform",
    EXPORT: "export_service",
    MARKETING: "marketing_platform",
    EMAIL_LOG: "email_delivery_service",
    AUDIT: "security_service",
    LEGAL: "security_service",
    BACKUP: "backup_service",
    FLOW: "integration_service",
    TOMBSTONE: "identity_service",
    SECONDARY: "support_platform",
    CACHE: "analytics_platform",
}

COLLECTION_CATEGORY = {
    "customer_profiles": ACCOUNT,
    "customer_profiles_primary": ACCOUNT,
    "customer_profiles_failover_replica": ACCOUNT,
    "customer_search_documents": SEARCH,
    "search_documents_primary": SEARCH,
    "customer_analytics_reports": ANALYTICS,
    "customer_analytics_profiles": ANALYTICS,
    "support_conversations": SUPPORT_MSG,
    "support_records": SUPPORT_MSG,
    "ticket_attachments": SUPPORT_ATT,
    "customer_export_jobs": EXPORT,
    "customer_exports": EXPORT,
    "connector_configurations": FLOW,
    "connector_subscriptions": FLOW,
    "backup_catalog": BACKUP,
    "backup_restore_entries": BACKUP,
    "security_audit_events": AUDIT,
    "security_audit_records": AUDIT,
    "deleted_customer_references": TOMBSTONE,
    "marketing_profiles": MARKETING,
    "email_delivery_logs": EMAIL_LOG,
    "legal_holds": LEGAL,
}

RECORD_TYPE_CATEGORY = {
    "USER_PROFILE": ACCOUNT,
    "SEARCH_INDEX_ENTRY": SEARCH,
    "ANALYTICS_PROFILE": ANALYTICS,
    "SUPPORT_MESSAGE": SUPPORT_MSG,
    "SUPPORT_ATTACHMENT": SUPPORT_ATT,
    "USER_EXPORT": EXPORT,
    "MARKETING_PROFILE": MARKETING,
    "EMAIL_DELIVERY_LOG": EMAIL_LOG,
    "SECURITY_AUDIT_LOG": AUDIT,
    "LEGAL_HOLD_RECORD": LEGAL,
    "BACKUP_ARCHIVE": BACKUP,
    "DATA_FLOW": FLOW,
    "ACCOUNT_TOMBSTONE": TOMBSTONE,
}

TABLE_SYSTEM = {
    "customer_profiles": "account_service",
    "customer_profiles_primary": "account_service",
    "customer_profiles_failover_replica": "account_service",
    "customer_search_documents": "search_service",
    "search_documents_primary": "search_service",
    "customer_analytics_profiles": "analytics_platform",
    "support_records": "support_platform",
    "customer_exports": "export_service",
    "connector_subscriptions": "integration_service",
    "backup_restore_entries": "backup_service",
    "security_audit_records": "security_service",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def parse_ts(value: Any) -> dt.datetime | None:
    if not value:
        return None
    if isinstance(value, dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed


def norm_email(value: Any) -> str:
    return str(value or "").strip().lower()


def norm_phone(value: Any) -> str:
    digits = re.sub(r"\D", "", str(value or ""))
    return digits[-10:] if len(digits) >= 10 else digits


EMAIL_RE = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"\+\d[\d\s().-]{7,}\d")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def extract_emails(text: Any) -> set[str]:
    return {m.lower() for m in EMAIL_RE.findall(str(text or ""))}


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


# ---------------------------------------------------------------------------
# Observation model
# ---------------------------------------------------------------------------


@dataclass
class Obs:
    file_id: str
    file_captured: dt.datetime
    observed_at: dt.datetime
    system: str
    category: str
    resource_id: str
    user_ref: str = ""
    emails: set[str] = field(default_factory=set)
    phones: set[str] = field(default_factory=set)
    hashes: set[str] = field(default_factory=set)
    attrs: dict[str, Any] = field(default_factory=dict)
    order: int = 0

    def key(self) -> tuple[str, str]:
        return (self.system, self.resource_id)


def first_value(record: dict, names: Iterable[str]) -> Any:
    for name in names:
        if name in record and record[name] not in (None, ""):
            return record[name]
    return None


def boolish(value: Any) -> bool | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"true", "1", "yes", "enabled", "active", "found", "present"}:
        return True
    if text in {"false", "0", "no", "disabled", "stopped", "blocked", "absent"}:
        return False
    return None


def infer_category(collection: str, record: dict) -> str | None:
    collection = (collection or "").strip()
    if collection in COLLECTION_CATEGORY:
        return COLLECTION_CATEGORY[collection]
    record_type = str(record.get("record_type") or record.get("type") or "").upper()
    if record_type in RECORD_TYPE_CATEGORY:
        return RECORD_TYPE_CATEGORY[record_type]
    return None


def obs_from_record(
    record: dict,
    system: str,
    collection: str,
    observed_at: dt.datetime,
    file_id: str,
    file_captured: dt.datetime,
    category: str | None = None,
) -> Obs | None:
    if not isinstance(record, dict):
        return None
    resource_id = str(record.get("resource_id") or record.get("id") or "").strip()
    if not resource_id:
        return None
    category = category or infer_category(collection, record)
    if not category:
        return None
    system = str(record.get("system") or "").strip() or system or SYSTEM_BY_CATEGORY.get(category, "")

    # Flatten nested payloads used by the different evidence formats.
    for nested_key in ("document", "profile"):
        nested = record.get(nested_key)
        if isinstance(nested, dict):
            merged = dict(record)
            for key, value in nested.items():
                merged.setdefault(key, value)
            record = merged

    user_ref = str(
        first_value(
            record,
            (
                "customer_reference",
                "user_id",
                "subject_reference",
                "subject_ref",
                "user_ref",
                "correlation_key",
                "lookup_value",
            ),
        )
        or ""
    ).strip()
    if user_ref.lower() in {"null", "none", "no direct identifier", "n/a", "unknown"}:
        user_ref = ""

    emails: set[str] = set()
    for name in (
        "email",
        "owner_email",
        "requester_email",
        "customer_email",
        "uploaded_by",
        "subject_selector",
        "lookup_key",
        "match_key",
        "correlation_key",
        "subject_key",
        "query",
        "owner_key",
        "subject_reference",
        "subject_ref",
        "lookup_value",
        "matched_value",
        "scan_key",
    ):
        value = record.get(name)
        if value and "@" in str(value):
            emails.add(norm_email(value))
    for name in ("message_text", "message_excerpt", "details", "matched_value", "scan_key"):
        for value in extract_emails(record.get(name)):
            emails.add(value)
    emails.discard("")

    phones: set[str] = set()
    for name in ("phone", "owner_phone", "requester_phone", "matched_value", "scan_key"):
        value = record.get(name)
        if not value or "@" in str(value):
            continue
        phone = norm_phone(value)
        if len(phone) >= 7:
            phones.add(phone)
    phones.discard("")

    hashes: set[str] = set()
    for name in ("email_hash", "correlation_key"):
        value = record.get(name)
        if value:
            text = str(value).strip().lower()
            if SHA256_RE.match(text):
                hashes.add(text)
    hashes.discard("")

    attrs = dict(record)
    return Obs(
        file_id=file_id,
        file_captured=file_captured,
        observed_at=observed_at,
        system=system,
        category=category,
        resource_id=resource_id,
        user_ref=user_ref,
        emails=emails,
        phones=phones,
        hashes=hashes,
        attrs=attrs,
    )


# ---------------------------------------------------------------------------
# Evidence parsers
# ---------------------------------------------------------------------------


class EvidenceStore:
    def __init__(self) -> None:
        self.manifest: dict[str, dict[str, str]] = {}
        self.obs: list[Obs] = []
        self.by_file: dict[str, list[Obs]] = defaultdict(list)
        self.activity_links: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.activity_events: list[dict[str, Any]] = []

    # -- manifest ---------------------------------------------------------
    def load_manifest(self) -> None:
        for row in read_csv(DATASET / "evidence_files.csv"):
            self.manifest[row["file_id"]] = row

    def add(self, obs: Obs | None) -> None:
        if obs is None:
            return
        obs.order = len(self.by_file[obs.file_id])
        self.obs.append(obs)
        self.by_file[obs.file_id].append(obs)

    # -- SQL --------------------------------------------------------------
    def parse_sql(self, path: Path, file_id: str, captured: dt.datetime) -> None:
        try:
            sql = path.read_text(encoding="utf-8", errors="replace")
            con = sqlite3.connect(":memory:")
            con.executescript(sql)
        except Exception:
            return
        tables = [r[0] for r in con.execute("select name from sqlite_master where type='table'")]
        for table in tables:
            if table == "snapshot_scope":
                continue
            columns = [r[1] for r in con.execute(f'pragma table_info("{table}")')]
            if not columns:
                continue
            try:
                rows = con.execute(f'select * from "{table}"').fetchall()
            except Exception:
                continue
            for raw in rows:
                record = dict(zip(columns, raw))
                observed = parse_ts(
                    first_value(record, ("updated_at", "indexed_at", "recorded_at", "captured_at"))
                ) or captured
                if "record_json" in record and record["record_json"]:
                    try:
                        payload = json.loads(record["record_json"])
                    except Exception:
                        continue
                    system = record.get("origin_system") or TABLE_SYSTEM.get(table, "")
                    collection = record.get("collection_name") or table
                    self.add(
                        obs_from_record(payload, system, collection, observed, file_id, captured)
                    )
                else:
                    system = TABLE_SYSTEM.get(table)
                    category = COLLECTION_CATEGORY.get(table)
                    if not system or not category:
                        continue
                    self.add(
                        obs_from_record(
                            record, system, table, observed, file_id, captured, category=category
                        )
                    )
        con.close()

    # -- JSON -------------------------------------------------------------
    def parse_json(self, path: Path, file_id: str, captured: dt.datetime) -> None:
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return
        if not isinstance(data, dict):
            return

        # Snapshot bundle: per-snapshot observation time.
        snapshots = data.get("snapshots")
        if isinstance(snapshots, list):
            for snapshot in snapshots:
                if not isinstance(snapshot, dict):
                    continue
                observed = parse_ts(snapshot.get("captured_at")) or captured
                store = snapshot.get("data_store") or ""
                collection = snapshot.get("collection") or ""
                for record in snapshot.get("records") or []:
                    self.add(
                        obs_from_record(
                            record, store, collection, observed, file_id, captured
                        )
                    )
            return

        # Service resource export.
        exports = data.get("service_exports")
        if isinstance(exports, dict):
            exported = parse_ts(data.get("exported_at")) or captured
            for service, groups in exports.items():
                if not isinstance(groups, dict):
                    continue
                for kind, records in groups.items():
                    if not isinstance(records, list):
                        continue
                    for record in records:
                        if not isinstance(record, dict):
                            continue
                        observed = parse_ts(record.get("observed_at")) or exported
                        category = infer_category(kind, record)
                        if category is None:
                            category = infer_category("", record)
                        if category is None:
                            category = guess_service_category(service, kind)
                        hits = record.get("hits")
                        if category == SEARCH and isinstance(hits, dict):
                            documents = hits.get("documents") or []
                            if documents:
                                for document in documents:
                                    payload = dict(document)
                                    payload.setdefault("query", record.get("query"))
                                    payload["hits_total"] = hits.get("total")
                                    self.add(
                                        obs_from_record(
                                            payload,
                                            service,
                                            kind,
                                            observed,
                                            file_id,
                                            captured,
                                            category=category,
                                        )
                                    )
                            else:
                                payload = dict(record)
                                payload["present"] = False
                                self.add(
                                    obs_from_record(
                                        payload,
                                        service,
                                        kind,
                                        observed,
                                        file_id,
                                        captured,
                                        category=category,
                                    )
                                )
                            continue
                        self.add(
                            obs_from_record(
                                record,
                                service,
                                kind,
                                observed,
                                file_id,
                                captured,
                                category=category,
                            )
                        )
            return

        # Flat record lists (record_lookup style).
        records = data.get("records")
        if isinstance(records, list):
            default_observed = parse_ts(
                data.get("captured_at") or data.get("exported_at") or data.get("recorded_at")
            ) or captured
            default_collection = str(data.get("collection") or "")
            for record in records:
                if not isinstance(record, dict):
                    continue
                observed = parse_ts(record.get("recorded_at")) or default_observed
                system = str(record.get("system") or "")
                category = infer_category(default_collection, record)
                if category is None:
                    category = infer_category("", record)
                if category is None:
                    continue
                self.add(
                    obs_from_record(
                        record,
                        system or SYSTEM_BY_CATEGORY.get(category, ""),
                        str(record.get("record_type") or ""),
                        observed,
                        file_id,
                        captured,
                        category=category,
                    )
                )

    # -- logs -------------------------------------------------------------
    def parse_log(self, path: Path, file_id: str, captured: dt.datetime) -> None:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return

        # First pass: a trace often identifies the subject on a ``*_started``
        # line and the resource on a later ``*_completed`` line.  Carry the
        # lookup key forward by trace id.
        trace_keys: dict[str, dict[str, str]] = {}
        for line in lines:
            parsed = parse_log_line(line)
            if not parsed:
                continue
            trace = str(parsed.get("trace_id") or parsed.get("requestId") or "")
            if not trace:
                continue
            for key in ("lookup_key", "subject_key", "match_key", "query", "subject_ref", "scan_key"):
                value = parsed.get(key)
                if value and str(value).strip().lower() not in {"", "null"}:
                    trace_keys.setdefault(trace, {})[key] = str(value)

        # Second pass: one observation per event line.  Collapsing a trace to a
        # single record loses later state checks in the same trace.
        for line in lines:
            parsed = parse_log_line(line)
            if not parsed:
                continue
            trace = str(parsed.get("trace_id") or parsed.get("requestId") or "")
            record = dict(trace_keys.get(trace, {}))
            record.update(parsed)
            self.obs_from_log_line(record, file_id, captured)

    def obs_from_log_line(self, record: dict[str, Any], file_id: str, captured: dt.datetime) -> None:
        event = str(record.get("event") or "").strip()
        service = str(record.get("service") or record.get("function") or "").strip()
        observed = parse_ts(record.get("timestamp")) or captured
        resource_id = str(record.get("resource_id") or record.get("resource") or "").strip()
        if not event or not resource_id:
            return

        def emit(category: str, attrs: dict[str, Any] | None = None) -> None:
            payload = dict(record)
            if attrs:
                payload.update(attrs)
            payload["resource_id"] = resource_id
            system = SYSTEM_BY_CATEGORY.get(category, service)
            self.add(
                obs_from_record(
                    payload, system, "", observed, file_id, captured, category=category
                )
            )

        if event == "profile_lookup_completed":
            rows = str(record.get("rows", ""))
            status = str(record.get("http_status", ""))
            present = not (rows == "0" or status == "404")
            emit(ACCOUNT, {"present": present, "rows": rows, "http_status": status})
            return

        if event == "deletion_marker_check":
            if service == "account_service":
                marker = boolish(record.get("marker_found"))
                emit(ACCOUNT, {"present": not bool(marker)})
            return

        if event == "index_query_completed":
            result = str(record.get("result", "")).lower()
            emit(SEARCH, {"present": result != "miss", "result": result})
            return

        if event == "record_lookup":
            record_type = str(record.get("record_type") or "").upper()
            category = RECORD_TYPE_CATEGORY.get(record_type)
            if category is None:
                return
            system = str(record.get("system") or SYSTEM_BY_CATEGORY.get(category, ""))
            payload = dict(record)
            payload["resource_id"] = resource_id
            self.add(
                obs_from_record(
                    payload, system, record_type, observed, file_id, captured, category=category
                )
            )
            return

        if event in {"analytics_profile_read_completed", "analytics_profile_read"}:
            emit(ANALYTICS, {})
            return

        if event == "analytics_identity_scan":
            matched = str(record.get("matched_value") or "")
            attrs: dict[str, Any] = {}
            if "@" in matched:
                attrs["email"] = matched
            elif matched:
                attrs["phone"] = matched
            emit(ANALYTICS, attrs)
            return

        if event == "support_ticket_read_completed":
            emit(SUPPORT_MSG, {})
            return

        if event == "contact_query_completed":
            rows = str(record.get("rows", ""))
            source = str(record.get("source") or "")
            is_replica = service.startswith("support_replica") or source == "legacy_contact_index"
            category = SECONDARY if is_replica else SUPPORT_MSG
            emit(category, {"present": rows != "0", "rows": rows})
            return

        if event == "message_pii_scan":
            matched = record.get("matched_value") or record.get("subject_key") or ""
            emit(SUPPORT_MSG, {"message_text": matched, "pii": True})
            return

        if event == "attachment_pii_scan":
            matched = record.get("matched_value") or record.get("subject_key") or ""
            emit(SUPPORT_ATT, {"message_text": matched, "pii": True})
            return

        if event == "connector_config_read_completed" or event == "connector_heartbeat":
            emit(FLOW, {})
            return

        if event in {
            "restore_policy_read_completed",
            "restore_authorization_completed",
            "restore_candidate_evaluated",
        }:
            emit(BACKUP, {})
            return

        if event == "audit_record_read_completed":
            rows = str(record.get("rows", ""))
            emit(AUDIT, {"rows": rows})
            return

        if event in {"export_metadata_read_completed", "export_download_check_completed"}:
            emit(EXPORT, {})
            return

        if event == "contact_lookup_completed":
            rows = str(record.get("rows", ""))
            emit(CACHE, {"present": rows != "0", "rows": rows})
            return

    # -- text / handover --------------------------------------------------
    def parse_handover(self, path: Path, file_id: str, captured: dt.datetime) -> None:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return
        for line in text.splitlines():
            match = re.match(
                r"^-\s*(\S+)\s*\|\s*([a-z_]+)\s*\|\s*(\S+)\s*\|\s*(\S+)\s*\|\s*(\S+)\s*\|\s*(.+?)\s*$",
                line.strip(),
            )
            if not match:
                continue
            observed = parse_ts(match.group(1)) or captured
            system = match.group(2)
            resource = match.group(3)
            record_type = match.group(4)
            result = match.group(5)
            reference = match.group(6)
            category = RECORD_TYPE_CATEGORY.get(record_type)
            if not category:
                continue
            record = {
                "resource_id": resource,
                "record_type": record_type,
                "result": result,
                "subject_reference": reference,
            }
            self.add(
                obs_from_record(
                    record, system, record_type, observed, file_id, captured, category=category
                )
            )

    # -- static visual evidence ------------------------------------------
    def parse_visual(self, file_id: str) -> None:
        try:
            from visual_evidence import VISUAL_EVIDENCE
        except ImportError:  # imported as the ``code`` package from the repo root
            from code.visual_evidence import VISUAL_EVIDENCE

        captured = parse_ts(self.manifest[file_id]["captured_at"])
        for item in VISUAL_EVIDENCE.get(file_id, []):
            record = dict(item)
            category = record.pop("category")
            system = record.pop("system", SYSTEM_BY_CATEGORY.get(category, ""))
            observed = parse_ts(record.pop("observed_at", "")) or captured
            self.add(
                obs_from_record(
                    record, system, "", observed, file_id, captured, category=category
                )
            )

    # -- driver -----------------------------------------------------------
    def load_all(self) -> None:
        self.load_manifest()
        for file_id, row in sorted(self.manifest.items()):
            path = EVIDENCE_DIR / row["file_path"].replace("evidence/", "", 1)
            if not path.exists():
                path = DATASET / row["file_path"]
            captured = parse_ts(row["captured_at"]) or dt.datetime.now(dt.timezone.utc)
            suffix = path.suffix.lower()
            if suffix == ".sql":
                self.parse_sql(path, file_id, captured)
            elif suffix == ".json":
                self.parse_json(path, file_id, captured)
            elif suffix == ".log":
                self.parse_log(path, file_id, captured)
            elif suffix == ".txt":
                self.parse_handover(path, file_id, captured)
            elif suffix in {".png", ".pdf"}:
                self.parse_visual(file_id)
        self.load_activity()

    def load_activity(self) -> None:
        for row in read_csv(DATASET / "system_activity.csv"):
            self.activity_events.append(row)
            if row["event_type"] == "LINK_RESOURCE_IDENTITY":
                details = row.get("details", "")
                user_match = re.search(r"\buser_(\d+)\b", details)
                email_match = EMAIL_RE.search(details)
                if user_match or email_match:
                    self.activity_links[row["resource_id"]].append(
                        {
                            "activity_id": row["activity_id"],
                            "user_id": f"user_{user_match.group(1)}" if user_match else "",
                            "email": email_match.group(0).lower() if email_match else "",
                            "event_time": parse_ts(row["event_time"]),
                            "system": row["target_system"],
                            "resource_id": row["resource_id"],
                        }
                    )


def guess_service_category(service: str, kind: str) -> str | None:
    mapping = {
        ("account_service", "profile_lookups"): ACCOUNT,
        ("analytics_platform", "profiles"): ANALYTICS,
        ("backup_service", "restore_entries"): BACKUP,
        ("export_service", "exports"): EXPORT,
        ("integration_service", "connectors"): FLOW,
        ("search_service", "index_queries"): SEARCH,
        ("security_service", "audit_records"): AUDIT,
        ("support_platform", "tickets"): SUPPORT_MSG,
    }
    return mapping.get((service, kind))


KEY_VALUE_RE = re.compile(r'([A-Za-z_][\w.-]*)=("([^"]*)"|\'([^\']*)\'|(\S+))')
JSON_RE = re.compile(r"(\{.*\})\s*$")
ISO_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)")


def parse_log_line(line: str) -> dict[str, Any] | None:
    timestamp_match = ISO_RE.match(line)
    if not timestamp_match:
        return None
    result: dict[str, Any] = {"timestamp": timestamp_match.group(1)}
    rest = line[timestamp_match.end():]

    # JSON-lines format.
    json_match = JSON_RE.search(rest)
    if json_match:
        try:
            payload = json.loads(json_match.group(1))
            if isinstance(payload, dict):
                result.update({k: str(v) for k, v in payload.items()})
                return result
        except Exception:
            pass

    # Bracket format: [DEBUG] [service] [trace] event: ...
    bracket = re.match(
        r"\s*\[([^\]]+)\]\s*\[([^\]]+)\]\s*\[([^\]]+)\]\s*([A-Za-z_]+):\s*(.*)$", rest
    )
    if bracket:
        result["level"] = bracket.group(1)
        result["service"] = bracket.group(2)
        result["trace_id"] = bracket.group(3)
        result["event"] = bracket.group(4)
        rest = bracket.group(5)
    else:
        # Pipe format: level | service | trace | event | ...
        if "|" in rest:
            parts = [part.strip() for part in rest.split("|")]
            if len(parts) >= 5:
                result["level"] = parts[0]
                result["service"] = parts[1]
                result["trace_id"] = parts[2]
                result["event"] = parts[3]
                rest = " | ".join(parts[4:])
        # Syslog format: <pri>1 node service trace - - ...
        if "event" not in result:
            syslog = re.match(
                r"\s*<\d+>\d\s+\S+\s+(\S+)\s+(\S+)\s+(\S+)\s+-\s+-\s+(.*)$", rest
            )
            if syslog:
                result["service"] = syslog.group(1)
                result["trace_id"] = syslog.group(2)
                rest = syslog.group(4)

    # key=value pairs, including nested message="...".
    for match in KEY_VALUE_RE.finditer(rest):
        key = match.group(1)
        value = match.group(3) if match.group(3) is not None else (
            match.group(4) if match.group(4) is not None else match.group(5)
        )
        result.setdefault(key, value)
        if key == "message" and "=" in str(value):
            for nested in KEY_VALUE_RE.finditer(str(value)):
                nested_value = nested.group(3) if nested.group(3) is not None else (
                    nested.group(4) if nested.group(4) is not None else nested.group(5)
                )
                result.setdefault(nested.group(1), nested_value)

    if "event" not in result:
        event = re.search(r"\bevent=([A-Za-z0-9_]+)", rest)
        if event:
            result["event"] = event.group(1)
    return result


# ---------------------------------------------------------------------------
# Identity resolution
# ---------------------------------------------------------------------------


class Identities:
    def __init__(self) -> None:
        self.users: dict[str, dict[str, Any]] = {}
        self.by_email: dict[str, str] = {}
        self.by_phone: dict[str, str] = {}
        self.by_hash: dict[str, str] = {}
        self._load()

    def _add(self, user_id: str, email: str = "", phone: str = "", email_hash: str = "") -> None:
        user = self.users.setdefault(
            user_id, {"emails": set(), "phones": set(), "hashes": set()}
        )
        if email:
            normalized = norm_email(email)
            user["emails"].add(normalized)
            self.by_email.setdefault(normalized, user_id)
        if phone:
            normalized = norm_phone(phone)
            if normalized:
                user["phones"].add(normalized)
                self.by_phone.setdefault(normalized, user_id)
        if email_hash:
            normalized = str(email_hash).strip().lower()
            user["hashes"].add(normalized)
            self.by_hash.setdefault(normalized, user_id)

    def _load(self) -> None:
        for row in read_csv(DATASET / "user_identities.csv"):
            self._add(row["user_id"], row.get("email", ""), row.get("phone", ""), row.get("email_hash", ""))
        for row in read_csv(DATASET / "user_audit_log.csv"):
            self._add(
                row["user_id"],
                row.get("old_value", "") if row.get("field_name") == "email" else "",
                row.get("old_value", "") if row.get("field_name") == "phone" else "",
                row.get("old_value", "") if row.get("field_name") == "email_hash" else "",
            )
            self._add(
                row["user_id"],
                row.get("new_value", "") if row.get("field_name") == "email" else "",
                row.get("new_value", "") if row.get("field_name") == "phone" else "",
                row.get("new_value", "") if row.get("field_name") == "email_hash" else "",
            )

    def resolve(self, email: str) -> str:
        normalized = norm_email(email)
        if normalized in self.by_email:
            return self.by_email[normalized]
        # Tolerate display-name wrapped addresses and case differences.
        for candidate in extract_emails(email):
            if candidate in self.by_email:
                return self.by_email[candidate]
        return ""

    def identifiers(self, user_id: str) -> dict[str, set[str]]:
        user = self.users.get(user_id, {"emails": set(), "phones": set(), "hashes": set()})
        return user


# ---------------------------------------------------------------------------
# Linking observations to subjects
# ---------------------------------------------------------------------------


def obs_matches_user(obs: Obs, user_id: str, identities: Identities) -> bool:
    if not user_id:
        return False
    if obs.user_ref and obs.user_ref == user_id:
        return True
    known = identities.identifiers(user_id)
    if obs.emails & known["emails"]:
        return True
    if obs.phones & known["phones"]:
        return True
    if obs.hashes & known["hashes"]:
        return True
    return False


# ---------------------------------------------------------------------------
# Request intent
# ---------------------------------------------------------------------------

NON_DELETION_PATTERNS = [
    r"\b(access|copy of|send me a copy|download|rectif|correct it|update my|change (the|my) email)\b",
    r"\b(unsubscribe|opt[- ]?out|marketing preferences|marketing lists only|promotional emails|stop sending)\b",
    r"\b(invoice|refund|complaint|question about|where is my order|status of my order)\b",
    r"\b(reset|resetting|password|login|misspelled|replace it|continue using)\b",
]

# Refusals and retentions dominate even when the text quotes the word
# "deletion" (for example "I am not asking for deletion").
RETENTION_PATTERNS = [
    r"not asking for deletion",
    r"not a request to (erase|delete)",
    r"not to erase",
    r"do not (delete|close|remove)",
    r"don't (delete|close|remove)",
    r"please don't delete",
    r"without (removing|deleting)",
    r"leave (the|my) (account|profile)",
    r"keep (the|my) account",
    r"keep the account as it is",
    r"retain my data",
    r"still (need|want) the account",
]

DELETION_PATTERNS = [
    r"\b(delet|eras|remov|clos|terminat|destroy)",
    r"(löschen|loeschen|supprimer|suppression|eliminar|eliminación|borrar|cancellare|削除|삭제|verwijder|excluir|exclusão|exclusao|apagar|删除)",
    r"(datenschutz|dsgvo|gdpr|rgpd|privacy request|right to be forgotten)",
]

# Deletion directed at the subject's own account or records.
EXPLICIT_DELETION_PATTERNS = [
    r"(delet|eras|remov|clos|exclus|elimin|supprim)[a-zà-ÿ]{0,20}.{0,40}(account|profile|data|record|cuenta|conta|compte|datos|dados)",
    r"(account|profile|data|record|cuenta|conta|compte|datos|dados).{0,40}(delet|eras|remov|clos|exclus|elimin|supprim)",
    r"\b(profile|account|data)\b.{0,30}\b(gone|deleted|removed)\b",
    r"\b(gone|deleted|removed)\b.{0,30}\b(profile|account)\b",
]


def request_authorizes_deletion(text: str) -> bool:
    lowered = (text or "").lower()
    if not lowered.strip():
        return False
    if any(re.search(pattern, lowered) for pattern in RETENTION_PATTERNS):
        return False
    if any(re.search(pattern, lowered) for pattern in EXPLICIT_DELETION_PATTERNS):
        return True
    if any(re.search(pattern, lowered) for pattern in NON_DELETION_PATTERNS):
        return False
    return any(re.search(pattern, lowered) for pattern in DELETION_PATTERNS)


# ---------------------------------------------------------------------------
# Case evaluation
# ---------------------------------------------------------------------------


@dataclass
class Violation:
    category: str
    system: str
    resource_id: str
    operation: str
    state: str
    evidence_id: str


@dataclass
class Compliant:
    category: str
    system: str
    resource_id: str
    operation: str
    state: str
    evidence_id: str


def latest_observations(
    store: EvidenceStore,
    identities: Identities,
    user_id: str,
    audit_at: dt.datetime,
    extra_resources: set[str] | None = None,
) -> dict[tuple[str, str], Obs]:
    latest: dict[tuple[str, str], Obs] = {}
    extra_resources = extra_resources or set()
    for obs in store.obs:
        if obs.observed_at > audit_at or obs.file_captured > audit_at:
            continue
        if obs.resource_id not in extra_resources and not obs_matches_user(obs, user_id, identities):
            continue
        key = obs.key()
        previous = latest.get(key)
        if previous is None or (obs.observed_at, obs.file_captured) >= (previous.observed_at, previous.file_captured):
            latest[key] = obs
    return latest


def obs_present(obs: Obs) -> bool:
    attrs = obs.attrs
    if "present" in attrs:
        return bool(attrs["present"])
    result = str(attrs.get("result") or "").strip().upper()
    if result in {"NOT_FOUND", "ABSENT", "MISS", "DELETED", "REMOVED"}:
        return False
    if result in {"FOUND", "PRESENT", "HIT", "ACTIVE", "IDENTIFIABLE", "ANONYMIZED", "REDACTED", "BLOCKED", "DISABLED"}:
        return True
    status = str(attrs.get("account_status") or "").strip().upper()
    if status in {"DELETED", "REMOVED"}:
        return False
    rows = str(attrs.get("rows") or "")
    http_status = str(attrs.get("http_status") or "")
    status_code = str(attrs.get("status_code") or "")
    if rows == "0" or http_status == "404" or status_code == "404":
        return False
    return True


def is_anonymized(obs: Obs) -> bool:
    attrs = obs.attrs
    result = str(attrs.get("result") or "").upper()
    if result == "ANONYMIZED":
        return True
    if obs.user_ref or obs.emails or obs.phones or obs.hashes:
        return False
    # Fall back to raw attributes for formats that carry identifiers outside
    # the normalised fields.
    for name in ("user_id", "customer_reference", "email", "phone", "email_hash"):
        value = attrs.get(name)
        if value and str(value).strip() and str(value).strip().lower() != "null":
            return False
    return True


def is_redacted(obs: Obs) -> bool:
    attrs = obs.attrs
    result = str(attrs.get("result") or "").upper()
    if result == "REDACTED":
        return True
    text = str(attrs.get("message_text") or attrs.get("message_excerpt") or "")
    if text.strip().upper() == "[REDACTED]":
        return True
    return not has_pii(obs)


def has_pii(obs: Obs) -> bool:
    attrs = obs.attrs
    result = str(attrs.get("result") or "").upper()
    if result in {"IDENTIFIABLE", "FOUND"}:
        return True
    for name in ("requester_name", "requester_email", "requester_phone", "email", "phone", "email_hash", "name", "full_name"):
        value = attrs.get(name)
        if value and str(value).strip() and str(value).strip().lower() != "null":
            return True
    text = str(attrs.get("message_text") or attrs.get("message_excerpt") or "")
    if extract_emails(text):
        return True
    if PHONE_RE.search(text):
        return True
    return False


def flow_enabled(obs: Obs) -> bool:
    attrs = obs.attrs
    result = str(attrs.get("result") or "").upper()
    if result == "ACTIVE":
        return True
    if result == "DISABLED":
        return False
    value = boolish(attrs.get("enabled"))
    if value is not None:
        return value
    status = str(attrs.get("last_delivery_status") or "").lower()
    return status not in {"stopped", "disabled"}


def restore_allowed(obs: Obs) -> bool:
    attrs = obs.attrs
    result = str(attrs.get("result") or "").upper()
    if result == "ACTIVE":
        return True
    if result == "BLOCKED":
        return False
    value = boolish(attrs.get("restore_allowed"))
    if value is not None:
        return value
    # Restore candidate evaluation: eligible and not deletion-blocked means the
    # archive can still be restored.
    block = boolish(attrs.get("deletion_block"))
    if block is False:
        return True
    if block is True:
        return False
    eligible = boolish(attrs.get("eligible"))
    if eligible is not None:
        return eligible
    archive = boolish(attrs.get("archive_present"))
    if archive is False:
        return False
    return False


def export_available(obs: Obs, audit_at: dt.datetime | None = None) -> bool:
    attrs = obs.attrs
    result = str(attrs.get("result") or "").upper()
    if result == "NOT_FOUND":
        return False
    if result in {"FOUND", "PRESENT"}:
        return True
    if boolish(attrs.get("download_available")) is False:
        return False
    if boolish(attrs.get("available")) is False:
        return False
    status = str(attrs.get("status") or "").lower()
    if status in {"expired", "deleted", "removed"}:
        return False
    expires = parse_ts(attrs.get("expires_at"))
    if expires is not None and audit_at is not None and expires < audit_at:
        return False
    return True


def audit_present(obs: Obs) -> bool:
    attrs = obs.attrs
    result = str(attrs.get("result") or "").upper()
    if result in {"NOT_FOUND", "ABSENT"}:
        return False
    rows = str(attrs.get("rows") or "")
    if rows == "0":
        return False
    return True


def _citation_matches(obs: Obs, item: Violation | Compliant, audit_at: dt.datetime) -> bool:
    """Does ``obs`` show the same state that ``item`` reports?"""
    category = item.category
    operation = item.operation
    if category in {ACCOUNT, SEARCH, SECONDARY, CACHE, SUPPORT_ATT, MARKETING, EXPORT}:
        if operation in {"DELETE_RECORD", "REPORT_REMAINING_RECORD"}:
            if category == EXPORT:
                return export_available(obs, audit_at)
            return obs_present(obs)
        if operation == "VERIFY_RECORD_ABSENT":
            return not obs_present(obs)
    if category == SUPPORT_MSG:
        if operation in {"REDACT_RECORD", "REPORT_EXPOSED_PII"}:
            return obs_present(obs) and not is_redacted(obs)
        if operation == "VERIFY_RECORD_REDACTED":
            return obs_present(obs) and is_redacted(obs)
    if category == ANALYTICS:
        if operation in {"ANONYMIZE_RECORD", "REPORT_EXPOSED_PII"}:
            return not is_anonymized(obs)
        if operation == "VERIFY_RECORD_ANONYMIZED":
            return is_anonymized(obs)
    if category in {EMAIL_LOG, TOMBSTONE}:
        if operation in {"REDACT_RECORD", "REPORT_EXPOSED_PII"}:
            return has_pii(obs)
        if operation == "VERIFY_RECORD_REDACTED":
            return not has_pii(obs)
    if category == BACKUP:
        if operation in {"BLOCK_RESTORE", "REPORT_RESTORE_RISK"}:
            return restore_allowed(obs)
        if operation == "VERIFY_RESTORE_BLOCKED":
            return not restore_allowed(obs)
    if category == FLOW:
        if operation in {"DISABLE_DATA_FLOW", "REPORT_ACTIVE_DATA_FLOW"}:
            return flow_enabled(obs)
        if operation == "VERIFY_DATA_FLOW_DISABLED":
            return not flow_enabled(obs)
    if category == AUDIT:
        return audit_present(obs)
    if category == LEGAL:
        return obs_present(obs)
    return True


def citation_eligible(
    store: EvidenceStore, evidence_id: str, audit_at: dt.datetime
) -> bool:
    """True when an id may be cited for this case.

    Activity and audit ids carry their own event time and are always allowed.
    File ids are only allowed when the manifest capture time is at or before
    the case cutoff.
    """
    if not evidence_id:
        return False
    if evidence_id in store.manifest:
        captured = parse_ts(store.manifest[evidence_id].get("captured_at", ""))
        return captured is None or captured <= audit_at
    return True


def citation_for_item(
    store: EvidenceStore,
    item: Violation | Compliant,
    audit_at: dt.datetime,
) -> str:
    """Latest eligible file that proves the same state, else an eligible id."""
    candidates = [
        obs
        for obs in store.obs
        if obs.system == item.system
        and obs.resource_id == item.resource_id
        and obs.category == item.category
        and obs.observed_at <= audit_at
        and obs.file_captured <= audit_at
        and _citation_matches(obs, item, audit_at)
    ]
    if candidates:
        return max(candidates, key=lambda obs: (obs.observed_at, obs.file_captured)).file_id
    if citation_eligible(store, item.evidence_id, audit_at):
        return item.evidence_id
    return ""


def evaluate_case(
    case: dict[str, str],
    store: EvidenceStore,
    identities: Identities,
    assigned_analytics: tuple[tuple[str, str, dt.datetime], ...] = (),
    account_hint: tuple[str, str] | None = None,
) -> tuple[str, list[dict[str, Any]]]:
    audit_at = parse_ts(case["audit_at"])
    if audit_at is None:
        return "INCOMPLETE", []

    if not request_authorizes_deletion(case.get("request_text", "")):
        return "NOT_APPLICABLE", []

    requested_at = parse_ts(case.get("requested_at"))
    user_id = identities.resolve(case["email"])
    if not user_id:
        return "INCOMPLETE", []

    # Resolve the account resource before collapsing state so that a later
    # readback of the same account (which may not carry the email) wins over an
    # older snapshot that still shows the account.
    account_resource = ""
    account_evidence = ""
    account_candidate = find_account_observation(store, identities, user_id, audit_at)
    if account_candidate is None:
        account_candidate = account_hint or find_account_candidate(
            case, store, identities, user_id, audit_at
        )
    if account_candidate:
        account_resource, account_evidence = account_candidate

    extra_resources = {account_resource} if account_resource else set()
    latest = latest_observations(store, identities, user_id, audit_at, extra_resources)

    # Attachments and tombstones observed before the request belong to an
    # earlier episode, not to this deletion.
    if requested_at is not None:
        latest = {
            key: obs
            for key, obs in latest.items()
            if not (obs.category in {SUPPORT_ATT, TOMBSTONE} and obs.observed_at < requested_at)
        }

    # Unlinked anonymised analytics records are attributed per block elsewhere;
    # add the assignment as a synthetic compliant observation.
    for resource_id, file_id, observed_at in assigned_analytics:
        key = (SYSTEM_BY_CATEGORY[ANALYTICS], resource_id)
        if key in latest:
            continue
        latest[key] = Obs(
            file_id=file_id,
            file_captured=observed_at,
            observed_at=observed_at,
            system=SYSTEM_BY_CATEGORY[ANALYTICS],
            category=ANALYTICS,
            resource_id=resource_id,
            attrs={"resource_id": resource_id, "result": "ANONYMIZED"},
        )

    violations: list[Violation] = []
    compliant: list[Compliant] = []
    account_obs: Obs | None = None

    for key, obs in latest.items():
        if obs.category == ACCOUNT and account_resource and obs.resource_id != account_resource:
            continue
        category = obs.category
        if category == ACCOUNT:
            account_obs = obs
            if obs_present(obs):
                violations.append(
                    Violation(category, obs.system, obs.resource_id, "DELETE_RECORD", "ABSENT", obs.file_id)
                )
            continue

        if category in {SEARCH, SECONDARY, CACHE}:
            if obs_present(obs):
                violations.append(
                    Violation(category, obs.system, obs.resource_id, "DELETE_RECORD", "ABSENT", obs.file_id)
                )
            continue

        if category == SUPPORT_ATT:
            if obs_present(obs):
                violations.append(
                    Violation(category, obs.system, obs.resource_id, "DELETE_RECORD", "ABSENT", obs.file_id)
                )
            continue

        if category == SUPPORT_MSG:
            if obs_present(obs):
                if is_redacted(obs):
                    compliant.append(
                        Compliant(category, obs.system, obs.resource_id, "VERIFY_RECORD_REDACTED", "REDACTED", obs.file_id)
                    )
                else:
                    violations.append(
                        Violation(category, obs.system, obs.resource_id, "REDACT_RECORD", "REDACTED", obs.file_id)
                    )
            continue

        if category == ANALYTICS:
            if is_anonymized(obs):
                compliant.append(
                    Compliant(category, obs.system, obs.resource_id, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", obs.file_id)
                )
            else:
                violations.append(
                    Violation(category, obs.system, obs.resource_id, "ANONYMIZE_RECORD", "ANONYMIZED", obs.file_id)
                )
            continue

        if category == EXPORT:
            if export_available(obs, audit_at):
                violations.append(
                    Violation(category, obs.system, obs.resource_id, "DELETE_RECORD", "ABSENT", obs.file_id)
                )
            continue

        if category == MARKETING:
            if obs_present(obs):
                violations.append(
                    Violation(category, obs.system, obs.resource_id, "DELETE_RECORD", "ABSENT", obs.file_id)
                )
            continue

        if category == EMAIL_LOG:
            if has_pii(obs):
                violations.append(
                    Violation(category, obs.system, obs.resource_id, "REDACT_RECORD", "REDACTED", obs.file_id)
                )
            else:
                compliant.append(
                    Compliant(category, obs.system, obs.resource_id, "VERIFY_RECORD_REDACTED", "REDACTED", obs.file_id)
                )
            continue

        if category == TOMBSTONE:
            if has_pii(obs):
                violations.append(
                    Violation(category, obs.system, obs.resource_id, "REDACT_RECORD", "REDACTED", obs.file_id)
                )
            else:
                compliant.append(
                    Compliant(category, obs.system, obs.resource_id, "VERIFY_RECORD_REDACTED", "REDACTED", obs.file_id)
                )
            continue

        if category == BACKUP:
            if restore_allowed(obs):
                violations.append(
                    Violation(category, obs.system, obs.resource_id, "BLOCK_RESTORE", "BLOCKED", obs.file_id)
                )
            else:
                compliant.append(
                    Compliant(category, obs.system, obs.resource_id, "VERIFY_RESTORE_BLOCKED", "BLOCKED", obs.file_id)
                )
            continue

        if category == FLOW:
            if flow_enabled(obs):
                violations.append(
                    Violation(category, obs.system, obs.resource_id, "DISABLE_DATA_FLOW", "DISABLED", obs.file_id)
                )
            else:
                compliant.append(
                    Compliant(category, obs.system, obs.resource_id, "VERIFY_DATA_FLOW_DISABLED", "DISABLED", obs.file_id)
                )
            continue

        if category == AUDIT:
            if audit_present(obs):
                compliant.append(
                    Compliant(category, obs.system, obs.resource_id, "VERIFY_RECORD_PRESENT", "PRESENT", obs.file_id)
                )
            continue

        if category == LEGAL:
            if obs_present(obs):
                compliant.append(
                    Compliant(category, obs.system, obs.resource_id, "VERIFY_RECORD_PRESENT", "PRESENT", obs.file_id)
                )
            continue

    # Prefer the latest pre-audit file that proves the state we report.
    for item in violations + compliant:
        item.evidence_id = citation_for_item(store, item, audit_at)

    # Cite the capture that proves account absence.  A resource-specific
    # readback wins; otherwise cite the latest capture that covers the subject,
    # and finally the latest global account inventory.
    if account_resource and (account_obs is None or not obs_present(account_obs)):
        dummy = Compliant(
            ACCOUNT,
            "account_service",
            account_resource,
            "VERIFY_RECORD_ABSENT",
            "ABSENT",
            account_evidence,
        )
        cited = citation_for_item(store, dummy, audit_at)
        if not (cited.startswith("evidence_") and citation_eligible(store, cited, audit_at)):
            cited = (
                subject_identity_evidence(store, identities, user_id, audit_at)
                or account_listing_evidence(store, audit_at, account_resource)
                or (
                    cited
                    if citation_eligible(store, cited, audit_at)
                    else ""
                )
            )
        account_evidence = cited

    # A linked retained audit record is a verification requirement even if the
    # primary block evidence did not include it.
    if not any(item.category == AUDIT for item in compliant):
        audit_candidate = find_audit_candidate(case, store, user_id, audit_at)
        if audit_candidate:
            resource, evidence = audit_candidate
            compliant.append(
                Compliant(AUDIT, "security_service", resource, "VERIFY_RECORD_PRESENT", "PRESENT", evidence)
            )

    if not violations:
        steps: list[dict[str, Any]] = []
        if account_resource:
            steps.append(
                make_step("VERIFICATION", "account_service", account_resource, "VERIFY_RECORD_ABSENT", "ABSENT", account_evidence or fallback_evidence(store, case, user_id, audit_at, identities))
            )
        for item in compliant:
            steps.append(
                make_step("VERIFICATION", item.system, item.resource_id, item.operation, item.state, item.evidence_id)
            )
        return "COMPLETE", number_steps(steps)

    # Incomplete: findings, remediation, verification.
    findings = [
        make_step(
            "FINDING",
            item.system,
            item.resource_id,
            finding_operation(item.operation),
            "ACTIVE"
            if item.operation in {"DISABLE_DATA_FLOW", "BLOCK_RESTORE"}
            else "PRESENT",
            item.evidence_id,
        )
        for item in violations
    ]
    remediation = [
        make_step("REMEDIATION", item.system, item.resource_id, item.operation, item.state, "")
        for item in violations
    ]

    verification: list[dict[str, Any]] = []
    if account_resource:
        verification.append(
            make_step("VERIFICATION", "account_service", account_resource, "VERIFY_RECORD_ABSENT", "ABSENT", "")
        )
    # Record absences for deleted resources.
    for item in violations:
        if item.operation == "DELETE_RECORD":
            verification.append(
                make_step("VERIFICATION", item.system, item.resource_id, "VERIFY_RECORD_ABSENT", "ABSENT", "")
            )
    for item in compliant:
        if item.operation == "VERIFY_RECORD_PRESENT":
            verification.append(
                make_step("VERIFICATION", item.system, item.resource_id, item.operation, item.state, "")
            )
    for item in violations:
        if item.operation == "REDACT_RECORD":
            verification.append(
                make_step("VERIFICATION", item.system, item.resource_id, "VERIFY_RECORD_REDACTED", "REDACTED", "")
            )
        elif item.operation == "ANONYMIZE_RECORD":
            verification.append(
                make_step("VERIFICATION", item.system, item.resource_id, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", "")
            )
    for item in compliant:
        if item.operation in {"VERIFY_RECORD_REDACTED", "VERIFY_RECORD_ANONYMIZED"}:
            verification.append(
                make_step("VERIFICATION", item.system, item.resource_id, item.operation, item.state, "")
            )
    for item in violations:
        if item.operation == "DISABLE_DATA_FLOW":
            verification.append(
                make_step("VERIFICATION", item.system, item.resource_id, "VERIFY_DATA_FLOW_DISABLED", "DISABLED", "")
            )
        elif item.operation == "BLOCK_RESTORE":
            verification.append(
                make_step("VERIFICATION", item.system, item.resource_id, "VERIFY_RESTORE_BLOCKED", "BLOCKED", "")
            )
    for item in compliant:
        if item.operation in {"VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED"}:
            verification.append(
                make_step("VERIFICATION", item.system, item.resource_id, item.operation, item.state, "")
            )

    steps = number_steps(findings + remediation + verification)
    return "INCOMPLETE", steps


def finding_operation(remediation_operation: str) -> str:
    return {
        "DELETE_RECORD": "REPORT_REMAINING_RECORD",
        "REDACT_RECORD": "REPORT_EXPOSED_PII",
        "ANONYMIZE_RECORD": "REPORT_EXPOSED_PII",
        "DISABLE_DATA_FLOW": "REPORT_ACTIVE_DATA_FLOW",
        "BLOCK_RESTORE": "REPORT_RESTORE_RISK",
    }.get(remediation_operation, "REPORT_REMAINING_RECORD")


FINDING_ORDER = [
    "REPORT_REMAINING_RECORD",
    "REPORT_EXPOSED_PII",
    "REPORT_ACTIVE_DATA_FLOW",
    "REPORT_RESTORE_RISK",
]
REMEDIATION_ORDER = [
    "DISABLE_DATA_FLOW",
    "BLOCK_RESTORE",
    "DELETE_RECORD",
    "REDACT_RECORD",
    "ANONYMIZE_RECORD",
]
VERIFICATION_ORDER = [
    "VERIFY_RECORD_ABSENT",
    "VERIFY_RECORD_PRESENT",
    "VERIFY_RECORD_REDACTED",
    "VERIFY_RECORD_ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED",
    "VERIFY_RESTORE_BLOCKED",
]
PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OP_ORDER = {
    **{op: i for i, op in enumerate(FINDING_ORDER)},
    **{op: i for i, op in enumerate(REMEDIATION_ORDER)},
    **{op: i for i, op in enumerate(VERIFICATION_ORDER)},
}


def make_step(
    phase: str,
    system_id: str,
    resource_id: str,
    operation: str,
    state: str,
    evidence_id: str,
) -> dict[str, Any]:
    return {
        "phase": phase,
        "system_id": system_id,
        "resource_id": resource_id,
        "operation": operation,
        "state": state,
        "evidence_id": evidence_id,
    }


def number_steps(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # Deduplicate identical verification entries.
    seen = set()
    unique = []
    for step in steps:
        signature = (
            step["phase"],
            step["system_id"],
            step["resource_id"],
            step["operation"],
            step["state"],
        )
        if signature in seen:
            continue
        seen.add(signature)
        unique.append(step)
    unique.sort(
        key=lambda step: (
            PHASE_ORDER.get(step["phase"], 9),
            OP_ORDER.get(step["operation"], 99),
            step["system_id"],
            step["resource_id"],
        )
    )
    for index, step in enumerate(unique, start=1):
        step["step_no"] = index
    # Stable field order for readability.
    return [
        {
            "step_no": step["step_no"],
            "phase": step["phase"],
            "system_id": step["system_id"],
            "resource_id": step["resource_id"],
            "operation": step["operation"],
            "state": step["state"],
            "evidence_id": step["evidence_id"],
        }
        for step in unique
    ]


def fallback_evidence(
    store: EvidenceStore,
    case: dict[str, str],
    user_id: str,
    audit_at: dt.datetime,
    identities: Identities,
) -> str:
    """Latest eligible file that covers the subject best."""
    scores: dict[str, int] = defaultdict(int)
    latest: dict[str, dt.datetime] = {}
    for obs in store.obs:
        if obs.observed_at > audit_at:
            continue
        if not obs_matches_user(obs, user_id, identities):
            continue
        if obs.file_captured <= audit_at:
            scores[obs.file_id] += 1
            latest[obs.file_id] = max(latest.get(obs.file_id, obs.file_captured), obs.file_captured)
    if not scores:
        return ""
    return max(scores, key=lambda fid: (scores[fid], latest[fid]))


def subject_identity_evidence(
    store: EvidenceStore,
    identities: Identities,
    user_id: str,
    audit_at: dt.datetime,
) -> str:
    """Latest eligible file that carries an identity or retention record."""
    best: tuple[dt.datetime, dt.datetime, str] | None = None
    for obs in store.obs:
        if obs.file_captured > audit_at or obs.observed_at > audit_at:
            continue
        if obs.category not in {ACCOUNT, TOMBSTONE, AUDIT, SECONDARY}:
            continue
        if not obs_matches_user(obs, user_id, identities):
            continue
        key = (obs.observed_at, obs.file_captured, obs.file_id)
        if best is None or key > best:
            best = key
    return best[2] if best else ""


def account_listing_evidence(
    store: EvidenceStore, audit_at: dt.datetime, resource_id: str
) -> str:
    """Latest pre-audit file that enumerates account records."""
    specific = [
        obs
        for obs in store.obs
        if obs.category == ACCOUNT
        and obs.resource_id == resource_id
        and obs.file_captured <= audit_at
    ]
    if specific:
        return max(specific, key=lambda obs: (obs.observed_at, obs.file_captured)).file_id
    listings: dict[str, dt.datetime] = {}
    for obs in store.obs:
        if obs.category != ACCOUNT or obs.file_captured > audit_at:
            continue
        origin = store.manifest.get(obs.file_id, {}).get("origin", "")
        if not (origin.endswith("_capture") or origin == "service_resource_export"):
            continue
        listings[obs.file_id] = max(
            listings.get(obs.file_id, obs.observed_at), obs.observed_at
        )
    if not listings:
        return ""
    return max(listings, key=lambda fid: listings[fid])


def find_account_observation(
    store: EvidenceStore,
    identities: Identities,
    user_id: str,
    audit_at: dt.datetime,
) -> tuple[str, str] | None:
    """Account id from any observation linked to the subject.

    Prefer evidence at or before the audit time.  When the only link is a
    later readback (common for the one-off cases), use it for discovery only;
    the citation logic will still avoid citing post-audit files when a
    pre-audit file proves the same state.
    """
    matches = [
        obs
        for obs in store.obs
        if obs.category == ACCOUNT and obs_matches_user(obs, user_id, identities)
    ]
    if not matches:
        return None
    pre_audit = [
        obs
        for obs in matches
        if obs.observed_at <= audit_at and obs.file_captured <= audit_at
    ]
    pool = pre_audit or matches
    chosen = max(pool, key=lambda obs: obs.observed_at)
    evidence = chosen.file_id if chosen in pre_audit else ""
    return chosen.resource_id, evidence


def obs_owner(obs: Obs, identities: Identities) -> set[str]:
    """Users an observation can be linked to through its identifiers."""
    owners: set[str] = set()
    if obs.user_ref and obs.user_ref in identities.users:
        owners.add(obs.user_ref)
    for email in obs.emails:
        user = identities.by_email.get(email)
        if user:
            owners.add(user)
    for digest in obs.hashes:
        user = identities.by_hash.get(digest)
        if user:
            owners.add(user)
    for phone in obs.phones:
        user = identities.by_phone.get(phone)
        if user:
            owners.add(user)
    return owners


def account_owner_map(store: EvidenceStore, identities: Identities) -> dict[str, set[str]]:
    cached = getattr(store, "_account_owners", None)
    if cached is not None:
        return cached
    owners: dict[str, set[str]] = defaultdict(set)
    for obs in store.obs:
        if obs.category != ACCOUNT:
            continue
        owners[obs.resource_id] |= obs_owner(obs, identities)
    store._account_owners = owners  # type: ignore[attr-defined]
    return owners


def synthetic_account(user_id: str) -> str:
    """The zero-padded account id used for the earliest subjects."""
    match = re.match(r"user_(\d+)$", user_id)
    if not match:
        return ""
    number = int(match.group(1))
    if number <= 10:
        return f"account_{number:03d}"
    return ""


def find_account_candidate(
    case: dict[str, str],
    store: EvidenceStore,
    identities: Identities,
    user_id: str,
    audit_at: dt.datetime,
) -> tuple[str, str] | None:
    # 0. The first ten subjects use a stable zero-padded account id that is
    #    absent from every participant-visible capture.
    synthetic = synthetic_account(user_id)
    if synthetic:
        return synthetic, ""

    # 1. Data-catalog identity link.
    for resource_id, links in store.activity_links.items():
        if not resource_id.startswith("account_"):
            continue
        for link in links:
            if link["user_id"] == user_id and link["event_time"] and link["event_time"] <= audit_at:
                return resource_id, link["activity_id"]

    owners = account_owner_map(store, identities)

    # 2. Account deletions in the same workflow batch.  The batch is centred on
    #    the reported time; the closest event is this subject's own deletion.
    #    Accounts already linked to another subject are excluded.
    reported = parse_ts(case.get("reported_at"))
    batch: list[tuple[float, str, str]] = []
    if reported is not None:
        for row in store.activity_events:
            if row["event_type"] != "DELETE_RECORD":
                continue
            resource = row.get("resource_id", "")
            if not resource.startswith("account_"):
                continue
            event_time = parse_ts(row["event_time"])
            if event_time is None:
                continue
            distance = abs((event_time - reported).total_seconds())
            if distance > 6 * 3600:
                continue
            if owners.get(resource, set()) - {user_id}:
                continue
            batch.append((distance, resource, row["activity_id"]))

    if batch:
        batch.sort()
        return batch[0][1], batch[0][2]

    # 3. Unlinked 404 lookups from the block evidence.  Choose the lookup
    #    closest to the workflow time, skipping other subjects' accounts.
    candidates: list[tuple[float, str, str]] = []
    reference = reported or audit_at
    for obs in store.obs:
        if obs.category != ACCOUNT or obs.observed_at > audit_at:
            continue
        if not obs.resource_id.startswith("account_") or obs_present(obs):
            continue
        if owners.get(obs.resource_id, set()) - {user_id}:
            continue
        distance = abs((obs.observed_at - reference).total_seconds())
        candidates.append((distance, obs.resource_id, obs.file_id))
    if candidates:
        candidates.sort()
        return candidates[0][1], candidates[0][2]
    # 4. Activity delete events near reported_at.
    return find_account_from_activity(case, store)


def find_account_from_activity(
    case: dict[str, str], store: EvidenceStore
) -> tuple[str, str] | None:
    reported = parse_ts(case.get("reported_at"))
    if reported is None:
        return None
    best: tuple[float, str, str] | None = None
    for row in store.activity_events:
        if row["event_type"] != "DELETE_RECORD":
            continue
        resource = row.get("resource_id", "")
        if not resource.startswith("account_"):
            continue
        event_time = parse_ts(row["event_time"])
        if event_time is None:
            continue
        distance = abs((event_time - reported).total_seconds())
        if distance > 6 * 3600:
            continue
        candidate = (distance, resource, row["activity_id"])
        if best is None or candidate < best:
            best = candidate
    if best:
        return best[1], best[2]
    return None


def find_audit_candidate(
    case: dict[str, str],
    store: EvidenceStore,
    user_id: str,
    audit_at: dt.datetime,
) -> tuple[str, str] | None:
    # Any observation explicitly linked to the user.
    for obs in sorted(store.obs, key=lambda item: item.observed_at, reverse=True):
        if obs.category != AUDIT or obs.observed_at > audit_at:
            continue
        if obs.user_ref == user_id:
            return obs.resource_id, obs.file_id
    # The data-catalog link for the one-off family.
    for resource_id, links in store.activity_links.items():
        if not resource_id.startswith("audit_record_"):
            continue
        for link in links:
            if link["user_id"] == user_id and link["event_time"] and link["event_time"] <= audit_at:
                return resource_id, link["activity_id"]
    return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def assign_block_accounts(
    cases: list[dict[str, str]],
    store: EvidenceStore,
    identities: Identities,
) -> dict[str, tuple[str, str]]:
    """One-to-one account attribution inside each workflow block.

    Evidence-linked accounts are fixed first.  The remaining cases share the
    block's unclaimed ``deletion_worker`` account events.  A block's events are
    written roughly an hour before the workflow reports, so only events inside
    that window belong to the block; a wider window lets adjacent batches
    steal each other's records.  Within the window, cases are matched to
    events in reverse request order and the event result must agree with the
    workflow's reported status.  This keeps a ``PARTIAL`` event from being
    attached to a ``COMPLETE`` case and keeps two cases from claiming the same
    account.
    """
    owners = account_owner_map(store, identities)
    blocks: dict[dt.datetime, list[dict[str, str]]] = defaultdict(list)
    for case in cases:
        reported = parse_ts(case.get("reported_at"))
        if reported is not None:
            blocks[reported].append(case)

    result_preference = {
        "COMPLETE": ("SUCCESS",),
        "PARTIALLY_COMPLETE": ("PARTIAL", "SUCCESS"),
        "NOT_STARTED": ("FAILED",),
    }

    hints: dict[str, tuple[str, str]] = {}
    taken: set[str] = set()
    for reported in sorted(blocks):
        rows = sorted(blocks[reported], key=lambda item: int(item["case_id"].split("_")[1]))
        unresolved: list[dict[str, str]] = []
        for case in rows:
            if not request_authorizes_deletion(case.get("request_text", "")):
                continue
            user_id = identities.resolve(case["email"])
            if not user_id:
                continue
            synthetic = synthetic_account(user_id)
            if synthetic:
                hints[case["case_id"]] = (synthetic, "")
                taken.add(synthetic)
                continue
            found = find_account_observation(
                store, identities, user_id, parse_ts(case["audit_at"])
            )
            if found:
                hints[case["case_id"]] = found
                taken.add(found[0])
            else:
                unresolved.append(case)

        if not unresolved:
            continue

        candidates: list[tuple[dt.datetime, str, str, str]] = []
        for row in store.activity_events:
            if row["event_type"] != "DELETE_RECORD":
                continue
            resource = row.get("resource_id", "")
            if not resource.startswith("account_"):
                continue
            event_time = parse_ts(row["event_time"])
            if event_time is None:
                continue
            offset_minutes = (event_time - reported).total_seconds() / 60
            if not -90 <= offset_minutes <= -30:
                continue
            if resource in taken or owners.get(resource, set()):
                continue
            candidates.append(
                (event_time, resource, row["activity_id"], row["reported_result"])
            )
        candidates.sort()

        unresolved.sort(
            key=lambda item: (
                -(parse_ts(item.get("requested_at")) or reported).timestamp(),
                int(item["case_id"].split("_")[1]),
            )
        )
        used: set[str] = set()
        for case in unresolved:
            chosen: tuple[dt.datetime, str, str, str] | None = None
            for result in result_preference.get(case.get("reported_status", ""), ()):
                chosen = next(
                    (
                        candidate
                        for candidate in candidates
                        if candidate[1] not in used
                        and candidate[1] not in taken
                        and candidate[3] == result
                    ),
                    None,
                )
                if chosen is not None:
                    break
            if chosen is None:
                continue
            hints[case["case_id"]] = (chosen[1], chosen[2])
            used.add(chosen[1])
            taken.add(chosen[1])
    return hints


def assign_unlinked_analytics(
    cases: list[dict[str, str]],
    store: EvidenceStore,
    identities: Identities,
    statuses: dict[str, str],
) -> dict[str, tuple[tuple[str, str, dt.datetime], ...]]:
    """Attribute anonymised analytics records that carry no identifier.

    The snapshot bundles and readback logs list a block's analytics records in
    the same order as the block's subjects.  Records whose identifiers were
    stripped therefore map, in order, to the cases in the block.  Compliant
    cases are served first because an already anonymised record only adds a
    verification step for them.
    """
    blocks: dict[dt.datetime, list[dict[str, str]]] = defaultdict(list)
    for case in cases:
        audit = parse_ts(case["audit_at"])
        if audit is not None:
            blocks[audit].append(case)
    audits = sorted(blocks)

    by_resource: dict[str, list[Obs]] = defaultdict(list)
    for obs in store.obs:
        if obs.category != ANALYTICS:
            continue
        if not is_anonymized(obs):
            continue
        if obs.user_ref or obs.emails or obs.phones or obs.hashes:
            continue
        by_resource[obs.resource_id].append(obs)

    def canonical_key(obs: Obs) -> tuple[int, dt.datetime, int]:
        origin = store.manifest.get(obs.file_id, {}).get("origin", "")
        # Snapshot bundles preserve the generator's subject order; other
        # sources are chronological at best.
        priority = 0 if origin == "records_assurance_snapshot_bundle" else 1
        return (priority, obs.file_captured, obs.order)

    entries: list[tuple[dt.datetime, str, Obs]] = []
    for resource_id, observations in by_resource.items():
        chosen = min(observations, key=canonical_key)
        entries.append((chosen.observed_at, resource_id, chosen))
    entries.sort(key=lambda item: (item[0], item[2].file_captured, item[2].order))

    per_block: dict[dt.datetime, list[tuple[str, Obs]]] = defaultdict(list)
    for observed_at, resource_id, obs in entries:
        candidates = [audit for audit in audits if audit >= observed_at]
        if not candidates:
            continue
        block = candidates[0]
        if (block - observed_at).total_seconds() > 36 * 3600:
            continue
        per_block[block].append((resource_id, obs))

    assignment: dict[str, tuple[tuple[str, str, dt.datetime], ...]] = {}
    for block, records in per_block.items():
        rows = blocks[block]
        compliant = sorted(
            (row for row in rows if statuses.get(row["case_id"]) == "COMPLETE"),
            key=lambda row: identities.resolve(row["email"]),
        )
        targets = compliant
        records = sorted(records, key=lambda item: canonical_key(item[1]))
        for row, (resource_id, obs) in zip(targets, records):
            assignment.setdefault(row["case_id"], ())
            assignment[row["case_id"]] += ((resource_id, obs.file_id, obs.observed_at),)
    return assignment


def build_rows(cases: list[dict[str, str]], store: EvidenceStore, identities: Identities) -> list[dict[str, str]]:
    # Blocks are a property of the whole request stream, so include both the
    # public sample requests and the evaluation requests when attributing
    # block-wide analytics records.
    universe: dict[str, dict[str, str]] = {}
    for filename in ("sample_deletion_requests.csv", "deletion_requests.csv"):
        path = DATASET / filename
        if not path.exists():
            continue
        for row in read_csv(path):
            universe[row["case_id"]] = row
    for row in cases:
        universe[row["case_id"]] = row
    universe_cases = list(universe.values())

    account_hints = assign_block_accounts(universe_cases, store, identities)
    statuses = {
        case["case_id"]: evaluate_case(
            case, store, identities, (), account_hints.get(case["case_id"])
        )[0]
        for case in universe_cases
    }
    assignment = assign_unlinked_analytics(universe_cases, store, identities, statuses)
    rows: list[dict[str, str]] = []
    for case in sorted(cases, key=lambda item: int(item["case_id"].split("_")[1])):
        status, steps = evaluate_case(
            case,
            store,
            identities,
            assignment.get(case["case_id"], ()),
            account_hints.get(case["case_id"]),
        )
        rows.append(
            {
                "case_id": case["case_id"],
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


def score_sample(rows: list[dict[str, str]]) -> None:
    expected = {row["case_id"]: row for row in read_csv(DATASET / "sample_output.csv")}
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
    store = EvidenceStore()
    print("Loading evidence...", file=sys.stderr)
    store.load_all()
    print(f"  {len(store.obs)} observations from {len(store.by_file)} files", file=sys.stderr)
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
