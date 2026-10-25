"""Evidence manifest loading and format-specific parsers."""
from __future__ import annotations

import datetime as dt
import json
import re
import sqlite3
from collections import defaultdict
from pathlib import Path
from typing import Any

from .config import DATASET
from .model import (
    Obs,
    EMAIL_RE,
    first_value,
    infer_category,
    obs_from_record,
    parse_ts,
    read_csv,
)
from .taxonomy import (
    ACCOUNT,
    ANALYTICS,
    AUDIT,
    BACKUP,
    CACHE,
    COLLECTION_CATEGORY,
    EXPORT,
    FLOW,
    RECORD_TYPE_CATEGORY,
    SEARCH,
    SECONDARY,
    SUPPORT_ATT,
    SUPPORT_MSG,
    SYSTEM_BY_CATEGORY,
    TABLE_SYSTEM,
    guess_service_category,
)
from .visual import load_visual_evidence

class EvidenceStore:
    def __init__(self, dataset: Path = DATASET) -> None:
        self.dataset = Path(dataset)
        self.manifest: dict[str, dict[str, str]] = {}
        self.obs: list[Obs] = []
        self.by_file: dict[str, list[Obs]] = defaultdict(list)
        self.activity_links: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.activity_events: list[dict[str, Any]] = []
        self.errors: list[str] = []
        self._account_owners: dict[str, set[str]] | None = None

    def _error(self, file_id: str, message: str) -> None:
        """Record a skipped artefact instead of silently dropping it."""
        if len(self.errors) < 200:
            self.errors.append(f"{file_id}: {message}")

    # -- manifest ---------------------------------------------------------
    def load_manifest(self) -> None:
        for row in read_csv(self.dataset / "evidence_files.csv"):
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
        except Exception as exc:
            self._error(file_id, f"sql load failed: {exc}")
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
            except Exception as exc:
                self._error(file_id, f"table {table} unreadable: {exc}")
                continue
            for raw in rows:
                record = dict(zip(columns, raw))
                observed = parse_ts(
                    first_value(record, ("updated_at", "indexed_at", "recorded_at", "captured_at"))
                ) or captured
                if "record_json" in record and record["record_json"]:
                    try:
                        payload = json.loads(record["record_json"])
                    except Exception as exc:
                        self._error(file_id, f"record_json in {table}: {exc}")
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
        except Exception as exc:
            self._error(file_id, f"json load failed: {exc}")
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
        except Exception as exc:
            self._error(file_id, f"log read failed: {exc}")
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
        except Exception as exc:
            self._error(file_id, f"handover read failed: {exc}")
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
        captured = parse_ts(self.manifest[file_id]["captured_at"])
        for item in load_visual_evidence().get(file_id, []):
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
        evidence_dir = self.dataset / "evidence"
        for file_id, row in sorted(self.manifest.items()):
            path = evidence_dir / row["file_path"].replace("evidence/", "", 1)
            if not path.exists():
                path = self.dataset / row["file_path"]
            if not path.exists():
                self._error(file_id, f"missing evidence file: {path}")
                continue
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
        for row in read_csv(self.dataset / "system_activity.csv"):
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
            parts = [part.strip() for part in rest.split("|") if part.strip()]
            if len(parts) >= 4:
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
