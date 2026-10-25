"""Normalised observations and value helpers shared by the pipeline."""
from __future__ import annotations

import csv
import datetime as dt
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .taxonomy import COLLECTION_CATEGORY, RECORD_TYPE_CATEGORY, SYSTEM_BY_CATEGORY

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
