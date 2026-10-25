"""Point-in-time state predicates for a single observation."""
from __future__ import annotations

import datetime as dt

from .identities import Identities, obs_matches_user
from .model import Obs, PHONE_RE, boolish, extract_emails, parse_ts
from .evidence import EvidenceStore

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
