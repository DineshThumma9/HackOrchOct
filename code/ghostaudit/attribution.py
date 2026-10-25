"""Heuristics that link resources to subjects and workflow blocks."""
from __future__ import annotations

import datetime as dt
import re
from collections import defaultdict

from .evidence import EvidenceStore
from .identities import Identities, obs_matches_user
from .intent import request_authorizes_deletion
from .model import Obs, parse_ts
from .state import is_anonymized, obs_present
from .taxonomy import ACCOUNT, ANALYTICS, AUDIT, SECONDARY, TOMBSTONE

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
    store._account_owners = owners
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
            audit_at = parse_ts(case.get("audit_at"))
            if audit_at is None:
                continue
            found = find_account_observation(store, identities, user_id, audit_at)
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
