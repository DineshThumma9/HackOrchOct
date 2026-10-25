"""Apply the deletion policy to observations and build case steps."""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Any, Callable

from .attribution import (
    account_listing_evidence,
    fallback_evidence,
    find_account_candidate,
    find_account_observation,
    find_audit_candidate,
    subject_identity_evidence,
)
from .evidence import EvidenceStore
from .identities import Identities
from .intent import request_authorizes_deletion
from .model import Obs, parse_ts
from .state import (
    audit_present,
    export_available,
    flow_enabled,
    has_pii,
    is_anonymized,
    is_redacted,
    latest_observations,
    obs_present,
    restore_allowed,
)
from .steps import finding_operation, make_step, number_steps
from .taxonomy import (
    ACCOUNT,
    ANALYTICS,
    AUDIT,
    BACKUP,
    CACHE,
    EMAIL_LOG,
    EXPORT,
    FLOW,
    LEGAL,
    MARKETING,
    SEARCH,
    SECONDARY,
    SUPPORT_ATT,
    SUPPORT_MSG,
    SYSTEM_BY_CATEGORY,
    TOMBSTONE,
)

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


def _violation(obs: Obs, operation: str, state: str) -> Violation:
    return Violation(obs.category, obs.system, obs.resource_id, operation, state, obs.file_id)


def _compliant(obs: Obs, operation: str, state: str) -> Compliant:
    return Compliant(obs.category, obs.system, obs.resource_id, operation, state, obs.file_id)


def _classify_account(obs: Obs, audit_at: dt.datetime) -> Violation | Compliant | None:
    if obs_present(obs):
        return _violation(obs, "DELETE_RECORD", "ABSENT")
    return None


def _classify_delete_if_present(obs: Obs, audit_at: dt.datetime) -> Violation | Compliant | None:
    if obs_present(obs):
        return _violation(obs, "DELETE_RECORD", "ABSENT")
    return None


def _classify_support_message(obs: Obs, audit_at: dt.datetime) -> Violation | Compliant | None:
    if not obs_present(obs):
        return None
    if is_redacted(obs):
        return _compliant(obs, "VERIFY_RECORD_REDACTED", "REDACTED")
    return _violation(obs, "REDACT_RECORD", "REDACTED")


def _classify_analytics(obs: Obs, audit_at: dt.datetime) -> Violation | Compliant | None:
    if is_anonymized(obs):
        return _compliant(obs, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED")
    return _violation(obs, "ANONYMIZE_RECORD", "ANONYMIZED")


def _classify_redactable(obs: Obs, audit_at: dt.datetime) -> Violation | Compliant | None:
    if has_pii(obs):
        return _violation(obs, "REDACT_RECORD", "REDACTED")
    return _compliant(obs, "VERIFY_RECORD_REDACTED", "REDACTED")


def _classify_export(obs: Obs, audit_at: dt.datetime) -> Violation | Compliant | None:
    if export_available(obs, audit_at):
        return _violation(obs, "DELETE_RECORD", "ABSENT")
    return None


def _classify_backup(obs: Obs, audit_at: dt.datetime) -> Violation | Compliant | None:
    if restore_allowed(obs):
        return _violation(obs, "BLOCK_RESTORE", "BLOCKED")
    return _compliant(obs, "VERIFY_RESTORE_BLOCKED", "BLOCKED")


def _classify_flow(obs: Obs, audit_at: dt.datetime) -> Violation | Compliant | None:
    if flow_enabled(obs):
        return _violation(obs, "DISABLE_DATA_FLOW", "DISABLED")
    return _compliant(obs, "VERIFY_DATA_FLOW_DISABLED", "DISABLED")


def _classify_retained(obs: Obs, audit_at: dt.datetime) -> Violation | Compliant | None:
    if obs.category == AUDIT:
        if audit_present(obs):
            return _compliant(obs, "VERIFY_RECORD_PRESENT", "PRESENT")
        return None
    if obs_present(obs):
        return _compliant(obs, "VERIFY_RECORD_PRESENT", "PRESENT")
    return None


def _ignore(obs: Obs, audit_at: dt.datetime) -> Violation | Compliant | None:
    return None


# One rule per data category, so a policy change edits a single small function.
CLASSIFIERS: dict[str, Callable[[Obs, dt.datetime], Violation | Compliant | None]] = {
    ACCOUNT: _classify_account,
    SEARCH: _classify_delete_if_present,
    SECONDARY: _classify_delete_if_present,
    CACHE: _classify_delete_if_present,
    SUPPORT_ATT: _classify_delete_if_present,
    MARKETING: _classify_delete_if_present,
    SUPPORT_MSG: _classify_support_message,
    ANALYTICS: _classify_analytics,
    EMAIL_LOG: _classify_redactable,
    TOMBSTONE: _classify_redactable,
    EXPORT: _classify_export,
    BACKUP: _classify_backup,
    FLOW: _classify_flow,
    AUDIT: _classify_retained,
    LEGAL: _classify_retained,
}


def _resolve_account(
    case: dict[str, str],
    store: EvidenceStore,
    identities: Identities,
    user_id: str,
    audit_at: dt.datetime,
    account_hint: tuple[str, str] | None,
) -> tuple[str, str]:
    """Account resource plus the evidence that proves its state.

    Resolving this before collapsing state lets a later readback of the same
    account (which may not carry the email) win over an older snapshot that
    still shows the account.
    """
    candidate = find_account_observation(store, identities, user_id, audit_at)
    if candidate is None:
        candidate = account_hint or find_account_candidate(
            case, store, identities, user_id, audit_at
        )
    return candidate if candidate else ("", "")


def _current_state(
    store: EvidenceStore,
    identities: Identities,
    user_id: str,
    audit_at: dt.datetime,
    requested_at: dt.datetime | None,
    account_resource: str,
    assigned_analytics: tuple[tuple[str, str, dt.datetime], ...],
) -> dict[tuple[str, str], Obs]:
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
    return latest


def _classify_all(
    latest: dict[tuple[str, str], Obs],
    account_resource: str,
    audit_at: dt.datetime,
) -> tuple[list[Violation], list[Compliant], Obs | None]:
    violations: list[Violation] = []
    compliant: list[Compliant] = []
    account_obs: Obs | None = None

    for obs in latest.values():
        if obs.category == ACCOUNT and account_resource and obs.resource_id != account_resource:
            continue
        if obs.category == ACCOUNT:
            account_obs = obs
        item = CLASSIFIERS.get(obs.category, _ignore)(obs, audit_at)
        if isinstance(item, Violation):
            violations.append(item)
        elif isinstance(item, Compliant):
            compliant.append(item)
    return violations, compliant, account_obs


def _citation_for_account_absence(
    store: EvidenceStore,
    identities: Identities,
    user_id: str,
    audit_at: dt.datetime,
    account_resource: str,
    account_evidence: str,
    account_obs: Obs | None,
) -> str:
    """Cite the capture that proves account absence.

    A resource-specific readback wins; otherwise use the latest capture that
    covers the subject, and finally the latest global account inventory.
    """
    if not account_resource or (account_obs is not None and obs_present(account_obs)):
        return account_evidence

    dummy = Compliant(
        ACCOUNT,
        "account_service",
        account_resource,
        "VERIFY_RECORD_ABSENT",
        "ABSENT",
        account_evidence,
    )
    cited = citation_for_item(store, dummy, audit_at)
    if cited.startswith("evidence_") and citation_eligible(store, cited, audit_at):
        return cited
    return (
        subject_identity_evidence(store, identities, user_id, audit_at)
        or account_listing_evidence(store, audit_at, account_resource)
        or (cited if citation_eligible(store, cited, audit_at) else "")
    )


def _retained_audit_record(
    case: dict[str, str],
    store: EvidenceStore,
    user_id: str,
    audit_at: dt.datetime,
    compliant: list[Compliant],
) -> Compliant | None:
    """A linked retained audit record is required even if block evidence omits it."""
    if any(item.category == AUDIT for item in compliant):
        return None
    candidate = find_audit_candidate(case, store, user_id, audit_at)
    if not candidate:
        return None
    resource, evidence = candidate
    return Compliant(AUDIT, "security_service", resource, "VERIFY_RECORD_PRESENT", "PRESENT", evidence)


def _complete_steps(
    case: dict[str, str],
    store: EvidenceStore,
    identities: Identities,
    user_id: str,
    audit_at: dt.datetime,
    account_resource: str,
    account_evidence: str,
    compliant: list[Compliant],
) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    if account_resource:
        steps.append(
            make_step(
                "VERIFICATION",
                "account_service",
                account_resource,
                "VERIFY_RECORD_ABSENT",
                "ABSENT",
                account_evidence
                or fallback_evidence(store, case, user_id, audit_at, identities),
            )
        )
    for item in compliant:
        steps.append(
            make_step("VERIFICATION", item.system, item.resource_id, item.operation, item.state, item.evidence_id)
        )
    return number_steps(steps)


def _verification_checks(
    violations: list[Violation],
    compliant: list[Compliant],
    account_resource: str,
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    if account_resource:
        checks.append(
            make_step("VERIFICATION", "account_service", account_resource, "VERIFY_RECORD_ABSENT", "ABSENT", "")
        )
    for item in violations:
        if item.operation == "DELETE_RECORD":
            checks.append(make_step("VERIFICATION", item.system, item.resource_id, "VERIFY_RECORD_ABSENT", "ABSENT", ""))
    for item in compliant:
        if item.operation == "VERIFY_RECORD_PRESENT":
            checks.append(make_step("VERIFICATION", item.system, item.resource_id, item.operation, item.state, ""))
    for item in violations:
        if item.operation == "REDACT_RECORD":
            checks.append(make_step("VERIFICATION", item.system, item.resource_id, "VERIFY_RECORD_REDACTED", "REDACTED", ""))
        elif item.operation == "ANONYMIZE_RECORD":
            checks.append(make_step("VERIFICATION", item.system, item.resource_id, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", ""))
    for item in compliant:
        if item.operation in {"VERIFY_RECORD_REDACTED", "VERIFY_RECORD_ANONYMIZED"}:
            checks.append(make_step("VERIFICATION", item.system, item.resource_id, item.operation, item.state, ""))
    for item in violations:
        if item.operation == "DISABLE_DATA_FLOW":
            checks.append(make_step("VERIFICATION", item.system, item.resource_id, "VERIFY_DATA_FLOW_DISABLED", "DISABLED", ""))
        elif item.operation == "BLOCK_RESTORE":
            checks.append(make_step("VERIFICATION", item.system, item.resource_id, "VERIFY_RESTORE_BLOCKED", "BLOCKED", ""))
    for item in compliant:
        if item.operation in {"VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED"}:
            checks.append(make_step("VERIFICATION", item.system, item.resource_id, item.operation, item.state, ""))
    return checks


def _incomplete_steps(
    violations: list[Violation],
    compliant: list[Compliant],
    account_resource: str,
) -> list[dict[str, Any]]:
    findings = [
        make_step(
            "FINDING",
            item.system,
            item.resource_id,
            finding_operation(item.operation),
            "ACTIVE" if item.operation in {"DISABLE_DATA_FLOW", "BLOCK_RESTORE"} else "PRESENT",
            item.evidence_id,
        )
        for item in violations
    ]
    remediation = [
        make_step("REMEDIATION", item.system, item.resource_id, item.operation, item.state, "")
        for item in violations
    ]
    return number_steps(findings + remediation + _verification_checks(violations, compliant, account_resource))


def evaluate_case(
    case: dict[str, str],
    store: EvidenceStore,
    identities: Identities,
    assigned_analytics: tuple[tuple[str, str, dt.datetime], ...] = (),
    account_hint: tuple[str, str] | None = None,
) -> tuple[str, list[dict[str, Any]]]:
    """Classify one case at ``audit_at`` and return its status and steps."""
    audit_at = parse_ts(case["audit_at"])
    if audit_at is None:
        return "INCOMPLETE", []

    if not request_authorizes_deletion(case.get("request_text", "")):
        return "NOT_APPLICABLE", []

    user_id = identities.resolve(case["email"])
    if not user_id:
        return "INCOMPLETE", []

    account_resource, account_evidence = _resolve_account(
        case, store, identities, user_id, audit_at, account_hint
    )
    latest = _current_state(
        store,
        identities,
        user_id,
        audit_at,
        parse_ts(case.get("requested_at")),
        account_resource,
        assigned_analytics,
    )
    violations, compliant, account_obs = _classify_all(latest, account_resource, audit_at)

    # Prefer the latest pre-audit file that proves the state we report.
    for item in violations + compliant:
        item.evidence_id = citation_for_item(store, item, audit_at)

    account_evidence = _citation_for_account_absence(
        store, identities, user_id, audit_at, account_resource, account_evidence, account_obs
    )
    retained = _retained_audit_record(case, store, user_id, audit_at, compliant)
    if retained is not None:
        compliant.append(retained)

    if not violations:
        return "COMPLETE", _complete_steps(
            case, store, identities, user_id, audit_at, account_resource, account_evidence, compliant
        )
    return "INCOMPLETE", _incomplete_steps(violations, compliant, account_resource)
