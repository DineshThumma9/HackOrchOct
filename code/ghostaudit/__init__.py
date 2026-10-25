"""Ghost Data Still Exists - deterministic deletion-audit agent.

The pipeline is split into small modules:

``config``       filesystem anchors
``taxonomy``     data categories, systems and collection mappings
``model``        normalised observations and value helpers
``evidence``     manifest loading and format-specific parsers
``identities``   current and historical identifier resolution
``intent``       request-text authorisation check
``state``        point-in-time observation predicates
``steps``        step construction and contract ordering
``policy``       deletion policy evaluation
``attribution``  resource-to-subject and block heuristics
``pipeline``     case orchestration and CSV output
``cli``          command line entry point
"""

from __future__ import annotations

from .attribution import (
    account_listing_evidence,
    account_owner_map,
    assign_block_accounts,
    assign_unlinked_analytics,
    fallback_evidence,
    find_account_candidate,
    find_account_from_activity,
    find_account_observation,
    find_audit_candidate,
    obs_owner,
    subject_identity_evidence,
    synthetic_account,
)
from .cli import main, score_sample
from .config import DATASET, EVIDENCE_DIR, ROOT
from .evidence import EvidenceStore, parse_log_line
from .identities import Identities, obs_matches_user
from .intent import (
    check_tev_available,
    classify_intent_tev,
    is_tev_service_available,
    request_authorizes_deletion,
    request_authorizes_deletion_regex,
    request_authorizes_deletion_tev,
    set_tev_available,
)
from .model import (
    EMAIL_RE,
    PHONE_RE,
    SHA256_RE,
    Obs,
    boolish,
    extract_emails,
    first_value,
    infer_category,
    norm_email,
    norm_phone,
    obs_from_record,
    parse_ts,
    read_csv,
)
from .pipeline import build_rows, write_output
from .policy import (
    Compliant,
    Violation,
    citation_eligible,
    citation_for_item,
    evaluate_case,
)
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
from .steps import (
    FINDING_ORDER,
    OP_ORDER,
    PHASE_ORDER,
    REMEDIATION_ORDER,
    VERIFICATION_ORDER,
    finding_operation,
    make_step,
    number_steps,
)
from .taxonomy import (
    ACCOUNT,
    ANALYTICS,
    AUDIT,
    BACKUP,
    CACHE,
    COLLECTION_CATEGORY,
    EMAIL_LOG,
    EXPORT,
    FLOW,
    LEGAL,
    MARKETING,
    RECORD_TYPE_CATEGORY,
    SEARCH,
    SECONDARY,
    SUPPORT_ATT,
    SUPPORT_MSG,
    SYSTEM_BY_CATEGORY,
    TABLE_SYSTEM,
    TOMBSTONE,
)
from .visual import load_visual_evidence

__all__ = [
    "ACCOUNT",
    "ANALYTICS",
    "AUDIT",
    "BACKUP",
    "CACHE",
    "COLLECTION_CATEGORY",
    "Compliant",
    "DATASET",
    "EMAIL_LOG",
    "EMAIL_RE",
    "EVIDENCE_DIR",
    "EXPORT",
    "EvidenceStore",
    "FINDING_ORDER",
    "FLOW",
    "Identities",
    "LEGAL",
    "MARKETING",
    "OP_ORDER",
    "Obs",
    "PHASE_ORDER",
    "PHONE_RE",
    "RECORD_TYPE_CATEGORY",
    "REMEDIATION_ORDER",
    "ROOT",
    "SEARCH",
    "SECONDARY",
    "SHA256_RE",
    "SUPPORT_ATT",
    "SUPPORT_MSG",
    "SYSTEM_BY_CATEGORY",
    "TABLE_SYSTEM",
    "TOMBSTONE",
    "VERIFICATION_ORDER",
    "Violation",
    "account_listing_evidence",
    "account_owner_map",
    "assign_block_accounts",
    "assign_unlinked_analytics",
    "audit_present",
    "boolish",
    "build_rows",
    "citation_eligible",
    "citation_for_item",
    "evaluate_case",
    "export_available",
    "extract_emails",
    "fallback_evidence",
    "find_account_candidate",
    "find_account_from_activity",
    "find_account_observation",
    "find_audit_candidate",
    "finding_operation",
    "first_value",
    "flow_enabled",
    "has_pii",
    "infer_category",
    "is_anonymized",
    "is_redacted",
    "latest_observations",
    "load_visual_evidence",
    "main",
    "make_step",
    "norm_email",
    "norm_phone",
    "number_steps",
    "obs_from_record",
    "obs_matches_user",
    "obs_owner",
    "obs_present",
    "parse_log_line",
    "parse_ts",
    "read_csv",
    "request_authorizes_deletion",
    "request_authorizes_deletion_regex",
    "request_authorizes_deletion_tev",
    "restore_allowed",
    "score_sample",
    "subject_identity_evidence",
    "synthetic_account",
    "write_output",
]
