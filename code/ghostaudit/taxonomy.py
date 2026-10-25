"""Data categories, systems and collection/record-type mappings."""
from __future__ import annotations

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
