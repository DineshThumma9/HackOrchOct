"""
Facts transcribed from participant-facing screenshots and PDFs.

The dataset ships some evidence as images and PDFs.  The audit agent must use
the facts those artefacts contain, so this module holds the structured facts we
read from each one.  Every entry is grounded in visible text in the artefact;
nothing here comes from organiser-only truth.

``observed_at`` is the moment the artefact itself shows the record (console
capture time, statement time, register time).  When omitted, the manifest
capture time is used.
"""

VISUAL_EVIDENCE = {
    # Customer Operations console: Haruka Sato, user_11 / account_5762, ACTIVE.
    "evidence_04": [
        {
            "category": "USER_PROFILE",
            "system": "account_service",
            "resource_id": "account_5762",
            "user_ref": "user_11",
            "email": "haruka.s1838@zoho.com",
            "phone": "+81 90 7610 2507",
            "account_status": "ACTIVE",
            "observed_at": "2026-09-26T11:00:00Z",
        }
    ],
    # Search console: two hits for g.silva76@gmail.com.
    "evidence_09": [
        {
            "category": "SEARCH_INDEX_ENTRY",
            "system": "search_service",
            "resource_id": "search_428",
            "user_ref": "user_13",
            "display_name": "Gabriel Silva",
            "email": "g.silva76@gmail.com",
            "observed_at": "2026-09-01T06:00:14Z",
        },
        {
            "category": "SEARCH_INDEX_ENTRY",
            "system": "search_service",
            "resource_id": "search_1874",
            "user_ref": "user_13",
            "email": "g.silva76.jr@gmail.com",
            "observed_at": "2026-09-01T06:00:14Z",
        },
    ],
    # BridgeOps connector console: two continuous sync connectors.
    "evidence_14": [
        {
            "category": "DATA_FLOW",
            "system": "integration_service",
            "resource_id": "data_flow_1121",
            "user_ref": "user_14",
            "subject_selector": "jain.aditi@gmail.com",
            "connector_name": "customer-events-to-warehouse",
            "enabled": True,
            "mode": "continuous_sync",
            "observed_at": "2026-08-07T08:00:00Z",
        },
        {
            "category": "DATA_FLOW",
            "system": "integration_service",
            "resource_id": "data_flow_9846",
            "user_ref": "user_15",
            "subject_selector": "lucia-torres@gmail.com",
            "connector_name": "customer-events-to-warehouse",
            "enabled": True,
            "mode": "continuous_sync",
            "observed_at": "2026-08-07T08:00:00Z",
        },
    ],
    # Customer statement PDF: export NST-2026-0718-1842 for Ingrid Dahl.
    "evidence_18": [
        {
            "category": "USER_EXPORT",
            "system": "export_service",
            "resource_id": "export_1842",
            "user_ref": "user_18",
            "owner_email": "ingrid.dahl@outlook.com",
            "file_name": "NST-2026-0718-1842.pdf",
            "download_available": True,
            "observed_at": "2026-07-18T11:00:00Z",
        }
    ],
    # Pulse Analytics profile: Omar Darwish, still attributable by email.
    "evidence_19": [
        {
            "category": "ANALYTICS_PROFILE",
            "system": "analytics_platform",
            "resource_id": "analytics_7438",
            "user_ref": "user_20",
            "email": "darwish.omar@icloud.com",
            "observed_at": "2026-07-13T10:00:00Z",
        }
    ],
    # Download centre: export_1260 is Ready and expires 25 Jun 2026.
    "evidence_23": [
        {
            "category": "USER_EXPORT",
            "system": "export_service",
            "resource_id": "export_1260",
            "user_ref": "user_18",
            "owner_email": "ingrid.dahl@outlook.com",
            "file_name": "customer_export_1260.zip",
            "created_at": "2026-06-18T06:42:00Z",
            "expires_at": "2026-06-25T06:42:00Z",
            "download_available": True,
            "observed_at": "2026-06-18T12:00:00Z",
        }
    ],
    # Helpline console: support_1034 for Kofi Agyeman still shows direct PII.
    "evidence_28": [
        {
            "category": "SUPPORT_MESSAGE",
            "system": "support_platform",
            "resource_id": "support_1034",
            "user_ref": "user_22",
            "requester_name": "Kofi Agyeman",
            "requester_email": "kagyeman8947@fastmail.com",
            "message_excerpt": "Could you let me know where my order is and when it is expected to arrive?",
            "observed_at": "2026-05-24T07:00:00Z",
        }
    ],
    # Vault Recovery Manager: backup_9287 belongs to areed1433@gmail.com and is
    # still restorable (retention ends 26 Jul 2026).
    "evidence_32": [
        {
            "category": "BACKUP_ARCHIVE",
            "system": "backup_service",
            "resource_id": "backup_9287",
            "user_ref": "user_16",
            "customer_email": "areed1433@gmail.com",
            "retention_end": "2026-07-26T00:00:00Z",
            "restore_allowed": True,
            "observed_at": "2026-04-29T09:00:00Z",
        }
    ],
    # Sentinel account events: audit_record_003 is the signed closure record.
    "evidence_37": [
        {
            "category": "SECURITY_AUDIT_LOG",
            "system": "security_service",
            "resource_id": "audit_record_003",
            "user_ref": "user_03",
            "event_name": "account_closure_recorded",
            "integrity": "valid",
            "observed_at": "2026-09-05T07:00:00Z",
        }
    ],
    # Customer Reference Registry: retained customer key for user_17 with no
    # direct identifiers.
    "evidence_42": [
        {
            "category": "ACCOUNT_TOMBSTONE",
            "system": "identity_service",
            "resource_id": "tombstone_17",
            "user_ref": "user_17",
            "reference_type": "customer_key",
            "status": "retained_reference",
            "observed_at": "2026-03-10T06:00:00Z",
        }
    ],
    # Object storage: delivery_confirmation_19.pdf belongs only to user_07.
    "evidence_46": [
        {
            "category": "SUPPORT_ATTACHMENT",
            "system": "object_storage",
            "resource_id": "object_19",
            "user_ref": "user_07",
            "file_name": "delivery_confirmation_19.pdf",
            "observed_at": "2026-02-13T08:00:00Z",
        }
    ],
    # Signed compliance journal extract for audit_record_003.
    "evidence_55": [
        {
            "category": "SECURITY_AUDIT_LOG",
            "system": "security_service",
            "resource_id": "audit_record_003",
            "user_ref": "user_03",
            "event_name": "account_closure_recorded",
            "retention_until": "2027-08-25T04:03:00Z",
            "observed_at": "2026-09-05T06:30:00Z",
        }
    ],
    # Support attachment PDF: delivery address correction for Priya Raman.
    "evidence_58": [
        {
            "category": "SUPPORT_ATTACHMENT",
            "system": "support_platform",
            "resource_id": "support_001",
            "user_ref": "user_07",
            "requester_name": "Priya Raman",
            "requester_email": "priya.raman@gmail.com",
            "requester_phone": "+91 98765 73142",
            "file_name": "delivery_address_correction.pdf",
            "observed_at": "2026-09-12T07:30:00Z",
        }
    ],
    # Audience Operations console: marketing_001 for Kwame Mensah.
    "evidence_60": [
        {
            "category": "MARKETING_PROFILE",
            "system": "marketing_platform",
            "resource_id": "marketing_001",
            "user_ref": "user_09",
            "email": "kwame-mensah@proton.me",
            "phone": "+82 10-5837-9451",
            "email_opt_in": True,
            "observed_at": "2026-09-16T07:20:00Z",
        }
    ],
}
