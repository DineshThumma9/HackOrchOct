"""Unit tests for the attribution heuristics."""

from __future__ import annotations

import datetime as dt
import unittest

from ghostaudit.attribution import (
    account_owner_map,
    assign_block_accounts,
    obs_owner,
    synthetic_account,
)
from ghostaudit.evidence import EvidenceStore
from ghostaudit.identities import Identities
from ghostaudit.model import Obs
from ghostaudit.taxonomy import ACCOUNT


class AttributionTest(unittest.TestCase):
    def test_synthetic_account(self) -> None:
        self.assertEqual(synthetic_account("user_1"), "account_001")
        self.assertEqual(synthetic_account("user_10"), "account_010")
        self.assertEqual(synthetic_account("user_25"), "")
        self.assertEqual(synthetic_account("invalid"), "")
        self.assertEqual(synthetic_account(""), "")

    def test_obs_owner_linking(self) -> None:
        identities = Identities.__new__(Identities)
        identities.by_email = {"ada@example.com": "user_1"}
        identities.by_phone = {"+15550101000": "user_1"}
        identities.by_hash = {}
        identities.users = {"user_1": {"emails": {"ada@example.com"}, "phones": {"+15550101000"}, "hashes": set()}}

        obs = Obs(
            file_id="evidence_01",
            file_captured=dt.datetime(2026, 3, 1, tzinfo=dt.timezone.utc),
            observed_at=dt.datetime(2026, 3, 1, tzinfo=dt.timezone.utc),
            system="account_service",
            category=ACCOUNT,
            resource_id="account_001",
            emails={"ada@example.com"},
        )
        owners = obs_owner(obs, identities)
        self.assertEqual(owners, {"user_1"})

    def test_account_owner_map_caching(self) -> None:
        store = EvidenceStore()
        identities = Identities.__new__(Identities)
        identities.by_email = {"user@example.com": "user_1"}
        identities.by_phone = {}
        identities.by_hash = {}
        identities.users = {"user_1": {"emails": {"user@example.com"}, "phones": set(), "hashes": set()}}

        obs = Obs(
            file_id="evidence_01",
            file_captured=dt.datetime(2026, 3, 1, tzinfo=dt.timezone.utc),
            observed_at=dt.datetime(2026, 3, 1, tzinfo=dt.timezone.utc),
            system="account_service",
            category=ACCOUNT,
            resource_id="account_999",
            emails={"user@example.com"},
        )
        store.obs = [obs]
        self.assertIsNone(store._account_owners)

        owners = account_owner_map(store, identities)
        self.assertEqual(owners["account_999"], {"user_1"})
        # Caching verified
        self.assertIsNotNone(store._account_owners)
        self.assertIs(store._account_owners, owners)

    def test_missing_audit_cutoff_safe(self) -> None:
        store = EvidenceStore()
        identities = Identities.__new__(Identities)
        identities.by_email = {"user@example.com": "user_1"}
        identities.by_phone = {}
        identities.by_hash = {}
        identities.users = {"user_1": {"emails": {"user@example.com"}, "phones": set(), "hashes": set()}}

        # A case with empty audit_at must not raise TypeError
        cases = [
            {
                "case_id": "case_9999",
                "email": "user@example.com",
                "request_text": "Please delete my account",
                "audit_at": "",
                "reported_at": "2026-03-01T12:00:00Z",
                "reported_status": "COMPLETE",
            }
        ]
        hints = assign_block_accounts(cases, store, identities)
        self.assertIsInstance(hints, dict)


if __name__ == "__main__":
    unittest.main()
