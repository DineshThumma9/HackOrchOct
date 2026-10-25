"""Value helpers and observation normalisation."""

from __future__ import annotations

import datetime as dt
import unittest

from ghostaudit.model import (
    Obs,
    boolish,
    extract_emails,
    infer_category,
    norm_email,
    norm_phone,
    obs_from_record,
    parse_ts,
)
from ghostaudit.taxonomy import ACCOUNT, SUPPORT_ATT, SYSTEM_BY_CATEGORY

UTC = dt.timezone.utc
CAPTURED = dt.datetime(2026, 3, 1, tzinfo=UTC)


class ParseTimestampTest(unittest.TestCase):
    def test_iso_with_z(self) -> None:
        self.assertEqual(parse_ts("2026-09-01T06:00:14Z"), dt.datetime(2026, 9, 1, 6, 0, 14, tzinfo=UTC))

    def test_naive_is_utc(self) -> None:
        self.assertEqual(parse_ts("2026-09-01T06:00:14"), dt.datetime(2026, 9, 1, 6, 0, 14, tzinfo=UTC))

    def test_empty_and_garbage(self) -> None:
        self.assertIsNone(parse_ts(""))
        self.assertIsNone(parse_ts(None))
        self.assertIsNone(parse_ts("yesterday"))


class NormalisationTest(unittest.TestCase):
    def test_email_and_phone(self) -> None:
        self.assertEqual(norm_email("  ADA@Example.COM "), "ada@example.com")
        self.assertEqual(norm_phone("+1 (555) 010-1000"), "5550101000")
        self.assertEqual(norm_phone("123"), "123")

    def test_extract_emails(self) -> None:
        self.assertEqual(
            extract_emails("Contact Ada@Example.com or bea@example.com."),
            {"ada@example.com", "bea@example.com"},
        )

    def test_boolish(self) -> None:
        self.assertIs(boolish("true"), True)
        self.assertIs(boolish("disabled"), False)
        self.assertIs(boolish(1), True)
        self.assertIsNone(boolish("maybe"))
        self.assertIsNone(boolish(""))


class CategoryTest(unittest.TestCase):
    def test_collection_and_record_type(self) -> None:
        self.assertEqual(infer_category("customer_profiles", {}), ACCOUNT)
        self.assertEqual(infer_category("", {"record_type": "SUPPORT_ATTACHMENT"}), SUPPORT_ATT)
        self.assertIsNone(infer_category("unknown", {}))


class ObservationTest(unittest.TestCase):
    def test_support_attachment_identifiers(self) -> None:
        obs = obs_from_record(
            {
                "resource_id": "support_77",
                "record_type": "SUPPORT_ATTACHMENT",
                "uploaded_by": "Ada@Example.com",
                "scan_key": "+1 555 010 1000",
                "email_hash": "c" * 64,
            },
            "support_platform",
            "",
            CAPTURED,
            "evidence_01",
            CAPTURED,
        )
        self.assertIsNotNone(obs)
        assert obs is not None
        self.assertEqual(obs.category, SUPPORT_ATT)
        self.assertEqual(obs.system, SYSTEM_BY_CATEGORY[SUPPORT_ATT])
        self.assertEqual(obs.emails, {"ada@example.com"})
        self.assertIn("5550101000", obs.phones)
        self.assertEqual(obs.hashes, {"c" * 64})

    def test_nested_profile_is_flattened(self) -> None:
        obs = obs_from_record(
            {"resource_id": "account_1", "profile": {"email": "ada@example.com"}},
            "account_service",
            "customer_profiles",
            CAPTURED,
            "evidence_01",
            CAPTURED,
        )
        assert obs is not None
        self.assertEqual(obs.emails, {"ada@example.com"})

    def test_missing_resource_id_is_rejected(self) -> None:
        self.assertIsNone(
            obs_from_record({"email": "ada@example.com"}, "s", "customer_profiles", CAPTURED, "f", CAPTURED)
        )

    def test_key_is_system_and_resource(self) -> None:
        obs = Obs("f", CAPTURED, CAPTURED, "account_service", ACCOUNT, "account_1")
        self.assertEqual(obs.key(), ("account_service", "account_1"))


if __name__ == "__main__":
    unittest.main()
