"""Point-in-time state predicates."""

from __future__ import annotations

import datetime as dt
import unittest

from ghostaudit.model import Obs
from ghostaudit.state import (
    audit_present,
    export_available,
    flow_enabled,
    has_pii,
    is_anonymized,
    is_redacted,
    obs_present,
    restore_allowed,
)

UTC = dt.timezone.utc
CAPTURED = dt.datetime(2026, 3, 1, tzinfo=UTC)


def make_obs(**attrs: object) -> Obs:
    return Obs("evidence_01", CAPTURED, CAPTURED, "s", "USER_PROFILE", "r", attrs=dict(attrs))


class PresentTest(unittest.TestCase):
    def test_explicit_flags(self) -> None:
        self.assertFalse(obs_present(make_obs(present=False)))
        self.assertTrue(obs_present(make_obs(present=True)))

    def test_result_and_status(self) -> None:
        self.assertFalse(obs_present(make_obs(result="not_found")))
        self.assertTrue(obs_present(make_obs(result="FOUND")))
        self.assertFalse(obs_present(make_obs(account_status="DELETED")))

    def test_zero_rows_and_404(self) -> None:
        self.assertFalse(obs_present(make_obs(rows="0")))
        self.assertFalse(obs_present(make_obs(http_status="404")))
        self.assertTrue(obs_present(make_obs()))


class AnonymityTest(unittest.TestCase):
    def test_result_wins(self) -> None:
        self.assertTrue(is_anonymized(make_obs(result="ANONYMIZED")))

    def test_identifiers_mean_not_anonymised(self) -> None:
        obs = make_obs()
        obs.emails = {"ada@example.com"}
        self.assertFalse(is_anonymized(obs))

    def test_explicit_anonymised_wins(self) -> None:
        obs = make_obs(result="ANONYMIZED")
        obs.emails = {"ada@example.com"}
        self.assertTrue(is_anonymized(obs))

    def test_clean_record_is_anonymised(self) -> None:
        self.assertTrue(is_anonymized(make_obs()))


class RedactionTest(unittest.TestCase):
    def test_explicit_redaction(self) -> None:
        self.assertTrue(is_redacted(make_obs(result="REDACTED")))
        self.assertTrue(is_redacted(make_obs(message_text="[REDACTED]")))

    def test_pii_blocks_redaction(self) -> None:
        self.assertFalse(is_redacted(make_obs(message_text="write to ada@example.com")))

    def test_no_pii_counts_as_redacted(self) -> None:
        self.assertTrue(is_redacted(make_obs(message_text="no identifiers left")))


class PiiTest(unittest.TestCase):
    def test_direct_fields(self) -> None:
        self.assertTrue(has_pii(make_obs(email="ada@example.com")))
        self.assertFalse(has_pii(make_obs(email="null")))

    def test_message_text(self) -> None:
        self.assertTrue(has_pii(make_obs(message_text="call +1 555 010 1000")))
        self.assertFalse(has_pii(make_obs(message_text="nothing here")))


class FlowAndRestoreTest(unittest.TestCase):
    def test_flow_states(self) -> None:
        self.assertTrue(flow_enabled(make_obs(result="ACTIVE")))
        self.assertFalse(flow_enabled(make_obs(result="DISABLED")))
        self.assertFalse(flow_enabled(make_obs(enabled=False)))
        self.assertTrue(flow_enabled(make_obs(enabled=True)))
        self.assertFalse(flow_enabled(make_obs(last_delivery_status="stopped")))

    def test_restore_states(self) -> None:
        self.assertFalse(restore_allowed(make_obs(restore_allowed=False)))
        self.assertTrue(restore_allowed(make_obs(deletion_block=False)))
        self.assertFalse(restore_allowed(make_obs(deletion_block=True)))
        self.assertTrue(restore_allowed(make_obs(eligible=True)))
        self.assertFalse(restore_allowed(make_obs()))


class ExportAndAuditTest(unittest.TestCase):
    def test_export(self) -> None:
        self.assertTrue(export_available(make_obs(result="FOUND")))
        self.assertFalse(export_available(make_obs(result="NOT_FOUND")))
        self.assertFalse(export_available(make_obs(status="expired")))
        self.assertFalse(export_available(make_obs(expires_at="2026-02-01T00:00:00Z"), CAPTURED))

    def test_audit_present(self) -> None:
        self.assertFalse(audit_present(make_obs(rows="0")))
        self.assertTrue(audit_present(make_obs(rows="3")))


if __name__ == "__main__":
    unittest.main()
