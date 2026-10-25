"""Identity resolution across current and historical identifiers."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ghostaudit.identities import Identities
from tests.fixtures import identity_dataset


class IdentitiesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = identity_dataset(Path(self.tmp.name))
        self.identities = Identities(self.root)

    def test_current_email(self) -> None:
        self.assertEqual(self.identities.resolve("ada@example.com"), "user_1")

    def test_historical_email(self) -> None:
        self.assertEqual(self.identities.resolve("ada.old@example.com"), "user_1")

    def test_case_and_display_name(self) -> None:
        self.assertEqual(self.identities.resolve("Ada Example <ADA@EXAMPLE.COM>"), "user_1")

    def test_unknown_email(self) -> None:
        self.assertEqual(self.identities.resolve("nobody@example.com"), "")

    def test_identifiers_include_history(self) -> None:
        known = self.identities.identifiers("user_2")
        self.assertIn("bea@example.com", known["emails"])
        self.assertIn("5550102000", known["phones"])
        self.assertIn("5550109999", known["phones"])

    def test_unknown_user_has_empty_sets(self) -> None:
        known = self.identities.identifiers("user_missing")
        self.assertEqual(known["emails"], set())


if __name__ == "__main__":
    unittest.main()
