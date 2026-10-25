"""The request-text gate between deletion and non-deletion intents."""

from __future__ import annotations

import unittest

from ghostaudit.intent import (
    classify_intent_tev,
    request_authorizes_deletion,
    request_authorizes_deletion_regex,
    set_tev_available,
)


class DeletionIntentTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # Keep unit test suite fast by using the deterministic engine as fallback
        set_tev_available(False)

    @classmethod
    def tearDownClass(cls) -> None:
        set_tev_available(None)

    def test_plain_deletion(self) -> None:
        self.assertTrue(request_authorizes_deletion("Please delete my account and all my data."))
        self.assertTrue(request_authorizes_deletion_regex("Please delete my account and all my data."))

    def test_retention_beats_keyword(self) -> None:
        self.assertFalse(request_authorizes_deletion("I am not asking for deletion, keep the account."))

    def test_access_request(self) -> None:
        self.assertFalse(request_authorizes_deletion("Send me a copy of my data."))

    def test_marketing_opt_out(self) -> None:
        self.assertFalse(request_authorizes_deletion("Unsubscribe me from marketing emails."))

    def test_correction_request(self) -> None:
        self.assertFalse(request_authorizes_deletion("Please update my phone number."))

    def test_multilingual_deletion(self) -> None:
        self.assertTrue(request_authorizes_deletion("Bitte löschen Sie mein Konto."))
        self.assertTrue(request_authorizes_deletion("Quiero eliminar mi cuenta y mis datos."))
        self.assertTrue(request_authorizes_deletion("このメールアドレスに関連するアカウントの完全な削除を依頼します。"))
        self.assertTrue(request_authorizes_deletion("이 이메일 주소에 연결된 계정의 영구 삭제를 요청합니다."))

    def test_empty(self) -> None:
        self.assertFalse(request_authorizes_deletion(""))
        self.assertFalse(request_authorizes_deletion(None))

    def test_tev_fallback_when_unreachable(self) -> None:
        # Use uncached unique string to test network unreachable fallback
        uncached = "unique_uncached_test_string_for_unreachable_network_probe"
        res = classify_intent_tev(uncached, url="http://127.0.0.1:59999/invalid", timeout=0.05)
        self.assertIsNone(res)
        # request_authorizes_deletion with engine='tev' gracefully falls back to regex
        self.assertTrue(request_authorizes_deletion("Please delete my account", engine="tev"))

    def test_tev_primary_with_fallback(self) -> None:
        try:
            set_tev_available(False)
            self.assertTrue(request_authorizes_deletion("Please delete my account."))
            self.assertFalse(request_authorizes_deletion("Do not delete my account."))
        finally:
            set_tev_available(False)


if __name__ == "__main__":
    unittest.main()
