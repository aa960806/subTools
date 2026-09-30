"""Phone binding state and paid-activation lifecycle; no external requests."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import phone_flow
from openai_reauth import AuthFlowError
from phone_pool import PhonePool, PhonePoolError, PhoneSlot, SmsbowerSettings


class PhoneLifecycleTests(unittest.TestCase):
    def make_pool(self, journal=None, used=0):
        settings = SmsbowerSettings(api_key="fake", max_reuse=3, number_attempts=1)
        pool = PhonePool(settings, journal_path=journal)
        pool.client = Mock()
        pool.slot = PhoneSlot(settings, phone="+233123456789", activation_id="order-1", reuse_count=used)
        return pool

    def test_close_completes_used_number_below_reuse_limit(self):
        pool = self.make_pool(used=1)
        pool.client.complete.return_value = True
        self.assertEqual(pool.close(), {})
        pool.client.complete.assert_called_once_with("order-1")
        pool.client.cancel.assert_not_called()

    def test_failed_cancel_is_recoverable_and_blocks_new_purchase(self):
        with tempfile.TemporaryDirectory() as folder:
            journal = Path(folder) / "orders.json"
            pool = self.make_pool(journal=journal)
            pool.client.cancel.return_value = False
            pool.cancel_current()
            self.assertEqual(pool.pending_cleanup, {"order-1": "cancel"})
            saved = journal.read_text(encoding="utf-8")
            self.assertNotIn('"fake"', saved)
            restored = PhonePool(pool.settings, journal_path=journal)
            restored.client = Mock()
            restored.client.cancel.return_value = False
            with self.assertRaises(PhonePoolError) as error:
                restored.prepare_for_send()
            self.assertEqual(error.exception.category, "sms_cleanup_required")
            restored.client.get_number.assert_not_called()
            restored.client.cancel.return_value = True
            self.assertEqual(restored.close(), {})
            self.assertEqual(json.loads(journal.read_text(encoding="utf-8")), [])

    def test_unknown_buy_response_does_not_repeat_purchase(self):
        pool = self.make_pool()
        pool.slot = PhoneSlot(pool.settings)
        pool.settings.number_attempts = 3
        pool.client.get_number.side_effect = RuntimeError("network result unknown")
        with self.assertRaises(PhonePoolError) as error:
            pool.prepare_for_send()
        self.assertEqual(error.exception.category, "sms_network")
        self.assertEqual(pool.client.get_number.call_count, 1)

    def test_fatal_provider_error_is_preserved(self):
        pool = self.make_pool()
        pool.slot = PhoneSlot(pool.settings)
        pool.client.get_number.side_effect = RuntimeError("NO_BALANCE")
        with self.assertRaises(PhonePoolError) as error:
            pool.prepare_for_send()
        self.assertEqual(error.exception.category, "sms_fatal")


class PhoneVerificationTests(unittest.TestCase):
    def setUp(self):
        self.pool = Mock()
        self.pool.settings = SmsbowerSettings(api_key="fake", number_attempts=1)
        self.pool.prepare_for_send.return_value = "+233123456789"
        self.pool.wait_code.return_value = "123456"
        self.pool.mark_used.return_value = {"phone": "+233123456789", "reuse_count": 1, "max_reuse": 3}
        self.page = Mock(url="https://auth.openai.com/add-phone")
        guard_patch = patch.object(phone_flow, "PhoneSendGuard")
        guard_patch.start()
        self.addCleanup(guard_patch.stop)
        for target, value in (
            ("first_visible", Mock()), ("_fill_phone_number", True),
            ("ensure_sms_channel", "sms"),
            ("form_is_busy", False), ("visible_error_text", ""),
        ):
            patcher = patch.object(phone_flow, target, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_validation_error_never_counts_binding(self):
        with patch.object(phone_flow, "_submit_and_capture", side_effect=[(200, "{}"), (400, '{"error":{"code":"invalid_code"}}')]):
            with self.assertRaises(AuthFlowError):
                phone_flow.complete_phone_on_page(self.page, self.pool)
        self.pool.mark_used.assert_not_called()
        self.pool.cancel_current.assert_called()

    def test_business_error_in_http_200_never_counts_binding(self):
        with patch.object(phone_flow, "_submit_and_capture", side_effect=[(200, "{}"), (200, '{"error":{"code":"invalid_code"}}')]):
            with self.assertRaises(AuthFlowError):
                phone_flow.complete_phone_on_page(self.page, self.pool)
        self.pool.mark_used.assert_not_called()

    def test_confirmed_validation_counts_exactly_once(self):
        with patch.object(phone_flow, "_submit_and_capture", side_effect=[(200, "{}"), (200, '{"continue_url":"/consent"}')]):
            result = phone_flow.complete_phone_on_page(self.page, self.pool)
        self.assertEqual(result["status"], "verified")
        self.pool.mark_used.assert_called_once()

    def test_missing_phone_form_does_not_buy_number(self):
        with patch.object(phone_flow, "first_visible", return_value=None):
            with self.assertRaises(AuthFlowError):
                phone_flow.complete_phone_on_page(self.page, self.pool)
        self.pool.prepare_for_send.assert_not_called()

    def test_rate_limit_does_not_buy_replacement(self):
        self.pool.settings.number_attempts = 3
        with patch.object(phone_flow, "_submit_and_capture", return_value=(429, '{"error":"rate_limit"}')):
            with self.assertRaises(AuthFlowError) as error:
                phone_flow.complete_phone_on_page(self.page, self.pool)
        self.assertEqual(error.exception.category, "rate_limited")
        self.assertEqual(self.pool.prepare_for_send.call_count, 1)

    def test_fraud_does_not_buy_replacement(self):
        self.pool.settings.number_attempts = 3
        with patch.object(phone_flow, "_submit_and_capture", return_value=(400, '{"error":"fraud_guard"}')):
            with self.assertRaises(AuthFlowError) as error:
                phone_flow.complete_phone_on_page(self.page, self.pool)
        self.assertEqual(error.exception.category, "phone_fraud")
        self.assertEqual(self.pool.prepare_for_send.call_count, 1)

    def test_expired_deadline_does_not_buy_number(self):
        with self.assertRaises(AuthFlowError) as error:
            phone_flow.complete_phone_on_page(self.page, self.pool, deadline=0)
        self.assertEqual(error.exception.category, "circuit_open")
        self.pool.prepare_for_send.assert_not_called()


if __name__ == "__main__":
    unittest.main()
