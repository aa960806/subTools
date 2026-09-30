"""Regression coverage for used orders and binding/cleanup separation."""

import unittest
from unittest.mock import MagicMock, patch

import openai_reauth as core
from phone_pool import PhonePool, PhonePoolError, PhoneSlot, SmsbowerSettings
from phone_smsbower import SmsBowerActivation, SmsBowerClient


class PhoneOrderLifecycleTests(unittest.TestCase):
    def pool(self, used=1, max_reuse=3):
        pool = PhonePool(SmsbowerSettings(api_key="dummy", max_reuse=max_reuse))
        pool.slot = PhoneSlot(pool.settings, phone="+233123456789", activation_id="order-one", reuse_count=used)
        pool.client = MagicMock()
        pool.client.complete.return_value = True
        pool.client.cancel.return_value = True
        return pool

    def test_second_account_timeout_completes_previously_used_number(self):
        pool = self.pool()
        pool.client.wait_for_code.return_value = None
        with self.assertRaisesRegex(RuntimeError, "phone_sms_timeout"):
            pool.wait_code()
        pool.client.complete.assert_called_once_with("order-one")
        pool.client.cancel.assert_not_called()
        self.assertFalse(pool.slot.activation_id)

    def test_stop_during_second_account_completes_previously_used_number(self):
        pool = self.pool()
        with self.assertRaisesRegex(RuntimeError, "sms_cancelled"):
            pool.wait_code(should_stop=lambda: True)
        pool.client.complete.assert_called_once_with("order-one")
        pool.client.cancel.assert_not_called()

    def test_failed_additional_sms_completes_before_buying_new_number(self):
        pool = self.pool()
        pool.client.request_additional.return_value = False
        pool.client.get_number.return_value = SmsBowerActivation("order-two", "+233234567890", "dr", "38")
        self.assertEqual(pool.prepare_for_send(), "+233234567890")
        pool.client.complete.assert_called_once_with("order-one")
        pool.client.cancel.assert_not_called()
        self.assertEqual(pool.slot.activation_id, "order-two")
        self.assertEqual(pool.slot.reuse_count, 0)

    def test_unused_number_is_still_cancelled(self):
        pool = self.pool(used=0)
        pool.cancel_current()
        pool.client.cancel.assert_called_once_with("order-one")
        pool.client.complete.assert_not_called()

    def test_failed_release_of_used_order_records_complete_for_retry(self):
        pool = self.pool()
        pool.client.complete.return_value = False
        pool.cancel_current()
        self.assertEqual(pool.pending_cleanup, {"order-one": "complete"})
        pool.client.cancel.assert_not_called()

    def test_already_closed_order_is_removed_from_pending_cleanup(self):
        pool = self.pool(used=0)
        pool.slot = PhoneSlot(pool.settings)
        client = SmsBowerClient(api_key="dummy")
        client.set_status = MagicMock(return_value="NO_ACTIVATION")
        pool.client = client
        pool.pending_cleanup = {"closed-complete": "complete", "closed-cancel": "cancel"}
        self.assertEqual(pool.cleanup(), {"closed-complete": True, "closed-cancel": True})
        self.assertFalse(pool.pending_cleanup)

    def test_unknown_cleanup_response_keeps_order_for_later_recovery(self):
        client = SmsBowerClient(api_key="dummy")
        client.set_status = MagicMock(return_value="BAD_KEY")
        self.assertFalse(client.complete("order"))
        self.assertFalse(client.cancel("order"))

    def test_failed_journal_save_preserves_confirmed_binding_info(self):
        pool = self.pool(used=0)
        with patch.object(pool, "_save_journal", side_effect=PhonePoolError("sms_cleanup_required", "disk unavailable")):
            with self.assertRaises(PhonePoolError) as caught:
                pool.mark_used()
        self.assertEqual(caught.exception.category, "sms_cleanup_required")
        self.assertEqual(caught.exception.phone_info["status"], "verified")
        self.assertEqual(caught.exception.phone_info["reuse_count"], 1)

    def test_failed_completion_preserves_confirmed_binding_and_stops(self):
        pool = self.pool(used=0, max_reuse=1)
        pool.client.complete.return_value = False
        with self.assertRaises(PhonePoolError) as caught:
            pool.mark_used()
        self.assertEqual(caught.exception.phone_info["status"], "verified")
        self.assertEqual(pool.pending_cleanup, {"order-one": "complete"})

    def test_oauth_result_preserves_binding_through_cleanup_exception_chain(self):
        pool = self.pool(used=0)
        pool._save_journal = MagicMock(side_effect=PhonePoolError("sms_cleanup_required", "disk unavailable"))
        account = core.AccountInput("test@example.com", "dummy", "", 1)
        browser = MagicMock()
        page = browser.new_context.return_value.new_page.return_value
        page.url = "https://auth.openai.com/add-phone"
        callback = MagicMock()
        callback.wait.return_value = None

        def handler(*args, **kwargs):
            try:
                return pool.mark_used()
            except PhonePoolError:
                # Match a failure during defensive cleanup: the first error is
                # available only through __context__, not the top-level error.
                pool.cancel_current()

        with patch.object(core, "page_text", return_value="phone verification required"), \
             patch.object(core, "visible_error_text", return_value=""), \
             patch.object(core, "form_is_busy", return_value=False), \
             patch.object(core, "exchange_code") as exchange, patch.object(core, "log"):
            result = core.reauth_account(browser, callback, account, 30, None, True, phone_handler=handler)
        self.assertFalse(result.ok)
        self.assertEqual(result.phone_status, "verified")
        self.assertEqual(result.category, "sms_cleanup_required")
        self.assertEqual(result.phone_info["reuse_count"], 1)
        self.assertIsNone(result.phone_error)
        exchange.assert_not_called()


if __name__ == "__main__":
    unittest.main()
