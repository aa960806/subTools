"""Phone results must not be confused with a successful OAuth callback."""

import tempfile
import unittest
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import openai_reauth as core
import phone_flow
from phone_pool import PhonePoolError, SmsbowerSettings
from phone_smsbower import SmsBowerError


class PhoneBatchTests(unittest.TestCase):
    def setUp(self):
        self.account = core.AccountInput("test@example.com", "dummy", "", 1)
        self.session = core.OAuthSession("state", "verifier", core.DEFAULT_REDIRECT_URI, "https://auth.openai.com/oauth/authorize")
        self.payload = {"credentials": {"email": self.account.email}}

    def run_account(self, login, handler=None, token_error=None):
        with patch.object(core, "generate_oauth_session", return_value=self.session), \
             patch.object(core, "login_with_browser", side_effect=login), \
             patch.object(core, "exchange_code", side_effect=token_error, return_value={}), \
             patch.object(core, "build_account_payload", return_value=self.payload), \
             patch.object(core, "log"):
            return core.reauth_account(MagicMock(), MagicMock(), self.account, 30, None, True, phone_handler=handler)

    def test_oauth_without_phone_challenge_is_not_binding_success(self):
        callback = core.CallbackResult(code="code", state="state")
        result = self.run_account(lambda *a, **kw: callback, handler=MagicMock())
        self.assertTrue(result.ok)
        self.assertEqual(result.phone_status, "not_triggered")
        self.assertIsNone(result.phone_info)

    def test_default_oauth_keeps_original_success_semantics(self):
        result = self.run_account(lambda *a, **kw: core.CallbackResult(code="code", state="state"))
        self.assertTrue(result.ok)
        self.assertEqual(result.category, "success")
        self.assertEqual(result.phone_status, "not_requested")

    def test_binding_success_survives_later_token_error(self):
        def login(*args, **kwargs):
            kwargs["phone_state"].update(attempted=True, status="verified", info={"status": "verified", "reuse_count": 1})
            return core.CallbackResult(code="code", state="state")

        result = self.run_account(login, handler=MagicMock(), token_error=core.AuthFlowError("network", "换票超时"))
        self.assertFalse(result.ok)
        self.assertEqual(result.phone_status, "verified")
        self.assertIsNone(result.phone_error)
        self.assertEqual(result.error, "换票超时")

    def test_fatal_sms_error_keeps_readable_reason_and_stops_batch(self):
        def login(*args, **kwargs):
            kwargs["phone_state"].update(attempted=True, status="attempted")
            raise core.AuthFlowError("sms_fatal", "SMSBower 余额不足（NO_BALANCE）")

        result = self.run_account(login, handler=MagicMock())
        self.assertEqual(result.category, "sms_fatal")
        self.assertIn("NO_BALANCE", result.error)
        self.assertEqual(result.phone_status, "failed")
        with patch("playwright.sync_api.sync_playwright"), \
             patch.object(core, "CallbackServer"), patch.object(core, "launch_browser"), \
             patch.object(core, "reauth_account", return_value=result) as worker, \
             patch.object(core, "log"):
            results = core.run_batch_reauth([self.account] * 3, recovery_dir=None, phone_handler=MagicMock())
        self.assertEqual(len(results), 1)
        self.assertEqual(worker.call_count, 1)

    def test_phone_handler_is_not_called_twice_on_delayed_redirect(self):
        page = MagicMock()
        page.url = "https://auth.openai.com/add-phone"
        callback = MagicMock()
        done = core.CallbackResult(code="code", state="state")
        callback.wait.side_effect = lambda *_: done if handler.call_count and callback.wait.call_count > 10 else None
        handler = MagicMock(return_value={"status": "verified", "reuse_count": 1})
        state = {}
        with patch.object(core, "page_text", return_value="phone verification required"), \
             patch.object(core, "visible_error_text", return_value=""), \
             patch.object(core, "form_is_busy", return_value=False), \
             patch.object(core, "log"):
            result = core.login_with_browser(page, self.account, self.session, callback, 30, phone_handler=handler, phone_state=state)
        self.assertIs(result, done)
        handler.assert_called_once()
        self.assertEqual(state["status"], "verified")
        self.assertIn("deadline", handler.call_args.kwargs)

    def test_rate_limit_on_phone_route_does_not_buy_a_number(self):
        page = MagicMock()
        page.url = "https://auth.openai.com/add-phone"
        callback = MagicMock()
        callback.wait.return_value = None
        handler = MagicMock()
        with patch.object(core, "page_text", return_value="Too many login attempts. Try again later."), \
             patch.object(core, "visible_error_text", return_value=""), patch.object(core, "log"):
            with self.assertRaises(core.AuthFlowError) as caught:
                core.login_with_browser(page, self.account, self.session, callback, 30, phone_handler=handler)
        self.assertEqual(caught.exception.category, "rate_limited")
        handler.assert_not_called()

    def test_default_authorization_still_skips_phone_page(self):
        page = MagicMock()
        page.url = "https://auth.openai.com/add-phone"
        callback = MagicMock()
        callback.wait.return_value = None
        with patch.object(core, "page_text", return_value="phone verification required"), \
             patch.object(core, "visible_error_text", return_value=""), \
             patch.object(core, "form_is_busy", return_value=False), patch.object(core, "log"):
            with self.assertRaises(core.AuthFlowError) as caught:
                core.login_with_browser(page, self.account, self.session, callback, 30)
        self.assertEqual(caught.exception.category, "phone_required")
        self.assertIn("已确认手机验证页面", str(caught.exception))

    def test_phone_batch_always_closes_pool_and_supplies_journal(self):
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(phone_flow, "PhonePool") as factory, \
             patch.object(phone_flow, "run_batch_reauth", side_effect=RuntimeError("test failure")):
            factory.return_value.close.return_value = {}
            with self.assertRaisesRegex(RuntimeError, "test failure"):
                phone_flow.run_batch_phone_verify([self.account], SmsbowerSettings(api_key="dummy"), recovery_dir=folder)
            factory.return_value.close.assert_called_once()
            self.assertEqual(factory.call_args.kwargs["journal_path"], Path(folder) / "phone-orders.json")

    def test_report_checkpoints_binding_before_later_batch_failure(self):
        result = core.ReauthResult(self.account.email, False, error="换票超时", category="network", phone_status="verified", phone_info={"phone": "+233123456789", "reuse_count": 1})

        def batch(*args, **kwargs):
            kwargs["on_progress"](1, 3, result)
            raise RuntimeError("later browser failure")

        with tempfile.TemporaryDirectory() as folder, \
             patch.object(phone_flow, "PhonePool") as factory, \
             patch.object(phone_flow, "run_batch_reauth", side_effect=batch), \
             patch.object(phone_flow, "log"):
            factory.return_value.close.return_value = {"unreleased": False}
            with self.assertRaisesRegex(RuntimeError, "later browser failure"):
                phone_flow.run_batch_phone_verify([self.account] * 3, SmsbowerSettings(api_key="private-test-key"), recovery_dir=folder)
            report_file = next(Path(folder).glob("phone-results-*.json"))
            text = report_file.read_text(encoding="utf-8")
            report = json.loads(text)
        self.assertEqual(report["attempted"], 1)
        self.assertEqual(report["unattempted"], 2)
        self.assertEqual(report["results"][0]["phone_status"], "verified")
        self.assertFalse(report["results"][0]["oauth_ok"])
        self.assertEqual(report["pending_cleanup_count"], 1)
        self.assertTrue(report["finished_at"])
        self.assertNotIn("private-test-key", text)
        self.assertNotIn(self.account.password, text)

    def test_phone_handler_preserves_safe_provider_error_categories(self):
        for error in (SmsBowerError("sms_fatal", "余额不足"), PhonePoolError("sms_cleanup_required", "订单未释放")):
            with self.subTest(category=error.category), \
                 patch.object(phone_flow, "complete_phone_on_page", side_effect=error):
                handler = phone_flow.make_phone_handler(MagicMock())
                with self.assertRaises(core.AuthFlowError) as caught:
                    handler(MagicMock(), self.account)
                self.assertEqual(caught.exception.category, error.category)
                self.assertEqual(str(caught.exception), str(error))


if __name__ == "__main__":
    unittest.main()
