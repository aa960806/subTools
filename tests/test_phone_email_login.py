"""Mailbox login input support, without accessing real accounts or inboxes."""

from pathlib import Path
import json
import sys
import time
import unittest
from unittest.mock import MagicMock, patch

import pytest
from playwright.sync_api import sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import openai_reauth as core
from phone_flow import parse_phone_jobs


MAILBOX_URL = "https://fake.example/messages/private-test-token/user@example.com"


class MailboxInputTests(unittest.TestCase):
    def test_plain_mailbox_url_is_not_treated_as_password(self):
        for scheme in ("http", "https"):
            with self.subTest(scheme=scheme):
                url = MAILBOX_URL.replace("https:", scheme + ":")
                job = parse_phone_jobs("user@example.com----" + url)[0]
                self.assertEqual(job.email, "user@example.com")
                self.assertEqual(job.mailbox_url, url)
                self.assertEqual(job.password, "")
                self.assertEqual(job.totp_secret, "")

    def test_markdown_mailbox_link_preserves_destination(self):
        text = "user@example.com----[邮箱接码地址](" + MAILBOX_URL + ")"
        job = parse_phone_jobs(text)[0]
        self.assertEqual(job.mailbox_url, MAILBOX_URL)
        self.assertEqual(job.password, "")

    def test_user_pasted_markdown_escapes_are_normalized(self):
        url = "http://fake.example/messages/private_token/user_name@example.com"
        text = r"user\_name\@example.com----[" + url.replace("_", r"\_") + "](" + url + ")"
        job = parse_phone_jobs(text)[0]
        self.assertEqual(job.email, "user_name@example.com")
        self.assertEqual(job.mailbox_url, url)

    def test_mixed_mailbox_and_password_lines_keep_login_material_separate(self):
        jobs = parse_phone_jobs(
            "# fixture accounts\n"
            "user@example.com----" + MAILBOX_URL + "\n"
            "password@example.com----password-value\n"
            "totp@example.com----another-password----JBSWY3DPEHPK3PXP\n"
        )
        self.assertEqual(len(jobs), 3)
        self.assertEqual(jobs[0].source_line, 2)
        self.assertEqual(jobs[0].mailbox_url, MAILBOX_URL)
        self.assertEqual(jobs[1].password, "password-value")
        self.assertEqual(jobs[1].mailbox_url, "")
        self.assertEqual(jobs[2].totp_secret, "JBSWY3DPEHPK3PXP")
        self.assertEqual(jobs[2].mailbox_url, "")

    def test_non_http_text_preserves_existing_password_semantics(self):
        job = parse_phone_jobs("user@example.com----ftp://ordinary-password")[0]
        self.assertEqual(job.password, "ftp://ordinary-password")
        self.assertEqual(job.mailbox_url, "")

    def test_mailbox_url_is_not_exposed_by_account_repr(self):
        job = core.AccountInput("user@example.com", "password-value", "totp-value", 1, mailbox_url=MAILBOX_URL)
        displayed = repr(job)
        self.assertNotIn("private-test-token", displayed)
        self.assertNotIn("password-value", displayed)
        self.assertNotIn("totp-value", displayed)

    def test_existing_positional_account_input_remains_valid(self):
        job = core.AccountInput("user@example.com", "password-value", "", 1)
        self.assertEqual(job.mailbox_url, "")


class DefaultAuthorizationIsolationTests(unittest.TestCase):
    def setUp(self):
        self.account = core.AccountInput("user@example.com", "", "", 1, mailbox_url=MAILBOX_URL)
        self.session = core.OAuthSession("state", "verifier", core.DEFAULT_REDIRECT_URI, "https://auth.openai.com/oauth/authorize")
        self.page = MagicMock()
        self.page.url = "https://auth.openai.com/email-verification"
        self.callback = MagicMock()
        self.callback.wait.return_value = None

    def test_default_authorization_does_not_automatically_read_mailbox(self):
        mailbox_module = MagicMock()
        with patch.dict(sys.modules, {"phone_mailbox": mailbox_module}), \
             patch.object(core, "page_text", return_value="Check your inbox. We sent a code to your email."), \
             patch.object(core, "visible_error_text", return_value=""), \
             patch.object(core, "form_is_busy", return_value=False), \
             patch.object(core, "first_visible", return_value=None), \
             patch.object(core, "maybe_handle_passkey_or_method_picker"), \
             patch.object(core, "maybe_select_workspace", return_value=False), \
             patch.object(core.time, "monotonic", side_effect=range(100)), \
             patch.object(core.time, "sleep"), \
             patch.object(core, "log"):
            with self.assertRaises(core.AuthFlowError) as caught:
                core.login_with_browser(self.page, self.account, self.session, self.callback, 30)
        self.assertEqual(caught.exception.category, "needs_interaction")
        self.assertIn("邮箱验证码", str(caught.exception))
        mailbox_module.MailboxClient.assert_not_called()

    def test_explicit_mailbox_enables_email_login_without_phone_handler(self):
        callback = core.CallbackResult(code="fixture-code", state="state")
        with patch("phone_email_login.EmailLogin") as email_login, \
             patch.object(core, "generate_oauth_session", return_value=self.session), \
             patch.object(core, "login_with_browser", return_value=callback) as login, \
             patch.object(core, "exchange_code", return_value={}), \
             patch.object(core, "build_account_payload", return_value={"credentials": {}}), \
             patch.object(core, "log"):
            result = core.reauth_account(MagicMock(), MagicMock(), self.account, 30, None, True)
        self.assertTrue(result.ok)
        email_login.assert_called_once_with(self.account, None)
        self.assertIs(login.call_args.kwargs.get("email_login"), email_login.return_value)
        self.assertIsNone(login.call_args.kwargs.get("phone_handler"))
        email_login.return_value.close.assert_called_once()


@pytest.fixture(scope="module")
def email_browser():
    with sync_playwright() as playwright:
        browser = core.launch_browser(playwright, True, None)
        yield browser
        browser.close()


EMAIL_HTML = """<!doctype html><html><body><h1>Sign in</h1>
<main><input type="email"><button onclick="startEmail()">Continue</button></main>
<script>
function startEmail() {
  history.pushState({}, '', '/email-verification');
  document.querySelector('h1').textContent = 'Check your inbox';
  document.querySelector('main').innerHTML = '<input name="code" autocomplete="one-time-code"><button onclick="verifyEmail()">Continue</button>';
}
async function verifyEmail() {
  let response = await fetch('/api/accounts/email-otp/validate', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({code: document.querySelector('input').value})
  });
  let body = await response.json();
  if (response.ok && body.continue_url) { location.href = body.continue_url; }
  else { document.querySelector('h1').textContent = 'Incorrect email code'; }
}
</script></body></html>"""


def email_fixture_page(browser, *, validate_status=200):
    page = browser.new_page()
    requests = []

    def respond(route):
        if route.request.url.endswith("/api/accounts/email-otp/validate"):
            requests.append(route.request.post_data_json)
            body = ({"continue_url": core.DEFAULT_REDIRECT_URI + "?code=fixture-code&state=state"}
                    if validate_status == 200 else {"error": {"code": "invalid_code"}})
            route.fulfill(status=validate_status, content_type="application/json", body=json.dumps(body))
        elif route.request.url == "https://auth.openai.com/log-in":
            route.fulfill(status=200, content_type="text/html", body=EMAIL_HTML)
        elif route.request.url.startswith(core.DEFAULT_REDIRECT_URI):
            route.fulfill(status=200, content_type="text/html", body="<h1>Fixture OAuth callback</h1>")
        else:
            route.fulfill(status=404, body="Unexpected fixture route")

    page.route("**/*", respond)
    return page, requests


@pytest.mark.parametrize("validate_status", [200, 400, 429])
def test_browser_email_code_login_uses_mailbox_and_checks_response(email_browser, validate_status):
    from phone_email_login import EmailLogin

    page, requests = email_fixture_page(email_browser, validate_status=validate_status)
    account = core.AccountInput("user@example.com", "", "", 1, mailbox_url=MAILBOX_URL)
    session = core.OAuthSession("state", "verifier", core.DEFAULT_REDIRECT_URI, "https://auth.openai.com/log-in")
    callback = MagicMock()
    callback.wait.return_value = None
    callback.set_result.return_value = True
    phone_handler = MagicMock()
    baseline = object()
    with patch("phone_email_login.MailboxClient") as mailbox_factory, \
         patch.object(core, "fill_otp", side_effect=AssertionError("Email login must not generate TOTP")), \
         patch.object(core, "log"), patch("phone_email_login.log"):
        mailbox = mailbox_factory.return_value
        mailbox.snapshot.return_value = baseline
        mailbox.wait_for_code.return_value = "731905"
        email_login = EmailLogin(account)
        try:
            if validate_status == 200:
                result = core.login_with_browser(page, account, session, callback, 20,
                                                 phone_handler=phone_handler, email_login=email_login)
                assert result.code == "fixture-code"
            else:
                with pytest.raises(core.AuthFlowError) as caught:
                    core.login_with_browser(page, account, session, callback, 20,
                                            phone_handler=phone_handler, email_login=email_login)
                assert caught.value.category == ("rate_limited" if validate_status == 429 else "mailbox_code_rejected")
            assert requests == [{"code": "731905"}]
            mailbox.snapshot.assert_called_once()
            mailbox.wait_for_code.assert_called_once()
            assert mailbox.wait_for_code.call_args.args[0] is baseline
            phone_handler.assert_not_called()
        finally:
            email_login.close()
            page.close()
        mailbox.close.assert_called_once()


def test_email_login_does_not_consume_mailbox_code_for_authenticator_challenge(email_browser):
    from phone_email_login import EmailLogin

    page = email_browser.new_page()
    page.route("**/*", lambda route: route.fulfill(status=200, content_type="text/html",
                                                 body='<h1>Enter your authenticator code</h1><input name="code">'))
    page.goto("https://auth.openai.com/mfa")
    account = core.AccountInput("user@example.com", "", "JBSWY3DPEHPK3PXP", 1, mailbox_url=MAILBOX_URL)
    with patch("phone_email_login.MailboxClient") as mailbox_factory:
        login = EmailLogin(account)
        try:
            assert login.handle_page(page, "Enter your authenticator code", time.monotonic() + 10, None) is False
            mailbox_factory.return_value.wait_for_code.assert_not_called()
        finally:
            login.close()
            page.close()


if __name__ == "__main__":
    unittest.main()
