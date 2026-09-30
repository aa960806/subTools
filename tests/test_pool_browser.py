"""Local Chromium pages prove pool-mode phone skip and missing-TOTP handling."""

from unittest.mock import Mock, patch

import pytest
from playwright.sync_api import sync_playwright

import openai_reauth as core


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as playwright:
        instance = core.launch_browser(playwright, headless=True, proxy=None)
        yield instance
        instance.close()


def run_page(browser, path, html):
    context = browser.new_context(service_workers="block")
    context.route("**/*", lambda route: route.fulfill(status=200, content_type="text/html", body=html))
    page = context.new_page()
    session = core.OAuthSession("fixture-state", "fixture-verifier", core.DEFAULT_REDIRECT_URI, "https://fixture.test"+path)
    callback = Mock()
    callback.wait.return_value = None
    try:
        with patch.object(core, "fill_otp", side_effect=AssertionError("must not generate TOTP without a secret")):
            with pytest.raises(core.AuthFlowError) as error:
                core.login_with_browser(page, core.AccountInput("fixture@example.com", "fixture-password", "", 1),
                                        session, callback, 3, headless=True, skip_phone_verification=True)
        return error.value
    finally:
        context.close()


def test_phone_url_skips_even_without_english_phone_text(browser):
    error = run_page(browser, "/add-phone", "<h1>添加手机号</h1><input type='tel'><button>继续</button>")
    assert error.category == "phone_required" and "待补手机" in str(error)


def test_missing_totp_requests_interaction_without_submitting_empty_code(browser):
    error = run_page(browser, "/verify", "<h1>Enter code</h1><input autocomplete='one-time-code'><button>Continue</button>")
    assert error.category == "needs_interaction"


def test_deactivated_failure_takes_precedence_over_stale_phone_url(browser):
    error = run_page(browser, "/add-phone", "<h1>Your account has been deactivated</h1>")
    assert error.category == "failed"
