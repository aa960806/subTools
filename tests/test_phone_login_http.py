"""Reject blocked login documents clearly, before any paid phone operation."""
from unittest.mock import Mock, patch

import pytest

import openai_reauth as core
from test_phone_browser import browser


@pytest.mark.parametrize("status,body,category,cloudflare", [
    (403, "Sorry, you have been blocked. Cloudflare Ray ID: fixture-private-id", "needs_interaction", True),
    (403, "Access denied fixture-private-server-text", "needs_interaction", False),
    (429, "Try later", "rate_limited", False),
    (503, "Service unavailable", "network", False),
])
def test_phone_blocked_document_fails_before_phone_or_credentials(browser, status, body, category, cloudflare):
    page = browser.new_page()
    page.route("**/*", lambda route: route.fulfill(status=status, content_type="text/html", body=body))
    callback = Mock()
    callback.wait.return_value = None
    handler = Mock()
    session = core.OAuthSession("fixture-state", "fixture-verifier", core.DEFAULT_REDIRECT_URI,
                                "https://auth.openai.com/oauth/authorize?state=fixture-secret-state")
    try:
        with pytest.raises(core.AuthFlowError) as caught:
            core.login_with_browser(page, core.AccountInput("test@example.com", "fixture-pw", "", 1),
                                    session, callback, 30, phone_handler=handler)
        assert caught.value.category == category
        message = str(caught.value)
        assert f"HTTP {status}" in message
        assert "尚未进入手机号页" in message
        assert ("Cloudflare" in message) is cloudflare
        for secret in ("fixture-private-id", "fixture-secret-state", "fixture-pw", "fixture-private-server-text"):
            assert secret not in message
        callback.wait.assert_not_called()
        handler.assert_not_called()
    finally:
        page.close()


def test_visible_phone_flow_can_continue_after_user_resolves_initial_403(browser):
    page = browser.new_page()
    page.route("**/*", lambda route: route.fulfill(status=403, content_type="text/html", body="Cloudflare"))
    callback = Mock()
    expected = core.CallbackResult(code="fixture-code", state="fixture-state")
    callback.wait.return_value = expected  # manual completion is simulated
    handler = Mock()
    session = core.OAuthSession("fixture-state", "fixture-verifier", core.DEFAULT_REDIRECT_URI, "https://auth.openai.com/oauth/authorize")
    try:
        with patch.object(core, "log") as log:
            result = core.login_with_browser(page, core.AccountInput("test@example.com", "fixture-pw", "", 1),
                                            session, callback, 30, headless=False, phone_handler=handler)
        assert result is expected
        assert any("HTTP 403" in call.args[0] and "人工检查" in call.args[0] for call in log.call_args_list)
        handler.assert_not_called()
    finally:
        page.close()


def test_default_authorization_keeps_existing_navigation_behavior(browser):
    page = browser.new_page()
    page.route("**/*", lambda route: route.fulfill(status=403, content_type="text/html", body="Cloudflare"))
    callback = Mock()
    expected = core.CallbackResult(code="fixture-code", state="fixture-state")
    callback.wait.return_value = expected
    session = core.OAuthSession("fixture-state", "fixture-verifier", core.DEFAULT_REDIRECT_URI, "https://auth.openai.com/oauth/authorize")
    try:
        with patch.object(core, "log") as log:
            assert core.login_with_browser(page, core.AccountInput("test@example.com", "fixture-pw", "", 1),
                                           session, callback, 30) is expected
        assert any('HTTP 403' in call.args[0] for call in log.call_args_list)
        assert all('fixture-pw' not in call.args[0] for call in log.call_args_list)
    finally:
        page.close()
