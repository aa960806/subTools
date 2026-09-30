"""Phone-page recognition against local HTML; no login or paid SMS requests."""
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


@pytest.fixture
def run_html(browser):
    contexts = []

    def run(path, html, **options):
        context = browser.new_context(service_workers="block")
        contexts.append(context)
        context.route("**/*", lambda route: route.fulfill(status=200, content_type="text/html; charset=utf-8", body=html))
        page = context.new_page()
        callback = core.CallbackServer(0)
        session = core.OAuthSession("fixture-state", "fixture-verifier", core.DEFAULT_REDIRECT_URI,
                                    "https://auth.openai.com" + path)
        page.expose_function("fixtureDone", lambda: callback.set_result(
            core.CallbackResult(code="fixture-code", state=session.state)))
        account = core.AccountInput("fixture@example.com", "fixture-password", "JBSWY3DPEHPK3PXP", 1)
        return core.login_with_browser(page, account, session, callback, 6, **options)

    yield run
    for context in contexts:
        context.close()


WORKSPACE = '''<h1>Choose a workspace</h1>
<label>Organization A<input type="radio" name="workspace_id" checked disabled></label>
<button onclick="fixtureDone()">Continue</button>'''


@pytest.mark.parametrize("mode", ["auth", "pool", "phone"])
@pytest.mark.parametrize("notice", [
    "Phone verification is optional. Continue with your authenticator.",
    "You do not need to verify your phone number.",
    "Learn about phone verification in our help center.",
])
def test_workspace_phone_copy_cannot_stop_oauth_or_trigger_sms(run_html, mode, notice):
    handler = Mock()
    options = {"phone_handler": handler} if mode == "phone" else {"skip_phone_verification": mode == "pool"}
    result = run_html("/sign-in-with-chatgpt?next=/add-phone", WORKSPACE + f"<footer>{notice}</footer>", **options)
    assert result.code == "fixture-code"
    handler.assert_not_called()


def test_phone_method_option_does_not_block_authenticator_submission(run_html):
    html = '''<h1>Enter your authenticator code</h1>
    <input name="code" autocomplete="one-time-code">
    <button onclick="if(document.querySelector('input').value.length===6) fixtureDone()">Continue</button>
    <p>Other methods</p><button>Phone verification</button>'''
    assert run_html("/mfa", html).code == "fixture-code"


@pytest.mark.parametrize("path,html,evidence", [
    ("/add-phone", '<h1>添加手机号</h1><input type="tel">', "路由=/add-phone"),
    ("/phone-otp", '<h1>短信验证码</h1><input name="code">', "路由=/phone-otp"),
    ("/verify", '<h1>Add your phone number</h1><input type="tel">', "可见表单=手机号"),
    ("/verify", '<h1>短信验证码</h1><input name="code">', "可见表单=验证码"),
])
def test_real_phone_page_is_classified_without_totp_or_paid_submission(run_html, path, html, evidence):
    handler = Mock()
    with patch.object(core, "fill_otp") as fill:
        with pytest.raises(core.AuthFlowError) as caught:
            run_html(path, html, skip_phone_verification=True, phone_handler=handler)
    assert caught.value.category == "phone_required"
    assert evidence in str(caught.value)
    fill.assert_not_called()
    handler.assert_not_called()


def test_transient_phone_route_is_allowed_to_redirect_to_workspace(run_html):
    html = '''<h1>Add your phone number</h1><input type="tel">
    <script>setTimeout(() => {
      history.replaceState(null, '', '/workspace');
      document.body.innerHTML = `<h1>Choose a workspace</h1>
        <label>Organization A<input type="radio" name="workspace_id" checked disabled></label>
        <button onclick="fixtureDone()">Continue</button>`;
    }, 350);</script>'''
    handler = Mock()
    assert run_html("/add-phone", html, phone_handler=handler).code == "fixture-code"
    handler.assert_not_called()


def test_busy_phone_route_waits_for_redirect_without_buying_a_number(run_html):
    html = '''<h1>Add your phone number</h1><input type="tel">
    <button aria-busy="true">Continue</button>
    <script>setTimeout(() => {
      history.replaceState(null, '', '/workspace');
      document.body.innerHTML = `<h1>Choose a workspace</h1>
        <label>Organization A<input type="radio" name="workspace_id" checked disabled></label>
        <button onclick="fixtureDone()">Continue</button>`;
    }, 1300);</script>'''
    handler = Mock()
    assert run_html("/add-phone", html, phone_handler=handler).code == "fixture-code"
    handler.assert_not_called()


def test_phone_diagnostic_never_contains_url_query_or_form_values(run_html):
    html = '<h1>Add your phone number</h1><input type="tel" value="fixture-private-number">'
    logs = []
    with patch.object(core, "log", side_effect=logs.append):
        with pytest.raises(core.AuthFlowError) as caught:
            run_html("/add-phone?state=fixture-private-state&token=fixture-private-token", html)
    output = "\n".join(logs) + str(caught.value)
    assert "路由=/add-phone" in output
    assert "fixture-private" not in output


@pytest.mark.parametrize("html", [
    '<h1>Phone verification is optional</h1><input type="tel">',
    '<h1 style="display:none">Add your phone number</h1><input type="tel">',
    '<h1>Add your phone number</h1><input type="tel" style="display:none">',
    '<h1>Enter your authenticator code</h1><input type="tel" autocomplete="one-time-code">',
    '<h1>Enter your authenticator code</h1><input name="code"><h2>Phone verification</h2>',
    '<form><legend>Phone verification</legend></form><input name="code">',
])
def test_optional_hidden_or_authenticator_forms_are_not_phone_challenges(browser, html):
    page = browser.new_page()
    try:
        page.set_content(html)
        assert not core.phone_page_evidence(page, "/mfa")
    finally:
        page.close()
