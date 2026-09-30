"""Keep delayed page timers from submitting a second SMS or OTP request."""

from unittest.mock import Mock

import pytest
from playwright.sync_api import sync_playwright

from openai_reauth import AuthFlowError, launch_browser
from phone_flow import complete_phone_on_page
from phone_request import PhoneSendGuard
from phone_smsbower import SmsBowerActivation
from test_phone_browser import fixture_pool


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as playwright:
        instance = launch_browser(playwright, True, None, phone_workflow=True)
        yield instance
        instance.close()


HTML = '''<html><body><h1>Add your phone number</h1><main>
  <input type="tel"><button onclick="startPhone()">Continue</button></main>
  <script>
  window.sendAttempts = 0; window.validateAttempts = 0; window.afterResult = false;
  window.lateSendAfterResult = false; window.lateValidateAfterResult = false;
  let chosenPhone = '';
  async function sendNumber() {
    window.sendAttempts++;
    if (window.sendAttempts > 1) window.lateSendAfterResult = window.afterResult;
    return fetch('/api/accounts/add-phone/send', {
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({phone_number:chosenPhone, channel:'sms'})});
  }
  async function startPhone() {
    chosenPhone = document.querySelector('input[type=tel]').value;
    const response = await sendNumber();
    await response.json();
    history.pushState({},'', '/phone-verification');
    document.querySelector('main').innerHTML =
      '<input name="code" autocomplete="one-time-code"><button onclick="validateCode()">Verify</button>';
    const code = document.querySelector('[name=code]');
    if (OTP_DELAY >= 0) code.addEventListener('input', () => {
      if (code.value.length === 6) setTimeout(() => validateCode().catch(() => {}), OTP_DELAY);
    });
  }
  async function validateCode() {
    window.validateAttempts++;
    if (window.validateAttempts > 1) window.lateValidateAfterResult = window.afterResult;
    const response = await fetch('/api/accounts/phone-otp/validate', {
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({code:document.querySelector('[name=code]').value})});
    await response.json();
    if (LATE_SEND) setTimeout(() => sendNumber().catch(() => {}), 750);
  }
  </script></body></html>'''


@pytest.mark.parametrize("otp_delay,late_send", [(900, False), (-1, True), (900, True)])
def test_successful_binding_blocks_late_otp_and_resend_until_page_closes(browser, tmp_path, otp_delay, late_send, capsys):
    context = browser.new_context(service_workers="block")
    page = context.new_page()
    forwarded = []
    html = HTML.replace("OTP_DELAY", str(otp_delay)).replace("LATE_SEND", str(late_send).lower())

    def respond(route):
        if route.request.url.endswith("/api/accounts/add-phone/send"):
            forwarded.append(("send", route.request.post_data_json))
            route.fulfill(json={"continue_url": "/phone-verification"})
        elif route.request.url.endswith("/api/accounts/phone-otp/validate"):
            forwarded.append(("validate", route.request.post_data_json))
            route.fulfill(json={"success": True})
        elif route.request.url == "https://auth.openai.com/add-phone":
            route.fulfill(content_type="text/html", body=html)
        else:
            route.fulfill(status=404, body="Local fixture route not found")

    # The context intercepts every request, including any new page or popup.
    context.route("**/*", respond)
    pool = fixture_pool(tmp_path)
    pool.client.get_number.side_effect = [SmsBowerActivation("guard-lifetime-fixture", "+12025550123", "dr", "187")]
    try:
        page.goto("https://auth.openai.com/add-phone")
        result = complete_phone_on_page(page, pool)
        assert result["status"] == "verified"
        assert result["reuse_count"] == 1
        page.evaluate("window.afterResult = true")
        # Both timers fire after complete_phone_on_page has already returned.
        page.wait_for_timeout(1_100)
        assert forwarded == [
            ("send", {"phone_number": "+12025550123", "channel": "sms"}),
            ("validate", {"code": "123456"}),
        ]
        assert page.evaluate("window.validateAttempts") == (2 if otp_delay >= 0 else 1)
        assert page.evaluate("window.sendAttempts") == (2 if late_send else 1)
        if otp_delay >= 0:
            assert page.evaluate("window.lateValidateAfterResult") is True
        if late_send:
            assert page.evaluate("window.lateSendAfterResult") is True
        pool.client.wait_for_code.assert_called_once()
        assert "123456" not in capsys.readouterr().out
    finally:
        pool.close()
        context.close()


@pytest.mark.parametrize("verified", [False, True])
def test_guard_cleanup_failure_stops_retry_and_preserves_confirmed_binding(verified):
    page = Mock()
    page.unroute.side_effect = RuntimeError("synthetic-private-cleanup-details")
    original = AuthFlowError("phone_rejected", "OpenAI 拒绝该手机号")
    if verified:
        original.phone_info = {"status": "verified", "reuse_count": 1}
    with pytest.raises(AuthFlowError) as caught:
        with PhoneSendGuard(page, "+12025550123", Mock()):
            raise original
    assert caught.value.category == "needs_interaction"
    assert "synthetic-private-cleanup-details" not in str(caught.value)
    assert "+12025550123" not in str(caught.value)
    if verified:
        assert caught.value.phone_info == original.phone_info
