"""Real browser phone-submit behavior; every HTTP request is handled locally."""

import json
from unittest.mock import Mock

import pytest
from playwright.sync_api import sync_playwright

from openai_reauth import launch_browser
from phone_flow import (
    _response_summary,
    _response_succeeded,
    _submit_and_capture,
    _validation_confirmed,
)


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as playwright:
        instance = launch_browser(playwright, True, None)
        yield instance
        instance.close()


@pytest.mark.parametrize("automatic_delay", [-1, 0, 200, 450])
def test_otp_is_submitted_once_for_manual_and_automatic_forms(browser, automatic_delay):
    page = browser.new_page()
    requests = []
    html = """<html><body>
    <input id="code" autocomplete="one-time-code">
    <button type="button" onclick="verify()">Verify</button>
    <script>
    async function verify() {
      const response = await fetch('/api/accounts/phone-otp/validate', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({code: document.querySelector('#code').value})
      });
      await response.json();
    }
    const delay = DELAY_VALUE;
    if (delay >= 0) document.querySelector('#code').addEventListener('input', event => {
      if (event.target.value.length === 6) setTimeout(verify, delay);
    });
    </script></body></html>""".replace("DELAY_VALUE", str(automatic_delay))

    def respond(route):
        if route.request.url.endswith("/api/accounts/phone-otp/validate"):
            requests.append(route.request.post_data_json)
            route.fulfill(status=200, json={"success": True, "unrelated": "x" * 1500})
        elif route.request.url.endswith("/phone-verification"):
            route.fulfill(status=200, content_type="text/html", body=html)
        else:
            route.fulfill(status=404, body="Local test route not found")

    page.route("**/*", respond)
    try:
        page.goto("https://auth.openai.com/phone-verification")
        status, body = _submit_and_capture(
            page,
            "/api/accounts/phone-otp/validate",
            timeout_ms=3_000,
            before_submit=lambda: page.locator("#code").fill("123456"),
        )
        page.wait_for_timeout(100)
        assert _response_succeeded(status, body)
        assert _validation_confirmed(body)
        assert requests == [{"code": "123456"}]
    finally:
        page.close()


def test_large_success_response_is_parsed_before_summarizing():
    response = Mock(status=200)
    response.json.return_value = {"unrelated": "x" * 10_000, "continue_url": "/consent"}
    status, body = _response_summary(response)
    assert _response_succeeded(status, body)
    assert _validation_confirmed(body)
    assert "unrelated" not in json.loads(body)


def test_large_http_200_error_response_still_rejects_validation():
    response = Mock(status=200)
    response.json.return_value = {"unrelated": "x" * 10_000, "error": {"code": "invalid_code"}}
    status, body = _response_summary(response)
    assert not _response_succeeded(status, body)
    assert "invalid_code" in body


def test_response_text_fallback_parses_whole_json():
    response = Mock(status=200)
    response.json.side_effect = ValueError("json helper unavailable")
    response.text.return_value = json.dumps({"unrelated": "x" * 10_000, "verified": True})
    status, body = _response_summary(response)
    assert _response_succeeded(status, body)
    assert _validation_confirmed(body)
