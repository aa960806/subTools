"""Paid sends must match the purchased number; all browser traffic stays local."""

import json
from unittest.mock import Mock

import pytest
from playwright.sync_api import sync_playwright

from openai_reauth import AuthFlowError, launch_browser
from phone_flow import _submit_and_capture
from phone_request import PhoneSendGuard, check_send_payload, response_diagnostic


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as playwright:
        instance = launch_browser(playwright, True, None, phone_workflow=True)
        yield instance
        instance.close()


@pytest.mark.parametrize("payload", [
    None,
    {"phone_number": "+233241234567"},
    {"phone_number": "+12025550123", "phoneNumber": "+233241234567"},
    {"phone_number": "private-secret+12025550123"},
    {"phone_number": "+12025550123", "channel": "whatsapp"},
    {"phone_number": "+12025550123", "delivery_method": "voice"},
    {"phone_number": "+12025550123", "channel": None},
])
def test_incompatible_payload_is_rejected_without_echoing_values(payload):
    valid, channel, error = check_send_payload(payload, "+12025550123")
    assert not valid
    assert error
    assert "+12025550123" not in error
    assert "private-secret" not in error


@pytest.mark.parametrize("payload", [
    {"phone_number": "+1 (202) 555-0123"},
    {"phoneNumber": "+12025550123", "channel": "sms"},
    {"phone_number": "0012025550123", "delivery_method": "text"},
])
def test_matching_payload_is_accepted(payload):
    assert check_send_payload(payload, "+12025550123")[0]


def local_send_page(browser, payload, *, duplicate=False, status=200, security_headers=True, forwarded_headers=None):
    page = browser.new_page()
    forwarded = []
    headers = {'Content-Type': 'application/json'}
    if security_headers:
        headers.update({
            'openai-sentinel-token': 'synthetic-private-sentinel',
            'oai-device-id': 'synthetic-private-device',
        })
    html = '''<html><head><meta charset="utf-8"></head><body><button onclick="send()">继续</button><script>
      function send() {
        const sendOne = () => fetch('/api/accounts/add-phone/send', {
          method:'POST', headers: HEADERS, body: JSON.stringify(PAYLOAD)
        }).catch(() => {});
        sendOne(); DUPLICATE
      }
    </script></body></html>'''.replace('HEADERS', json.dumps(headers)).replace('PAYLOAD', json.dumps(payload)).replace('DUPLICATE', 'sendOne();' if duplicate else '')

    def respond(route):
        if route.request.url.endswith('/api/accounts/add-phone/send'):
            forwarded.append(route.request.post_data_json)
            if forwarded_headers is not None:
                # header_value() populates absent keys in Playwright's lookup
                # cache; the original array preserves actual header presence.
                forwarded_headers.append({
                    header['name'].lower(): header['value']
                    for header in route.request.headers_array()
                })
            route.fulfill(status=status, json={"success": True} if status == 200 else {"error": {"code": "fraud_guard"}}, headers={"x-request-id": "req_123456789abcdef0"})
        elif route.request.url.endswith('/add-phone'):
            route.fulfill(status=200, content_type='text/html', body=html)
        else:
            route.fulfill(status=404)

    page.route('**/*', respond)
    page.goto('https://auth.openai.com/add-phone')
    return page, forwarded


@pytest.mark.parametrize("payload", [
    {"phone_number": "+233241234567"},
    {"phone_number": "+12025550123", "channel": "whatsapp"},
    {"unknown": "synthetic-private-payload"},
])
def test_wrong_payload_is_aborted_before_server_and_guard_is_removed(browser, payload):
    page, forwarded = local_send_page(browser, payload)
    try:
        with pytest.raises(AuthFlowError, match="已阻止发送"):
            _submit_and_capture(page, '/api/accounts/add-phone/send', 400, expected_phone='+12025550123')
        assert forwarded == []
        # The guard's cleanup must not remove another handler or leak to a retry.
        page.locator('button').click()
        page.wait_for_timeout(100)
        assert forwarded == [payload]
    finally:
        page.close()


def test_matched_send_preserves_response_code_and_redacts_request_secrets(browser, capsys):
    page, forwarded = local_send_page(browser, {'phone_number': '+12025550123', 'channel': 'sms'}, status=400)
    try:
        status, body = _submit_and_capture(page, '/api/accounts/add-phone/send', 1_000, expected_phone='+12025550123')
        assert status == 400
        assert json.loads(body)['error']['code'] == 'fraud_guard'
        assert len(forwarded) == 1
        output = capsys.readouterr().out
        assert '***0123' in output
        assert 'request_id=req_123456789abcdef0' in output
        assert 'HTTP 400' in output
        assert 'sentinel=有' in output
        for secret in ('+12025550123', 'synthetic-private-sentinel', 'synthetic-private-device'):
            assert secret not in output
    finally:
        page.close()


def test_duplicate_send_is_not_forwarded_twice(browser):
    page, forwarded = local_send_page(browser, {'phone_number': '+12025550123'}, duplicate=True)
    try:
        with PhoneSendGuard(page, '+12025550123', lambda _: None) as guard:
            page.locator('button').click()
            page.wait_for_timeout(100)
        assert len(forwarded) == 1
        assert guard.duplicates == 1
    finally:
        page.close()


@pytest.mark.parametrize('security_headers', [True, False])
def test_guard_forwards_browser_headers_cookies_and_body_unchanged(browser, capsys, security_headers):
    payload = {'phone_number': '+12025550123', 'channel': 'sms', 'extra': 'synthetic-private-extra'}
    forwarded_headers = []
    page, forwarded = local_send_page(
        browser, payload, security_headers=security_headers, forwarded_headers=forwarded_headers,
    )
    page.context.add_cookies([{
        'name': 'synthetic_session', 'value': 'synthetic-private-cookie',
        'url': 'https://auth.openai.com/', 'httpOnly': True, 'secure': True,
    }])
    try:
        status, _ = _submit_and_capture(
            page, '/api/accounts/add-phone/send', 1_000, expected_phone='+12025550123',
        )
        assert status == 200
        assert forwarded == [payload]
        assert len(forwarded_headers) == 1
        headers = forwarded_headers[0]
        assert headers['content-type'] == 'application/json'
        assert headers['cookie'] == 'synthetic_session=synthetic-private-cookie'
        for name, value in (
            ('openai-sentinel-token', 'synthetic-private-sentinel'),
            ('oai-device-id', 'synthetic-private-device'),
        ):
            if security_headers:
                assert headers[name] == value
            else:
                assert name not in headers
        output = capsys.readouterr().out
        assert 'sentinel=' + ('有' if security_headers else '无') in output
        assert '不能据此判断风控原因' in output
        assert 'synthetic-private-' not in output
    finally:
        page.close()


def test_no_send_request_does_not_silently_skip_validation(browser):
    page, forwarded = local_send_page(browser, {'phone_number': '+12025550123'})
    try:
        page.locator('button').evaluate('(button) => button.onclick = null')
        with pytest.raises(AuthFlowError, match='未捕获'):
            _submit_and_capture(page, '/api/accounts/add-phone/send', 300, expected_phone='+12025550123')
        assert forwarded == []
    finally:
        page.close()


def test_response_identifier_does_not_accept_arbitrary_secret():
    response = Mock(url='https://auth.openai.com/api/accounts/add-phone/send')
    response.header_value.return_value = 'synthetic-private-value'
    assert response_diagnostic(response) == '接码发送响应：request_id=未提供'
