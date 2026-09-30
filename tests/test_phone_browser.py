"""Real Playwright DOM/response tests with every HTTP request intercepted locally."""
import json
from unittest.mock import Mock

import pytest
from playwright.sync_api import sync_playwright

from openai_reauth import AuthFlowError, launch_browser
from phone_flow import complete_phone_on_page, _fill_phone_number
from phone_pool import PhonePool, SmsbowerSettings
from phone_smsbower import SmsBowerActivation


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as playwright:
        instance = launch_browser(playwright, True, None)
        yield instance
        instance.close()


HTML = '''<html><body><h1>Add your phone number</h1><main>
  <input type="tel"><button onclick="sendPhone()">Continue</button></main>
  <script>
  async function sendPhone() {
    let response = await fetch('/api/accounts/add-phone/send', {
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({phone_number:document.querySelector('input').value})});
    let body = await response.json();
    if (!response.ok || body.error) { document.querySelector('h1').textContent='Request failed'; return; }
    history.pushState({},'', '/phone-verification');
    document.querySelector('h1').textContent='Enter SMS code';
    document.querySelector('main').innerHTML='<input name="code" autocomplete="one-time-code"><button onclick="validateCode()">Verify</button>';
  }
  async function validateCode() {
    let response = await fetch('/api/accounts/phone-otp/validate', {
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({code:document.querySelector('input').value})});
    let body = await response.json();
    if (!response.ok || body.error) { document.querySelector('h1').textContent='Incorrect verification code'; return; }
    setTimeout(() => {document.querySelector('h1').textContent='Phone verified';
      document.querySelector('main').innerHTML='';}, 200);
  }
  </script></body></html>'''


def fixture_page(browser, *, send_status=200, send_body=None, validate_status=200, validate_body=None):
    page = browser.new_page()
    requests = []

    def respond(route):
        path = route.request.url
        if path.endswith('/add-phone/send'):
            requests.append(('send', route.request.post_data_json))
            route.fulfill(status=send_status, json=send_body if send_body is not None else {"continue_url": "/phone-verification"})
        elif path.endswith('/phone-otp/validate'):
            requests.append(('validate', route.request.post_data_json))
            route.fulfill(status=validate_status, json=validate_body if validate_body is not None else {"success": True})
        elif path.endswith('/add-phone'):
            route.fulfill(status=200, content_type="text/html", body=HTML)
        else:
            route.fulfill(status=404, body="fixture route not found")

    page.route('**/*', respond)
    page.goto('https://auth.openai.com/add-phone')
    return page, requests


def fixture_pool(tmp_path, max_reuse=2):
    settings = SmsbowerSettings(api_key='fixture-only', max_reuse=max_reuse, number_attempts=1, sms_timeout=2)
    pool = PhonePool(settings, journal_path=tmp_path / 'orders.json')
    pool.client = Mock()
    pool.client.get_number.side_effect = [
        SmsBowerActivation('first', '+233111111111', 'dr', '38'),
        SmsBowerActivation('second', '+233222222222', 'dr', '38'),
    ]
    pool.client.wait_for_code.side_effect = ['123456', '654321', '456123']
    pool.client.complete.return_value = True
    pool.client.cancel.return_value = True
    pool.client.request_additional.return_value = True
    return pool


def test_browser_reuses_number_until_x_confirmed_bindings(browser, tmp_path):
    pool = fixture_pool(tmp_path)
    try:
        for index in range(3):
            page, requests = fixture_page(browser)
            try:
                result = complete_phone_on_page(page, pool)
                assert result['status'] == 'verified'
                assert [kind for kind, body in requests] == ['send', 'validate']
                assert len(requests[1][1]['code']) == 6
                assert pool.client.get_number.call_count == (1 if index < 2 else 2)
            finally:
                page.close()
        pool.client.request_additional.assert_called_once_with('first')
        pool.client.complete.assert_called_once_with('first')
    finally:
        pool.close()
    assert json.loads((tmp_path / 'orders.json').read_text()) == []


@pytest.mark.parametrize('status,body', [(400, {'error': {'code': 'invalid_code'}}), (200, {'success': False}), (200, {'error': {'code': 'invalid_code'}})])
def test_browser_rejected_otp_never_consumes_reuse(browser, tmp_path, status, body):
    pool = fixture_pool(tmp_path)
    page, requests = fixture_page(browser, validate_status=status, validate_body=body)
    try:
        with pytest.raises(AuthFlowError):
            complete_phone_on_page(page, pool)
        assert len(requests) == 2
        assert pool.slot.reuse_count == 0
        pool.client.complete.assert_not_called()
    finally:
        page.close()
        pool.close()


def test_browser_rate_limited_send_never_waits_for_sms(browser, tmp_path):
    pool = fixture_pool(tmp_path)
    page, requests = fixture_page(browser, send_status=429, send_body={'error': {'code': 'rate_limit_exceeded'}})
    try:
        with pytest.raises(AuthFlowError) as caught:
            complete_phone_on_page(page, pool)
        assert caught.value.category == 'rate_limited'
        pool.client.wait_for_code.assert_not_called()
        pool.client.complete.assert_not_called()
        assert len(requests) == 1
    finally:
        page.close()
        pool.close()


def test_browser_retries_sms_timeout_from_otp_page_once(browser, tmp_path):
    pool = fixture_pool(tmp_path)
    pool.settings.number_attempts = 2
    pool.client.wait_for_code.side_effect = [None, '654321']
    page, requests = fixture_page(browser)
    try:
        result = complete_phone_on_page(page, pool)
        assert result['status'] == 'verified'
        assert [kind for kind, body in requests] == ['send', 'send', 'validate']
        assert pool.client.get_number.call_count == 2
        pool.client.cancel.assert_called_once_with('first')
        assert pool.slot.activation_id == 'second'
        assert pool.slot.reuse_count == 1
    finally:
        page.close()
        pool.close()


def test_browser_rejected_number_with_zero_retries_opens_circuit(browser, tmp_path):
    pool = fixture_pool(tmp_path)
    page, requests = fixture_page(browser, send_status=400, send_body={'error': {'code': 'invalid_phone_number'}})
    try:
        with pytest.raises(AuthFlowError) as caught:
            complete_phone_on_page(page, pool)
        assert caught.value.category == 'circuit_open'
        assert len(requests) == 1
        pool.client.get_number.assert_called_once()
        pool.client.cancel.assert_called_once_with('first')
        pool.client.wait_for_code.assert_not_called()
    finally:
        page.close()
        pool.close()


def test_national_number_selects_country_and_checks_canonical_payload(browser):
    page = browser.new_page()
    try:
        page.set_content('''<select onchange="sync()"><option value="US">United States</option>
            <option value="GH">Ghana</option></select>
            <input type="tel" aria-label="National number" oninput="sync()">
            <input type="hidden" name="phoneNumber">
            <script>function sync(){document.querySelector('[name=phoneNumber]').value=
                (document.querySelector('select').value==='GH'?'+233':'+1')+
                document.querySelector('input[type=tel]').value}</script>''')
        assert _fill_phone_number(page, '+233241234567')
        assert page.locator('select').input_value() == 'GH'
        assert page.locator('input[type=tel]').input_value() == '241234567'
        assert page.locator('[name=phoneNumber]').input_value() == '+233241234567'
    finally:
        page.close()


def test_mismatched_hidden_number_blocks_sending(browser):
    page = browser.new_page()
    try:
        page.set_content('<input type="tel"><input type="hidden" name="phoneNumber" value="+19999999999">')
        with pytest.raises(AuthFlowError) as caught:
            _fill_phone_number(page, '+233241234567')
        assert caught.value.category == 'needs_interaction'
    finally:
        page.close()
