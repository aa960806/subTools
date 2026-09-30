"""Exercise form selection, request checks and successful binding together."""

import json
from unittest.mock import Mock, patch

import pytest

import phone_flow
from openai_reauth import AccountInput, AuthFlowError
from phone_pool import SmsbowerSettings
from phone_smsbower import SmsBowerActivation
from test_phone_browser import HTML, fixture_pool
from test_phone_request import browser


@pytest.mark.parametrize('country,number,international', [
    ('US', '2025550123', '+12025550123'),
    ('GH', '241234567', '+233241234567'),
])
@pytest.mark.parametrize('delayed_resend', [False, True])
def test_chinese_form_selects_sms_and_correct_country_through_verified_binding(browser, tmp_path, country, number, international, delayed_resend):
    page = browser.new_page()
    requests = []
    fields = '''<select aria-label="国家"><option value="US">美国 +1</option><option value="GH">加纳 +233</option></select>
      <input type="tel" aria-label="电话号码">
      <label><input type="radio" name="delivery" value="sms">短信</label>
      <label><input type="radio" name="delivery" value="whatsapp" checked>WhatsApp</label>'''
    html = HTML.replace('<html>', '<html><head><meta charset="utf-8"></head>')
    html = html.replace('<input type="tel">', fields).replace('>Continue<', '>继续<').replace('>Verify<', '>验证<')
    html = html.replace("phone_number:document.querySelector('input').value", "phone_number:(document.querySelector('select').value==='US'?'+1':'+233')+document.querySelector('input[type=tel]').value, channel:document.querySelector('[name=delivery]:checked').value")
    if delayed_resend:
        html = html.replace('let body = await response.json();', '''let body = await response.json();
          setTimeout(() => fetch('/api/accounts/add-phone/send', {method:'POST',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify({phone_number:PHONE, channel:'sms'})}).catch(() => {}), 200);
        '''.replace('PHONE', json.dumps(international)), 1)

    def respond(route):
        if route.request.url.endswith('/add-phone/send'):
            requests.append(route.request.post_data_json)
            route.fulfill(json={'continue_url': '/phone-verification'})
        elif route.request.url.endswith('/phone-otp/validate'):
            assert route.request.post_data_json == {'code': '123456'}
            route.fulfill(json={'success': True})
        elif route.request.url.endswith('/add-phone'):
            route.fulfill(content_type='text/html', body=html)
        else:
            route.fulfill(status=404)

    page.route('**/*', respond)
    pool = fixture_pool(tmp_path)
    pool.client.get_number.side_effect = [SmsBowerActivation('fixture', international, 'dr', '187' if country == 'US' else '38')]
    if delayed_resend:
        def wait_sms(*args, **kwargs):
            page.wait_for_timeout(350)
            return '123456'
        pool.client.wait_for_code.side_effect = wait_sms
    try:
        page.goto('https://auth.openai.com/add-phone')
        result = phone_flow.complete_phone_on_page(page, pool)
        assert result['status'] == 'verified'
        assert result['reuse_count'] == 1
        assert requests == [{'phone_number': international, 'channel': 'sms'}]
        pool.client.wait_for_code.assert_called_once()
    finally:
        pool.close()
        page.close()


def test_unusable_channel_does_not_purchase_number(browser, tmp_path):
    page = browser.new_page()
    page.route('**/*', lambda route: route.fulfill(status=404))
    page.set_content('<input type="tel"><label><input type="radio" value="whatsapp" checked>WhatsApp</label>')
    pool = fixture_pool(tmp_path)
    try:
        with pytest.raises(AuthFlowError, match='短信'):
            phone_flow.complete_phone_on_page(page, pool)
        pool.client.get_number.assert_not_called()
    finally:
        pool.close()
        page.close()


@pytest.mark.parametrize('override,expected', [
    (None, 'socks5://fixture-user:fixture-password@proxy.example:8080'),
    ('', ''),
    ('http://other.example:8081', 'http://other.example:8081'),
])
@pytest.mark.parametrize('source', ['explicit', 'system'])
def test_batch_has_one_effective_proxy_and_report_contains_only_safe_conditions(tmp_path, override, expected, source):
    original = 'socks5://fixture-user:fixture-password@proxy.example:8080'
    settings = SmsbowerSettings(api_key='fixture-private-key', proxy=original, network_source=source)
    with patch.object(phone_flow, 'PhonePool') as pool, patch.object(phone_flow, 'run_batch_reauth', return_value=[]) as run:
        pool.return_value.close.return_value = {}
        phone_flow.run_batch_phone_verify([AccountInput('test@example.com', 'fixture-password', '', 1)], settings, proxy=override, headless=False, recovery_dir=tmp_path)
    assert pool.call_args.args[0].proxy == expected
    assert run.call_args.kwargs['proxy'] == (expected or None)
    assert settings.proxy == original
    report_text = next(tmp_path.glob('phone-results-*.json')).read_text(encoding='utf-8')
    report = json.loads(report_text)
    assert report['network']['mode'] == ('proxy' if expected else 'direct')
    assert report['network']['source'] == ('override' if override is not None else source)
    assert report['browser_user_agent'] == 'native'
    assert report['headless'] is False
    for secret in ('fixture-user', 'fixture-password', 'proxy.example', 'other.example', 'fixture-private-key'):
        assert secret not in report_text
