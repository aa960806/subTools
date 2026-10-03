"""Failure-boundary regressions for the registration branch merge review."""
import json
import time
from types import SimpleNamespace
from unittest.mock import Mock

import httpx
import pytest

from flow_control import AuthFlowError
from registration_flow import (MicrosoftGraphMailboxClient, PlaywrightRegistrationAdapter,
    RegistrationFlowError, RegistrationPersistenceError, RegistrationResult,
    load_registration_inputs, run_batch_registration, validate_registration_url)
from test_registration_flow import registration_text
from test_web import data, engine, finished


@pytest.mark.parametrize('url', ['http://chatgpt.com/', 'https://chatgpt.com.evil.test/',
    'https://evil.test/?next=auth.openai.com', 'https://chatgpt.com@evil.test/',
    'file:///private.html', 'https://chatgpt.com/#secret'])
def test_registration_rejects_external_entry_and_redirect(engine, url):
    with pytest.raises(ValueError):
        validate_registration_url(url)
    with pytest.raises(ValueError):
        engine.save_config('register', {'signup_url':url})
    page = SimpleNamespace(url=url, locator=Mock(side_effect=AssertionError('must not inspect input')))
    assert PlaywrightRegistrationAdapter._stage(page) == 'external'


def test_submission_timeout_is_not_replayed_with_another_selector():
    click = Mock(side_effect=TimeoutError('navigation lost after commit'))
    target = SimpleNamespace(is_visible=lambda **_:True, click=click)
    page = SimpleNamespace(locator=Mock(return_value=SimpleNamespace(first=target)))
    with pytest.raises(RegistrationFlowError):
        PlaywrightRegistrationAdapter._click(page, ['button[type=submit]', 'button:has-text(Continue)'])
    assert click.call_count == 1 and page.locator.call_count == 1


def test_totp_secret_is_saved_before_activation_and_retained_on_lost_response():
    events = []
    def evaluate(script, args):
        if args[0].endswith('/mfa/enroll'):
            return {'status':200, 'body':{'secret':'JBSWY3DPEHPK3PXP','session_id':'fixture-sid'}}
        assert events == [('saved', 'JBSWY3DPEHPK3PXP')]
        events.append('activation sent')
        raise TimeoutError('response lost')
    secret, error = PlaywrightRegistrationAdapter._bind_totp_in_browser(
        SimpleNamespace(evaluate=evaluate), 'fixture-access', device_id='fixture',
        on_secret=lambda s:events.append(('saved', s)))
    assert secret is None and error and events[-1] == 'activation sent'


def test_checkpoint_failure_prevents_totp_activation():
    page = SimpleNamespace(evaluate=Mock(return_value={'status':200,
        'body':{'secret':'JBSWY3DPEHPK3PXP','session_id':'fixture-sid'}}))
    def fail(_):
        raise RegistrationPersistenceError('disk full')
    with pytest.raises(RegistrationPersistenceError):
        PlaywrightRegistrationAdapter._bind_totp_in_browser(page, 'fixture-access',
            device_id='fixture', on_secret=fail)
    assert page.evaluate.call_count == 1


def test_any_pending_side_effect_blocks_retry_even_if_stage_is_early():
    item = load_registration_inputs(registration_text())[0]
    for stage in ('created', 'identity_ready', 'sentinel'):
        result = PlaywrightRegistrationAdapter().register(item, config={}, should_stop=lambda:False,
            on_stage=Mock(), checkpoint={'stage':stage,'side_effects':{'email_submit_attempted':True}})
        assert result.category == 'uncertain'


def test_driver_change_cannot_erase_uncertain_registration_checkpoint():
    item = load_registration_inputs(registration_text())[0]
    item.checkpoint = {'stage':'auth_flow','side_effects':{'email_submit_attempted':True}}
    result = run_batch_registration([item], {'driver':'disabled'})[0]
    assert result.category == 'uncertain'
    assert item.checkpoint['side_effects']['email_submit_attempted']


def test_rate_limit_stops_remaining_accounts_without_touching_them():
    items = load_registration_inputs(registration_text()+'\n'+registration_text('second@example.com'))
    adapter = SimpleNamespace(register=Mock(return_value=RegistrationResult(items[0].email, category='rate_limited')))
    results = run_batch_registration(items, {}, adapter=adapter)
    assert [r.category for r in results] == ['rate_limited', 'not_processed']
    assert adapter.register.call_count == 1


def test_unknown_exception_does_not_leak_credentials_to_plain_checkpoint(tmp_path):
    adapter = SimpleNamespace(register=Mock(side_effect=RuntimeError('fixture-secret-password')))
    run_batch_registration(load_registration_inputs(registration_text()), {}, adapter=adapter, checkpoint_dir=tmp_path)
    assert 'fixture-secret-password' not in next(tmp_path.glob('*.json')).read_text(encoding='utf-8')


def test_success_checkpoint_survives_failed_result_persistence(tmp_path):
    item = load_registration_inputs(registration_text())[0]
    class Adapter:
        def register(self, item, **kw):
            kw['on_checkpoint']({'stage':'create_account','create_confirmed':True,
                'side_effects':{'profile_submit_attempted':True}})
            return RegistrationResult(item.email, ok=True, account={'fixture':'result'})
    with pytest.raises(OSError):
        run_batch_registration([item], {}, adapter=Adapter(), checkpoint_dir=tmp_path,
            on_progress=Mock(side_effect=OSError('disk full')))
    saved = json.loads(next(tmp_path.glob('*.json')).read_text())
    assert saved['create_confirmed'] and saved['side_effects']['profile_submit_attempted']


@pytest.mark.parametrize('url,body,expected', [
    ('https://evil.test/api/accounts/create_account', {}, None),
    ('https://auth.openai.com/api/accounts/create_account', {'error':'failed'}, 'failed'),
    ('https://auth.openai.com/api/accounts/create_account', {'success':False}, 'failed'),
])
def test_creation_confirmation_checks_origin_and_body(url, body, expected):
    response = SimpleNamespace(url=url, status=200, json=lambda:body)
    assert PlaywrightRegistrationAdapter._create_account_response(response) == expected


def test_session_fetch_is_cancellable_without_sending_fetch():
    page = SimpleNamespace(evaluate=Mock())
    with pytest.raises(AuthFlowError) as error:
        PlaywrightRegistrationAdapter._fetch_session(page, should_stop=lambda:True)
    assert error.value.category == 'cancelled' and not page.evaluate.called


def test_graph_refresh_rotation_saved_before_read_and_cancel_prevents_io():
    events = []
    def handler(req):
        if req.method == 'POST':
            return httpx.Response(200, json={'access_token':'fixture-access', 'refresh_token':'fixture-rotated'})
        assert events == ['fixture-rotated']
        events.append('read')
        return httpx.Response(200, json={'value':[]})
    mailbox = MicrosoftGraphMailboxClient('fixture@example.com', 'fixture-id', 'fixture-old', on_refresh=events.append)
    mailbox.client.close()
    mailbox.client = httpx.Client(transport=httpx.MockTransport(handler))
    with mailbox:
        with pytest.raises(AuthFlowError):
            mailbox.snapshot(time.monotonic()+10, should_stop=lambda:True)
        assert events == []
        assert not mailbox.snapshot(time.monotonic()+10).ids
    assert events == ['fixture-rotated','read']


def test_pending_totp_export_warns_instead_of_claiming_confirmed_binding(engine):
    task = finished(engine, engine.start('register', registration_text()))
    task['items'][0]['totp_secret'] = 'JBSWY3DPEHPK3PXP'
    task['items'][0]['checkpoint'] = {'create_confirmed':True, 'side_effects':{'totp_activation_attempted':True}}
    records, warnings = engine.export_registration_credentials(task['id'])
    assert records[0]['totp_secret'] == 'JBSWY3DPEHPK3PXP'
    assert any('2FA 激活结果待核对' in w for w in warnings)
