"""Registration-only robustness contracts, using synthetic accounts and I/O."""
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from registration_flow import (MicrosoftGraphMailboxClient, PlaywrightRegistrationAdapter,
    RegistrationFlowError, RegistrationResult)
from registration_history import RegistrationHistory
from registration_policy import session_candidate
from test_pool import account
from test_registration_flow import registration_text
from test_web import client, data, engine, finished, login


@pytest.mark.parametrize('url,selectors,expected', [
    ('https://auth.openai.com/log-in/password', {'input[type="password"]'}, 'login_password'),
    ('https://auth.openai.com/login/password', set(), 'login_password'),
    ('https://auth.openai.com/another-route', {'input[autocomplete="current-password"]'}, 'login_password'),
    ('https://auth.openai.com/create-account/password', {'input[type="password"]'}, 'password'),
    ('https://auth.openai.com/profile', {'input[name="age"]', 'input[inputmode="numeric"]'}, 'about_you'),
    ('https://auth.openai.com/unknown', {'input[inputmode="numeric"]'}, 'unknown'),
    ('https://auth.openai.com/email-verification', {'input[inputmode="numeric"]'}, 'otp'),
])
def test_registration_page_classification(monkeypatch, url, selectors, expected):
    monkeypatch.setattr(PlaywrightRegistrationAdapter, '_visible',
        staticmethod(lambda page, values: object() if selectors.intersection(values) else None))
    assert PlaywrightRegistrationAdapter._stage(SimpleNamespace(url=url)) == expected


@pytest.mark.parametrize('subject,body,expected', [
    ('Your ChatGPT code is 654321', '<style>.otp{color:#123456}</style><p>654321</p>', {'654321'}),
    ('您的 ChatGPT 代码为 654321', '654321', {'654321'}),
    ('ChatGPT の確認コード: 654321', '654321', {'654321'}),
    ('ChatGPT 인증 코드', '<p style="color:#123456">인증 코드: 654321</p>', {'654321'}),
    ('OpenAI verification', '<script>var id=123456;</script><b>Code: 654321</b>', {'654321'}),
    ('OpenAI verification', 'Codes: 123456 or 654321', {'123456', '654321'}),
    ('Invoice 654321', 'Payment received', set()),
])
def test_graph_otp_ignores_html_noise_and_retains_ambiguity(subject, body, expected):
    message = {'from':{'emailAddress':{'address':'noreply@openai.com'}},
               'subject':subject, 'body':{'content':body}}
    assert MicrosoftGraphMailboxClient._code(message) == expected


@pytest.mark.parametrize('nested,key', [(False, 'accessToken'), (True, 'accessToken'), (True, 'access_token')])
def test_session_reader_accepts_supported_shapes(nested, key):
    payload = {key:'synthetic-token', 'user':{'email':'fixture@example.com'}}
    if nested:
        payload = {'session':payload}
    page = SimpleNamespace(evaluate=Mock(return_value={'status':200,'text':json.dumps(payload)}))
    result = PlaywrightRegistrationAdapter._fetch_session(page)
    assert session_candidate(result) == {'access_token':'synthetic-token','email':'fixture@example.com'}
    assert page.evaluate.call_count == 1


@pytest.mark.parametrize('status,category', [(429, 'rate_limited'), (401, 'session_http_error'), (403, 'session_http_error')])
def test_session_terminal_http_errors_are_not_polled_or_hidden(status, category):
    page = SimpleNamespace(evaluate=Mock(return_value={'status':status,'text':'private response'}))
    with pytest.raises(RegistrationFlowError) as exc:
        PlaywrightRegistrationAdapter._fetch_session(page)
    assert exc.value.category == category and str(status) in str(exc.value)
    assert 'private response' not in str(exc.value) and page.evaluate.call_count == 1


def test_session_transient_retry_respects_budget_and_explains_failure(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr('registration_flow.time.monotonic', lambda:clock[0])
    page = SimpleNamespace(evaluate=Mock(return_value={'status':503,'text':'private'}),
        wait_for_timeout=lambda ms:clock.__setitem__(0, clock[0]+ms/1000))
    with pytest.raises(RegistrationFlowError) as exc:
        PlaywrightRegistrationAdapter._fetch_session(page, timeout=2)
    assert clock[0] == 1002 and page.evaluate.call_count == 2
    assert 'HTTP 503' in str(exc.value) and 'private' not in str(exc.value)


def install_adapter(engine, monkeypatch, *, complete=False, category='auth_session_pending', effects=None):
    calls = []
    cp = {'stage':'auth_session', 'create_confirmed':True,
          'side_effects':effects or {'profile_submit_attempted':True, 'session_confirmed':True}}
    def register(item, **options):
        calls.append(item.email)
        options['on_checkpoint'](dict(cp))
        return RegistrationResult(item.email, ok=complete, category='success' if complete else category,
            account=account(email=item.email) if complete else None, checkpoint={} if complete else dict(cp))
    monkeypatch.setattr('server_engine.PlaywrightRegistrationAdapter', lambda:SimpleNamespace(register=register))
    engine.save_config('register', {'driver':'playwright'})
    return calls


def test_new_task_cannot_replay_previous_registration(engine, monkeypatch):
    calls = install_adapter(engine, monkeypatch)
    original = finished(engine, engine.start('register', registration_text("fixture@example.com")))
    # A new guard instance emulates restart; it has no cached revisions.
    engine.registration_history = RegistrationHistory(engine.store)
    duplicate = finished(engine, engine.start('register', registration_text("fixture@example.com")))
    assert calls == ['fixture@example.com']
    assert duplicate['rows'][0]['state'] == 'registration_blocked'
    assert duplicate['rows'][0]['source_task'] == original['id']
    with pytest.raises(ValueError, match='没有可导出'):
        engine.export_registration_credentials(duplicate['id'])
    public = engine.public(duplicate['id'])
    assert public['rows'][0]['registration']['actions'] == []
    saved = next((engine.root/'registration/emails').glob('*.json')).read_text()
    assert 'fixture@example.com' not in saved and 'profile_submit_attempted' not in saved


def test_archived_legacy_success_also_blocks_new_task(engine, monkeypatch):
    calls = install_adapter(engine, monkeypatch, complete=True)
    task = finished(engine, engine.start('register', registration_text("fixture@example.com")))
    engine.tasks.archive(task['id'])
    # Remove only the synthetic index to model upgrading an older deployment.
    for file in (engine.root/'registration/emails').glob('*.json'):
        file.unlink()
    engine.registration_history = RegistrationHistory(engine.store)
    duplicate = finished(engine, engine.start('register', registration_text("fixture@example.com")))
    assert len(calls) == 1 and duplicate['rows'][0]['source_task'] == task['id']
    assert engine.registration_history.lookup('FIXTURE@example.com')['complete']


def test_guard_write_failure_stops_before_submission_and_recovers_from_task(engine, monkeypatch):
    calls = []
    def register(item, **options):
        options['on_checkpoint']({'stage':'user_register','side_effects':{'password_submit_attempted':True}})
        calls.append('submitted')
        raise AssertionError('must not submit')
    monkeypatch.setattr('server_engine.PlaywrightRegistrationAdapter', lambda:SimpleNamespace(register=register))
    engine.save_config('register', {'driver':'playwright'})
    original_write = engine.store.write
    def write(path, value):
        if str(path).startswith('registration/'):
            raise OSError('fixture disk full')
        original_write(path, value)
    monkeypatch.setattr(engine.store, 'write', write)
    first = finished(engine, engine.start('register', registration_text("fixture@example.com")))
    assert not calls and first['items'][0]['checkpoint']['side_effects']['password_submit_attempted']
    monkeypatch.setattr(engine.store, 'write', original_write)
    second = finished(engine, engine.start('register', registration_text("fixture@example.com")))
    assert second['rows'][0]['state'] == 'registration_blocked' and not calls


def test_registration_partial_recovery_preserves_secret_without_rebinding(engine, monkeypatch):
    install_adapter(engine, monkeypatch, effects={'profile_submit_attempted':True, 'totp_activation_attempted':True})
    task = finished(engine, engine.start('register', registration_text("fixture@example.com")))
    task['items'][0]['totp_secret'] = 'JBSWY3DPEHPK3PXP'
    engine._save(task)
    public = engine.public(task['id'])
    row = public['rows'][0]
    assert row['registration']['facts']['creation'] == '已创建'
    assert row['registration']['facts']['totp'] == '激活待核对'
    assert row['registration']['actions'] == ['auth']
    assert 'JBSWY3DPEHPK3PXP' not in json.dumps(public)
    from account_inputs import load_accounts
    draft = load_accounts(engine.transfer(task['id'], 'auth', ['0']))
    assert draft[0].password == task['items'][0]['password']
    assert draft[0].totp_secret == 'JBSWY3DPEHPK3PXP'
    with pytest.raises(ValueError):
        engine.transfer(task['id'], 'phone', ['0'])
    with pytest.raises(ValueError):
        engine.transfer(task['id'], 'auth', ['missing'])


def test_phone_recovery_only_prepares_existing_phone_flow(engine, monkeypatch):
    calls = install_adapter(engine, monkeypatch, category='phone_required')
    task = finished(engine, engine.start('register', registration_text("fixture@example.com")))
    phone = Mock(side_effect=AssertionError('transfer must not buy a number'))
    monkeypatch.setattr('server_engine.run_batch_phone_verify', phone)
    records = json.loads(engine.transfer(task['id'], 'phone', ['0']))
    assert records[0]['email'] == 'fixture@example.com'
    assert len(calls) == 1 and not phone.called


def test_registration_recovery_endpoint_keeps_auth_and_csrf_contract(client, monkeypatch):
    login(client)
    engine = client.app.state.engine
    install_adapter(engine, monkeypatch)
    task = finished(engine, engine.start('register', registration_text("fixture@example.com")))
    path = '/api/tasks/'+task['id']+'/transfer'
    csrf = client.headers.pop('x-csrf-token')
    assert client.post(path, json={'target':'auth'}).status_code == 403
    client.headers['x-csrf-token'] = csrf
    response = client.post(path, json={'target':'auth','selected':['0']})
    assert response.status_code == 200 and 'fixture@example.com' in response.json()['text']


@pytest.mark.parametrize('field', ['page_timeout', 'session_timeout', 'oauth_timeout'])
def test_registration_stage_timeout_validation(engine, field):
    with pytest.raises(ValueError):
        engine.save_config('register', {field:0})
    assert engine.save_config('register', {field:150})[field] == 150


def test_corrupt_registration_guard_does_not_disable_existing_auth(engine, monkeypatch):
    from test_web import fake_login
    engine.store.write(engine.registration_history._path('fixture@example.com'), {'invalid':'fixture'})
    with pytest.raises(ValueError, match='注册历史'):
        engine.start('register', registration_text('fixture@example.com'))
    monkeypatch.setattr('server_engine.run_batch_reauth', fake_login)
    task = finished(engine, engine.start('auth', 'fixture@example.com----fixture-password'))
    assert task['rows'][0]['state'] == 'success'
