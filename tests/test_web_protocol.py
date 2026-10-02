"""Protocol selection and ephemeral inputs through the authenticated web API."""
import json
import time
from unittest.mock import Mock

import httpx
import pytest

from test_web import data, engine, client, login, finished, fake_login
from test_pool import account, AdminBackend


@pytest.mark.parametrize('method', ['browser', 'protocol'])
def test_auth_explicit_selection_and_phone_unchanged(engine, monkeypatch, method):
    browser, protocol = Mock(side_effect=fake_login), Mock(side_effect=fake_login)
    monkeypatch.setattr('server_engine.run_batch_reauth', browser)
    monkeypatch.setattr('server_engine.run_batch_protocol', protocol)
    engine.save_config('auth', {'login_method':method, 'show_browser':True})
    task = finished(engine, engine.start('auth','fixture@example.com----fixture-pass'))
    assert task['rows'][0]['state'] == 'success'
    assert protocol.call_count == (method == 'protocol')
    assert browser.call_count == (method == 'browser')
    assert engine.public(task['id'])['login_method'] == method
    assert engine.bridge.enabled == (method == 'browser')
    phone = Mock(side_effect=lambda items, settings, **kw:fake_login(items, **kw))
    monkeypatch.setattr('server_engine.run_batch_phone_verify', phone)
    engine.save_config('phone', {'api_key':'fixture-key'})
    task = finished(engine, engine.start('phone','fixture@example.com----fixture-pass'))
    assert task['rows'][0]['state'] == 'success' and phone.call_count == 1
    assert engine.public(task['id'])['login_method'] == 'browser'


def test_protocol_refresh_failure_does_not_log_in_implicitly(engine,monkeypatch):
    from oauth_refresh import RefreshError
    refresh = Mock(side_effect=RefreshError('refresh_unknown','结果不明'))
    monkeypatch.setattr('oauth_refresh.refresh_account',refresh)
    monkeypatch.setattr('oauth_refresh.recover_refresh_account',lambda *a,**kw:None)
    protocol = Mock(side_effect=fake_login)
    monkeypatch.setattr('server_engine.run_batch_protocol',protocol)
    engine.save_config('auth',{'login_method':'protocol'})
    task = finished(engine,engine.start('auth',json.dumps(account())))
    assert not protocol.called and task['rows'][0]['state'] == 'refresh_unknown'
    task = finished(engine,engine.start('auth',previous=task['id']))
    assert not protocol.called and refresh.call_count == 1
    task = finished(engine,engine.start('auth',previous=task['id'],relogin=True))
    assert protocol.call_count == 1 and task['rows'][0]['state'] == 'success'
    assert not engine.bridge.enabled


def test_pool_protocol_creates_and_updates_same_identity(engine,monkeypatch):
    import pool_flow
    backend = AdminBackend()
    engine.save_config('pool', {'site':'https://sub2.test','credential':'fixture-key','group_ids':[7],
                               'login_method':'protocol','proxy_id':42,'load_factor':3})
    # Auth retains browser; pool's choice must be independent.
    assert engine.config('auth')['login_method'] == 'browser'
    monkeypatch.setattr('server_engine.run_batch_reauth',Mock(side_effect=AssertionError('wrong runner')))
    protocol = Mock(side_effect=fake_login)
    monkeypatch.setattr('server_engine.run_batch_protocol',protocol)
    monkeypatch.setattr('server_engine.run_pool_push',lambda *a,**kw:pool_flow.run_pool_push(
        *a,**kw,client_factory=backend.client,refresh=lambda a,**_:a))
    first = finished(engine,engine.start('pool','fixture@example.com----fixture-pass'))
    second = finished(engine,engine.start('pool','fixture@example.com----fixture-pass'))
    assert first['rows'][0]['state'] == 'created'
    assert second['rows'][0]['state'] == 'updated'
    assert protocol.call_count == 2 and len(backend.records) == 1
    assert next(iter(backend.records.values()))['load_factor'] == 3


@pytest.mark.parametrize('failure', [None, 'identity', 'phone', 'state', 'challenge', 'cancelled'])
def test_protocol_state_machine_to_pool_without_browser(engine, monkeypatch, failure):
    from protocol_login import run_batch_protocol
    from test_protocol_login import LoginSite, tokens, CHATGPT
    import pool_flow
    backend, sites = AdminBackend(), []
    engine.save_config('auth', {'human_pacing':False})
    engine.save_config('pool', {'site':'https://sub2.test', 'credential':'fixture-key', 'group_ids':[7],
                               'login_method':'protocol', 'proxy_id':42, 'load_factor':3,
                               'priority':11, 'concurrency':4})
    monkeypatch.setattr('server_engine.run_batch_reauth', Mock(side_effect=AssertionError('browser must not run')))
    def protocol(items, **kwargs):
        site = LoginSite(phone=failure == 'phone')
        sites.append(site)
        # Reproduce the post-MFA landing rejected by the old protocol adapter.
        site.override['/api/auth/callback/openai'] = httpx.Response(302, headers={'location':CHATGPT + '/'})
        if failure == 'state':
            site.callback = lambda:'http://localhost:1455/auth/callback?code=fixture&state=wrong'
        if failure == 'challenge':
            site.override['/api/auth/callback/openai'] = httpx.Response(403)
        if failure == 'cancelled':
            def stop_before_oauth(request):
                engine.stop.set()
                return httpx.Response(200, text='<html>home</html>')
            site.override['/api/auth/callback/openai'] = stop_before_oauth
        return run_batch_protocol(items, **kwargs, transport=httpx.MockTransport(site),
            exchange=lambda *a, **k:tokens(space='wrong-space' if failure == 'identity' else 'space-fixture'))
    monkeypatch.setattr('server_engine.run_batch_protocol', protocol)
    monkeypatch.setattr('server_engine.run_pool_push', lambda *a, **kw:pool_flow.run_pool_push(
        *a, **kw, client_factory=backend.client, refresh=lambda a, **_:a))
    source = 'fixture@example.com----fixture-pass----JBSWY3DPEHPK3PXP'
    first = finished(engine, engine.start('pool', source))
    if failure:
        assert first['rows'][0]['state'] not in ('created', 'updated', 'success')
        assert not backend.records
        assert not any(method in ('POST', 'PUT') for method, *_ in backend.requests)
        return
    assert first['rows'][0]['state'] == 'created', first['rows'][0]['message']
    second = finished(engine, engine.start('pool', source))
    assert second['rows'][0]['state'] == 'updated' and len(backend.records) == 1
    record = next(iter(backend.records.values()))
    assert record['group_ids'] == [7] and record['priority'] == 11 and record['concurrency'] == 4
    assert record['proxy_id'] == 42 and record['load_factor'] == 3
    assert record['credentials']['refresh_token'] == 'fixture-rotated'
    assert record['credentials']['chatgpt_account_id'] == 'space-fixture'
    assert not engine.bridge.enabled
    assert all(sum(r.url.path == '/api/accounts/mfa/verify' for r in s.requests) == 1 for s in sites)


def wait_prompt(engine, task):
    for _ in range(100):
        value = engine.public(task['id'])['login_prompt']
        if value: return value
        time.sleep(.01)
    raise AssertionError('No login prompt')


def manual_login(items, **kwargs):
    kwargs['prompt'](items[0].email,'totp',deadline=time.monotonic()+4,should_stop=kwargs['should_stop'])
    return fake_login(items,**kwargs)


def test_manual_input_auth_csrf_task_and_prompt_isolation(client,monkeypatch):
    url = '/api/tasks/nonexistent/login-input'
    assert client.post(url,json={'value':'123456'}).status_code == 401
    login(client)
    csrf = client.headers.pop('x-csrf-token')
    assert client.post(url,json={'value':'123456'}).status_code == 403
    client.headers['x-csrf-token'] = csrf
    assert client.put('/api/config/auth',json={'login_method':'invalid'}).status_code == 400
    client.put('/api/config/auth',json={'login_method':'protocol'})
    monkeypatch.setattr('server_engine.run_batch_protocol',manual_login)
    task = client.post('/api/tasks',json={'kind':'auth','text':'fixture@example.com----fixture-pass'}).json()
    e = client.app.state.engine
    p = wait_prompt(e,task)
    data = {'prompt_id':p['id'],'value':'123456'}
    assert client.post(url,json=data).status_code == 400
    url = f"/api/tasks/{task['id']}/login-input"
    assert client.post(url,json={**data,'prompt_id':'old'}).status_code == 400
    assert client.post(url,json=data).status_code == 200
    completed = finished(e,task)
    assert completed['rows'][0]['state'] == 'success'
    assert client.post(url,json=data).status_code == 400
    public = json.dumps(e.public(task['id']))
    saved = json.dumps(e.store.read(f"tasks/{task['id']}.json"))
    assert '123456' not in public + saved
    assert e.interaction.snapshot() is None and e.interaction.value is None


def test_stopping_pending_input_clears_prompt(client,monkeypatch):
    login(client)
    client.put('/api/config/auth',json={'login_method':'protocol'})
    monkeypatch.setattr('server_engine.run_batch_protocol',manual_login)
    task = client.post('/api/tasks',json={'kind':'auth','text':'fixture@example.com----fixture-pass'}).json()
    e = client.app.state.engine
    p = wait_prompt(e,task)
    client.post(f"/api/tasks/{task['id']}/stop")
    assert client.post(f"/api/tasks/{task['id']}/login-input",json={'prompt_id':p['id'],'value':'123456'}).status_code == 400
    completed = finished(e,task)
    assert completed['status'] == 'stopped' and e.interaction.snapshot() is None
