"""Real Chromium against intercepted registration pages; no external requests."""
import json
import os
from types import SimpleNamespace

import pytest

from test_web import data, engine
from test_registration_flow import registration_text
from test_protocol_login import tokens

pytestmark = pytest.mark.skipif(os.environ.get('SUBTOOLS_BROWSER_TEST') != '1', reason='opt-in local browser smoke')


@pytest.mark.parametrize('activation', ['confirmed', 'lost'])
def test_browser_registration_checkpoint_oauth_and_exports(engine, monkeypatch, activation):
    requests, oauth_calls, observations = [], [], []
    email = 'fixture@example.com'
    secret = 'JBSWY3DPEHPK3PXP'
    def html(form, script):
        return '<html><body>'+form+'<script>'+script+'</script></body></html>'
    pages = {
        '/auth/login': html('<form><input type="email" name="email"><button type="submit">Continue</button></form>',
            "document.querySelector('form').onsubmit=e=>{e.preventDefault();location.href='https://auth.openai.com/create-account/password'}"),
        '/create-account/password': html('<input type="password"><button type="submit">Continue</button>',
            "document.querySelector('button').onclick=()=>location.href='/email-verification'"),
        '/email-verification': html('<input autocomplete="one-time-code"><button type="submit">Verify</button>',
            "document.querySelector('button').onclick=()=>location.href='/about-you'"),
        '/about-you': html('<input autocomplete="name"><input type="date"><button type="submit">Continue</button>',
            "document.querySelector('button').onclick=async()=>{const r=await fetch('/api/accounts/create_account',{method:'POST'});await r.json();setTimeout(()=>location.href='https://chatgpt.com/',250)}"),
        '/': '<html><body>Signed in</body></html>',
    }
    def route(r):
        from urllib.parse import urlsplit
        request = r.request
        path = urlsplit(request.url).path
        requests.append(path)
        if path in pages:
            headers = {'set-cookie':'__Secure-next-auth.session-token.0=fixture; Path=/; Secure'} if path=='/' else {}
            return r.fulfill(status=200, content_type='text/html', body=pages[path], headers=headers)
        if path == '/api/accounts/create_account':
            return r.fulfill(status=200, json={'redirect':'https://chatgpt.com/'})
        if path == '/api/auth/session':
            return r.fulfill(status=200, json={'user':{'email':email}, 'accessToken':'fixture-session-token'})
        if path.endswith('/mfa/enroll'):
            return r.fulfill(status=200, json={'secret':secret,'session_id':'fixture-sid'})
        if path.endswith('/activate_enrollment'):
            current = engine.get(engine.active)
            persisted = engine.store.read('tasks/'+current['id']+'.json')
            assert persisted['items'][0]['totp_secret'] == secret
            assert persisted['items'][0]['checkpoint']['side_effects']['totp_activation_attempted']
            observations.append('secret saved before activation')
            if activation == 'lost':
                return r.abort('failed')
            return r.fulfill(status=200, json={'success':True})
        return r.abort('blockedbyclient')

    def launch(playwright, **kwargs):
        channel = os.environ.get('SUBTOOLS_TEST_BROWSER_CHANNEL')
        browser = playwright.chromium.launch(headless=True, **({'channel':channel} if channel else {}))
        def context():
            c = browser.new_context()
            c.route('**/*', route)
            return c
        return SimpleNamespace(new_context=context, close=browser.close)

    class Mailbox:
        def __init__(self, *a, **kw): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def snapshot(self, *a, **kw): return object()
        def wait_for_code(self, *a, **kw): return '123456'

    def oauth(page, account, session, callback, *a):
        assert account.totp_secret == secret
        assert account.password == 'fixture-password'
        oauth_calls.append(account.email)
        return SimpleNamespace(state=session.state, code='fixture-code', error='')

    class Callback:
        def start(self): pass
        def stop(self): pass

    monkeypatch.setattr('openai_reauth.launch_browser', launch)
    monkeypatch.setattr('openai_reauth.login_with_browser', oauth)
    monkeypatch.setattr('openai_reauth.exchange_code', lambda *a, **kw:tokens(email=email))
    monkeypatch.setattr('openai_reauth.CallbackServer', Callback)
    monkeypatch.setattr('registration_flow.MailboxClient', Mailbox)
    engine.save_config('register', {'driver':'playwright','require_totp':True,'timeout':90})
    task = engine.start('register', registration_text(email))
    engine.worker.join(45)
    assert not engine.worker.is_alive()
    final = engine.get(task['id'])
    assert observations == ['secret saved before activation'], (final['rows'][0]['message'], requests)
    assert requests.count('/api/accounts/create_account') == 1
    assert requests.count('/backend-api/accounts/mfa/user/activate_enrollment') == 1
    persisted = engine.store.read('tasks/'+task['id']+'.json')
    assert persisted['items'][0]['password'] == 'fixture-password'
    assert secret not in json.dumps(engine.public(task['id']))
    records, warnings = engine.export_registration_credentials(task['id'])
    assert records[0]['totp_secret'] == secret
    checkpoint_dir = engine.root/'tasks'/task['id']/'registration-checkpoints'
    if activation == 'confirmed':
        assert final['rows'][0]['state'] == 'success', final['rows'][0]
        assert oauth_calls == [email] and not warnings
        assert engine.export_accounts(task['id'])[0]['credentials']['refresh_token'] == 'fixture-rotated'
        assert list(checkpoint_dir.glob('*.json')) == []
    else:
        assert final['rows'][0]['state'] == 'auth_session_pending'
        assert not oauth_calls and not final['accounts']
        assert any('2FA 激活结果待核对' in w for w in warnings)
        assert list(checkpoint_dir.glob('*.json'))
        with pytest.raises(ValueError):
            engine.start('register', previous=task['id'])
