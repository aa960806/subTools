"""Synthetic upstream HTTP contracts; never calls real accounts or paid SMS."""
import json
import threading
import time
from unittest.mock import Mock

import httpx
import pytest

from account_inputs import AccountInput
from flow_control import AuthFlowError
from login_interaction import LoginInteraction
from openai_reauth import generate_oauth_session
from protocol_login import (AUTH, CHATGPT, ProtocolClient, ProtocolLogin,
                            callback_code, run_batch_protocol, trusted_url)
from test_conversion import access, jwt


def tokens(email='fixture@example.com', space='space-fixture'):
    return {'access_token': access(**{'https://api.openai.com/auth': {'chatgpt_account_id': space}}),
            'refresh_token': 'fixture-rotated', 'id_token': jwt({'email': email}), 'expires_in': 3600}


class LoginSite:
    def __init__(self, *, email_otp=False, mfa=True, phone=False):
        self.requests = []
        self.email_otp, self.mfa, self.phone = email_otp, mfa, phone
        self.state = None
        self.override = {}

    def workspace(self):
        return {'continue_url': AUTH + '/workspace', 'oai-client-auth-session': {'workspaces': [
            {'id': 'personal', 'kind': 'personal'}, {'id': 'space-fixture', 'kind': 'organization'}]}}

    def authenticated(self):
        return {'page': {'type': 'mfa_challenge'}, 'continue_url': AUTH + '/mfa-challenge/factor1',
                'oai-client-auth-session': {'mfa_challenge_factors': [{'id':'factor1', 'factor_type':'totp'}]}}

    def __call__(self, request):
        path = request.url.path
        self.requests.append(request)
        if path in self.override:
            response = self.override[path]
            return response(request) if callable(response) else response
        if str(request.url) == CHATGPT + '/':
            return httpx.Response(200, text='<html>home</html>')
        if path == '/api/auth/providers':
            return httpx.Response(200, json={'openai': {}})
        if path == '/api/auth/csrf':
            return httpx.Response(200, json={'csrfToken': 'fixture-csrf'},
                                  headers={'set-cookie': '__Host-next-auth.csrf-token=fixture-csrf; Path=/; Secure'})
        if path == '/api/auth/signin/openai':
            assert 'csrfToken=fixture-csrf' in request.content.decode()
            return httpx.Response(200, json={'url': AUTH + ('/email-verification' if self.email_otp else '/log-in/password')})
        if path in ('/email-verification', '/log-in/password'):
            return httpx.Response(200, text='<html>login</html>')
        if path in ('/api/accounts/password/verify', '/api/accounts/email-otp/validate'):
            return httpx.Response(200, json=self.authenticated() if self.mfa else self.workspace())
        if path == '/api/accounts/mfa/issue_challenge':
            assert json.loads(request.content) == {'type': 'totp', 'id': 'factor1', 'force_fresh_challenge': False}
            return httpx.Response(200, json={})
        if path == '/api/accounts/mfa/verify':
            assert len(json.loads(request.content)['code']) == 6
            return httpx.Response(200, json=self.workspace())
        if path == '/api/accounts/workspace/select':
            assert json.loads(request.content) == {'workspace_id': 'space-fixture'}
            return httpx.Response(200, json={'continue_url': self.callback() if self.state else CHATGPT + '/api/auth/callback/openai'})
        if path == '/api/auth/callback/openai':
            return httpx.Response(302, headers={'location': CHATGPT + '/', 'set-cookie': '__Secure-next-auth.session-token=fixture-session; Path=/; Secure'})
        if path == '/oauth/authorize':
            self.state = request.url.params['state']
            assert request.url.params['code_challenge_method'] == 'S256'
            return httpx.Response(200, text='<input name="session_id" value="us_fixture_session1">')
        if path == '/api/accounts/session/select':
            assert json.loads(request.content) == {'session_id':'us_fixture_session1'}
            return httpx.Response(200, json={'page':{'type':'add_phone'}} if self.phone else self.workspace())
        raise AssertionError(f'Unexpected fixture route {request.method} {path}')

    def callback(self):
        return 'http://localhost:1455/auth/callback?code=fixture-code&state=' + self.state


def run(site, **kwargs):
    return run_batch_protocol([AccountInput('fixture@example.com', 'fixture-password', 'JBSWY3DPEHPK3PXP', '')],
        transport=httpx.MockTransport(site), exchange=lambda *a, **k: tokens(), **kwargs)[0]


def test_password_mfa_organization_pkce_and_recovery(tmp_path):
    site = LoginSite()
    result = run(site, recovery_dir=tmp_path)
    assert result.ok, result.error
    assert result.account['credentials']['chatgpt_account_id'] == 'space-fixture'
    data = json.loads(next(tmp_path.glob('*/accounts.json')).read_text(encoding='utf-8'))
    assert len(data['accounts']) == 1
    assert data['accounts'][0]['credentials']['refresh_token'] == 'fixture-rotated'
    assert all(r.url.host != 'localhost' for r in site.requests)
    assert all(r.url.path != '/api/accounts/add-phone/send' for r in site.requests)


def test_email_and_totp_manual_input():
    site, prompts = LoginSite(email_otp=True), []
    def ask(email, kind, **kw):
        prompts.append(kind)
        return '123456'
    result = run_batch_protocol([AccountInput('fixture@example.com', '', '', '')], prompt=ask,
        transport=httpx.MockTransport(site), exchange=lambda *a, **k:tokens())[0]
    assert result.ok and prompts == ['email_code', 'totp']


def test_password_manual_and_automatic_mailbox_preserves_proxy(monkeypatch):
    site = LoginSite(mfa=False)
    client = ProtocolClient(deadline=time.monotonic()+30, transport=httpx.MockTransport(site))
    with client.http:
        code, _, _ = ProtocolLogin(AccountInput('fixture@example.com', '', '', ''), client,
            prompt=lambda *a, **kw: 'fixture-manual-password').run()
        assert code == 'fixture-code'
    site = LoginSite(email_otp=True, mfa=False)
    box = Mock()
    box.wait_for_code.return_value = '654321'
    factory = Mock(return_value=box)
    client = ProtocolClient(deadline=time.monotonic()+30, transport=httpx.MockTransport(site))
    client.proxy = 'http://fixture-proxy:1234'
    with client.http:
        ProtocolLogin(AccountInput('fixture@example.com', '', '', '', mailbox_url='https://mail.test/messages'),
                      client, mailbox_factory=factory).run()
    assert factory.call_args.kwargs['proxy'] == client.proxy
    assert box.snapshot.called and box.wait_for_code.called and box.close.called


@pytest.mark.parametrize('status,body,category', [
    (403, {}, 'needs_interaction'), (429, {}, 'rate_limited'),
    (400, {'error':{'code':'invalid_password'}}, 'failed'),
    (400, {'error':{'code':'account_deactivated'}}, 'failed'),
    (400, {'error':{'code':'fraud_guard'}}, 'phone_fraud'),
    (400, {'error':{'code':'invalid_auth_step'}}, 'needs_interaction'),
    (400, {'error':{'code':'invalid_totp'}}, 'failed'),
])
def test_errors_are_classified_without_replay_or_leaking_body(status,body,category):
    site = LoginSite()
    body['secret'] = 'fixture-never-log-this'
    site.override['/api/accounts/password/verify'] = httpx.Response(status, json=body)
    result = run(site)
    assert result.category == category and not result.ok
    assert 'fixture-never' not in result.error
    assert sum(r.url.path == '/api/accounts/password/verify' for r in site.requests) == 1


def test_phone_is_skipped_before_sms():
    result = run(LoginSite(phone=True))
    assert not result.ok and result.category == 'phone_required'


@pytest.mark.parametrize('target', ['https://evil.test/', '//evil.test/', 'http://auth.openai.com/',
                                  'https://auth.openai.com@evil.test/', 'https://auth.openai.com/\\evil'])
def test_unknown_redirect_is_not_requested(target):
    site = LoginSite()
    site.override['/api/auth/signin/openai'] = httpx.Response(200, json={'url':target})
    assert not run(site).ok
    assert not any(r.url.host == 'evil.test' for r in site.requests)


@pytest.mark.parametrize('tail', ['?code=x', '?code=x&state=wrong', '?code=x&state=s&state=s',
                                '?code=x&state=s&error=access_denied', '?code=&state=s', '?code=x&state=s#fragment'])
def test_invalid_callback_rejected(tail):
    session = generate_oauth_session(); session.state = 's'
    with pytest.raises(AuthFlowError):
        callback_code(session.redirect_uri + tail, session)


def test_relative_continue_and_callback_port():
    session = generate_oauth_session()
    assert callback_code('/workspace', session) is None
    assert trusted_url('/workspace') == AUTH + '/workspace'
    with pytest.raises(AuthFlowError):
        callback_code('http://localhost:22/auth/callback?code=x&state=' + session.state, session)


def test_network_uncertainty_and_workspace_loop_do_not_replay():
    site = LoginSite()
    def disconnect(request):
        raise httpx.ReadTimeout('fixture-password')
    site.override['/api/accounts/password/verify'] = disconnect
    result = run(site)
    assert result.category == 'network' and 'fixture-password' not in result.error
    assert len([r for r in site.requests if r.method == 'POST']) == 2
    site = LoginSite()
    site.override['/api/accounts/workspace/select'] = httpx.Response(200, json=site.workspace())
    assert run(site).category == 'needs_interaction'
    assert sum(r.url.path == '/api/accounts/workspace/select' for r in site.requests) == 1


@pytest.mark.parametrize('data', [[], {'page':[]}, {'page':{'payload':None}}, {'oai-client-auth-session':{'workspaces':42}}])
def test_malformed_payload_stops_safely(data):
    site = LoginSite()
    site.override['/api/accounts/password/verify'] = httpx.Response(200, json=data)
    assert run(site).category == 'needs_interaction'


def test_cancel_and_deadline_do_not_send_request():
    transport = Mock()
    client = ProtocolClient(deadline=time.monotonic()-1, transport=httpx.MockTransport(transport))
    with client.http, pytest.raises(AuthFlowError, match='时间'):
        client.request('GET', CHATGPT+'/')
    assert not transport.called
    site = LoginSite()
    assert run_batch_protocol([AccountInput('fixture@example.com','','','')],
        transport=httpx.MockTransport(site), should_stop=lambda:True) == []
    assert not site.requests


def test_token_identity_and_cookies_per_account():
    sites = [LoginSite(), LoginSite()]
    index = -1
    def route(request):
        nonlocal index
        if str(request.url) == CHATGPT+'/' and not request.headers.get('cookie'):
            index += 1
        return sites[index](request)
    exchanged = Mock(return_value=tokens(space='other-space'))
    inputs = [AccountInput('fixture@example.com','fixture-pass','JBSWY3DPEHPK3PXP','') for _ in sites]
    results = run_batch_protocol(inputs, transport=httpx.MockTransport(route), exchange=exchanged)
    assert [r.category for r in results] == ['identity', 'identity']
    assert exchanged.call_count == 2 and all(s.requests for s in sites)


def test_interaction_expiry_duplicate_validation_and_cancellation():
    prompt, stop, result = LoginInteraction(), threading.Event(), []
    def wait():
        try:
            result.append(prompt.request('fixture@example.com', 'totp', deadline=time.monotonic()+3, should_stop=stop.is_set))
        except AuthFlowError as exc:
            result.append(exc.category)
    thread = threading.Thread(target=wait); thread.start()
    for _ in range(50):
        if prompt.snapshot(): break
        time.sleep(.01)
    key = prompt.snapshot()['id']
    for bad in ('', 'abcdef', '１２３４５６', '12345'):
        with pytest.raises(ValueError): prompt.submit(key, bad)
    with pytest.raises(ValueError): prompt.submit('stale', '123456')
    prompt.submit(key, '123456'); thread.join(1)
    assert result == ['123456'] and prompt.snapshot() is None and prompt.value is None
    with pytest.raises(ValueError): prompt.submit(key,'123456')
    thread = threading.Thread(target=wait); thread.start(); stop.set(); thread.join(1)
    assert result[-1] == 'cancelled' and prompt.snapshot() is None
