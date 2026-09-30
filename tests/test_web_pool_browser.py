"""Real web -> owner-thread Chromium -> OAuth callback -> HTTP pool integration.

Only OpenAI pages/token responses and the local sub2api server use fixtures.
The production login loop, callback, web bridge and pool engine run unchanged.
"""
import html
import json
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit, urlencode

import httpx
import pytest
from playwright.sync_api import expect

import openai_reauth as core
from test_conversion import access, jwt, AUTH
from test_pool import AdminBackend
from test_web_browser import browser, site  # noqa: F401 - shared opt-in fixtures

pytestmark = pytest.mark.skipif(os.environ.get('SUBTOOLS_BROWSER_TEST') != '1', reason='opt-in local browser smoke')


@pytest.fixture
def pool_server():
    backend = AdminBackend()
    class Handler(BaseHTTPRequestHandler):
        def serve(self):
            body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
            response = backend(httpx.Request(self.command, 'http://fixture.test' + self.path,
                                            headers=dict(self.headers), content=body))
            self.send_response(response.status_code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(response.content)))
            self.end_headers()
            self.wfile.write(response.content)
        do_GET = do_POST = do_PUT = serve
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield backend, f'http://127.0.0.1:{server.server_port}'
    server.shutdown();server.server_close();thread.join(5)


@pytest.fixture
def oauth_pages(monkeypatch):
    original_login = core.login_with_browser
    original_session = core.generate_oauth_session
    visited = []
    manual = threading.Event()
    exchanged = []
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        callback_port = sock.getsockname()[1]
    redirect = f'http://localhost:{callback_port}/auth/callback'
    monkeypatch.setattr(core, 'CALLBACK_PORT', callback_port)
    monkeypatch.setattr(core, 'generate_oauth_session', lambda: original_session(redirect))
    monkeypatch.setattr(core, 'launch_browser', lambda playwright, headless, proxy, **kw:
                        playwright.chromium.launch(headless=headless))
    monkeypatch.setattr('server_engine.run_batch_reauth', core.run_batch_reauth)

    def login(page, account, session, callback, timeout, *args, **kwargs):
        assert kwargs.get('skip_phone_verification') is True
        assert kwargs.get('phone_handler') is None
        callback_url = redirect + '?' + urlencode({'code':'fixture-code', 'state':session.state})
        def route(request_route):
            request = request_route.request
            url = urlsplit(request.url)
            if request.url.startswith(redirect):
                request_route.continue_()
                return
            if url.hostname != 'auth.openai.com':
                request_route.abort()
                return
            visited.append(url.path)
            fields = parse_qs(request.post_data or '')
            if url.path == '/oauth/authorize':
                title, field, target = 'Sign in', '<input type="email" name="email">', '/fixture/password'
            elif url.path == '/fixture/password':
                assert fields['email'] == ['fixture@example.com']
                title, field, target = 'Password', '<input type="password" name="password">', '/fixture/otp'
            elif url.path == '/fixture/otp':
                assert fields['password'] == ['fixture-password']
                title, field, target = 'Authenticator', '<input name="code" autocomplete="one-time-code">', '/fixture/manual'
            elif url.path == '/fixture/manual':
                assert len(fields['code'][0]) == 6 and fields['code'][0].isdigit()
                manual.set()
                title, field, target = 'Check your email', '<input name="reply">', '/fixture/finish'
            elif url.path == '/fixture/finish':
                assert fields['reply'] == ['fixture-manual-answer']
                request_route.fulfill(status=302, headers={'Location':callback_url}, body='')
                return
            else:
                request_route.abort()
                return
            body = f'''<html><style>body{{margin:0;background:white;color:black}}h1{{margin:0}}
                input{{position:absolute;left:20px;top:90px;width:400px;height:40px}}
                button{{position:absolute;left:20px;top:160px}}</style><h1>{title}</h1>
                <form method="post" action="{html.escape(target)}">{field}<button>Continue</button></form></html>'''
            request_route.fulfill(status=200, content_type='text/html', body=body)
        page.route('**/*', route)
        return original_login(page, account, session, callback, timeout, *args, **kwargs)

    def exchange(code, *args, **kwargs):
        assert code == 'fixture-code'
        exchanged.append(code)
        return {'access_token':access(), 'refresh_token':'fixture-refresh', 'expires_in':3600,
                'id_token':jwt({'email':'fixture@example.com', AUTH:{'chatgpt_account_id':'space-fixture'}})}

    monkeypatch.setattr(core, 'login_with_browser', login)
    monkeypatch.setattr(core, 'exchange_code', exchange)
    return manual, visited, exchanged


@pytest.mark.parametrize('cancel', [False, True], ids=['complete-and-update', 'stop-before-write'])
def test_pool_web_manual_login_and_cancellation(browser, site, pool_server, oauth_pages, cancel):
    backend, destination = pool_server
    manual, visited, exchanged = oauth_pages
    page = browser.new_page(viewport={'width':1440, 'height':1050})
    errors = []
    page.on('pageerror', lambda e: errors.append(str(e)))
    page.goto(site)
    page.locator('#login-password').fill('fixture-password-for-web')
    page.locator('#login-form button').click()
    page.locator('#app').wait_for(state='visible')
    headers = {'X-CSRF-Token':page.request.get(site + '/api/session').json()['csrf']}
    assert page.request.put(site + '/api/config/auth', headers=headers, data={'human_pacing':False}).ok
    config = {'site':destination, 'credential':'fixture-admin-key', 'group_ids':[7, 8],
              'proxy_id':42, 'load_factor':5, 'priority':9, 'concurrency':6, 'show_browser':True,
              'timeout':60, 'model_mode':'replace', 'model_choices':{'gpt-5':True, 'removed-model':False}}
    assert page.request.put(site + '/api/config/pool', headers=headers, data=config).ok
    page.reload()
    page.locator('[data-page=pool]').click()
    page.locator('[data-settings-tab=login]').click()
    expect(page.locator('[data-field=show_browser]')).to_be_checked()
    page.locator('#account-input').fill('fixture@example.com----fixture-password----JBSWY3DPEHPK3PXP')
    page.locator('#start').click()
    page.locator('#browser-open').click()
    expect(page.locator('#result-rows')).to_contain_text('等待人工操作', timeout=45000)
    assert manual.is_set()
    # A second polling response ensures the visible frame has caught up with navigation.
    for _ in range(2):
        with page.expect_response('**/api/browser/frame', timeout=5000):
            pass
    expect(page.locator('#browser-wait')).to_be_hidden()
    if cancel:
        task = page.request.get(site + '/api/status').json()['active']
        assert page.request.post(site + f'/api/tasks/{task}/stop', headers=headers, data={}).ok
    else:
        rect = page.locator('#browser-frame').bounding_box()
        page.locator('#browser-frame').click(position={'x':60*rect['width']/1280, 'y':110*rect['height']/900})
        page.locator('#browser-text').fill('fixture-manual-answer')
        page.locator('#browser-send').click()
        page.locator('[data-key=Enter]').click()
    expect(page.locator('#browser-wait')).to_be_visible(timeout=15000)
    expect(page.locator('#browser-frame[src]')).to_have_count(0, timeout=5000)
    page.locator('#browser-close').click()
    if cancel:
        expect(page.locator('#stop')).to_be_disabled(timeout=15000)
        assert not backend.records and not exchanged
    else:
        expect(page.locator('#stop')).to_be_disabled(timeout=15000)
        assert page.locator('#stat-success').inner_text() == '1', page.locator('#result-rows').inner_text()
        assert len(backend.records) == 1 and len(exchanged) == 1
        record = next(iter(backend.records.values()))
        assert (record['group_ids'], record['proxy_id'], record['load_factor'], record['priority'], record['concurrency']) == ([7,8],42,5,9,6)
        assert record['credentials']['model_mapping'] == {'gpt-5':'gpt-5'}
        # Re-import the result. Fresh tokens must update the same identity without OAuth.
        task_id = page.request.get(site + '/api/history').json()['rows'][0]['id']
        export = page.request.get(site + f'/api/tasks/{task_id}/export?target=cpa')
        assert export.ok
        page.locator('#account-input').fill(export.text())
        page.locator('#start').click()
        expect(page.locator('#result-rows')).to_contain_text('已更新', timeout=15000)
        assert len(backend.records) == 1 and len(exchanged) == 1
    assert visited[:4] == ['/oauth/authorize','/fixture/password','/fixture/otp','/fixture/manual']
    assert not errors
    page.close()
