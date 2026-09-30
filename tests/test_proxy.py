"""Proxy parsing, browser authentication and local OAuth callback routing."""
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock, patch

import httpx
import pytest
from playwright.sync_api import sync_playwright

import openai_reauth as core
from reauth_proxy import normalize_proxy, playwright_proxy


@pytest.mark.parametrize('raw,expected', [
    ('proxy.example:8080:user:secret', 'http://user:secret@proxy.example:8080'),
    ('proxy.example:8080', 'http://proxy.example:8080'),
    ('[::1]:8080:user:secret', 'http://user:secret@[::1]:8080'),
    ('proxy.example:8080:u@ser:p:a/#%?', 'http://u%40ser:p%3Aa%2F%23%25%3F@proxy.example:8080'),
    ('https://u%40ser:p%3Aa%2F%23%25%3F@proxy.example:8080/', 'https://u%40ser:p%3Aa%2F%23%25%3F@proxy.example:8080'),
    (' proxy.example:8080:user:secret &#x20; ', 'http://user:secret@proxy.example:8080'),
    ('socks5://proxy.example:1080', 'socks5://proxy.example:1080'),
    ('socks5://user:secret@proxy.example:1080', 'socks5://user:secret@proxy.example:1080'),
    ('', None), (None, None),
])
def test_proxy_normalization(raw, expected):
    assert normalize_proxy(raw) == expected
    assert normalize_proxy(expected) == expected


@pytest.mark.parametrize('raw', ['proxy.example:not-port:secret', 'proxy.example:0:user:secret',
                               'http://user:secret@proxy.example:65536', 'http://user:secret@proxy.example/path',
                               'ftp://user:secret@proxy.example:8080', 'proxy.example:8080:user:',
                               'http://user:secret@proxy.example:8080?foo=bar', 'socks5://user:' + 'x' * 256 + '@proxy.example:1080'])
def test_invalid_proxy_error_never_reflects_credentials(raw):
    with pytest.raises(ValueError) as caught:
        normalize_proxy(raw)
    assert 'secret' not in str(caught.value)
    assert 'proxy.example' not in str(caught.value)


def test_playwright_credentials_decoded_and_loopback_excluded():
    config = playwright_proxy('proxy.example:8080:u@ser:p:a/#%?')
    assert config['server'] == 'http://proxy.example:8080'
    assert config['username'] == 'u@ser'
    assert config['password'] == 'p:a/#%?'
    assert '127.0.0.1' in config['bypass'] and 'localhost' in config['bypass']


def test_raw_proxy_selected_protocol_and_explicit_url_precedence():
    assert normalize_proxy('proxy.example:1080:user:secret', default_scheme='socks5') == 'socks5://user:secret@proxy.example:1080'
    assert normalize_proxy('http://proxy.example:80', default_scheme='socks5') == 'http://proxy.example:80'
    with pytest.raises(ValueError):
        normalize_proxy('proxy.example:1080', default_scheme='ftp')
    with pytest.raises(ValueError, match='本地转接'):
        playwright_proxy('socks5://user:secret@proxy.example:1080')


def test_token_exchange_uses_same_normalized_proxy():
    with patch.object(core.httpx, 'Client') as client:
        response = client.return_value.__enter__.return_value.post.return_value
        response.status_code = 200
        response.json.return_value = {'access_token': 'fixture', 'refresh_token': 'fixture-refresh', 'id_token': 'fixture-id'}
        core.exchange_code('fixture-code', 'fixture-verifier', core.DEFAULT_REDIRECT_URI, 'proxy.example:8080:user:secret')
        assert client.call_args.kwargs['proxy'] == 'http://user:secret@proxy.example:8080'


def test_real_browser_and_http_client_proxy_auth_and_loopback_bypass():
    expected_auth = 'Basic ' + base64.b64encode(b'fixture-user:fixture-pass').decode()
    seen = []

    class Proxy(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.headers.get('Proxy-Authorization') != expected_auth:
                self.send_response(407)
                self.send_header('Proxy-Authenticate', 'Basic realm="fixture"')
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
            seen.append(self.path)
            data = json.dumps({'via_proxy': True}).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Proxy)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    callback = core.CallbackServer(0)
    raw = f'127.0.0.1:{server.server_port}:fixture-user:fixture-pass'
    try:
        with httpx.Client(proxy=normalize_proxy(raw), trust_env=False) as client:
            assert client.get('http://proxy-fixture.invalid/httpx').json()['via_proxy']
        with sync_playwright() as playwright:
            browser = core.launch_browser(playwright, True, raw)
            try:
                page = browser.new_page()
                page.goto('http://proxy-fixture.invalid/browser')
                assert json.loads(page.locator('body').inner_text())['via_proxy']
                callback.start()
                callback.reset('fixture-state')
                page.goto(f'http://127.0.0.1:{callback.port}/auth/callback?code=fixture-code&state=fixture-state')
                assert callback.wait(1).code == 'fixture-code'
            finally:
                browser.close()
        assert any('/httpx' in path for path in seen)
        assert any('/browser' in path for path in seen)
        assert not any('/auth/callback' in path for path in seen)
    finally:
        callback.stop()
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
