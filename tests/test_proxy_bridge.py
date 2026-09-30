"""Exercise an authenticated SOCKS server without external network calls."""
import base64
from contextlib import contextmanager
import json
import socket
import socketserver
import threading
import time
from urllib.parse import urlsplit

import httpx
import pytest
from playwright.sync_api import sync_playwright

import openai_reauth as core
from reauth_proxy import browser_proxy_context
from reauth_proxy_bridge import _read_exact


@contextmanager
def fake_socks(*, reject_auth=False, stall=False):
    seen = []
    active = []
    stopped = threading.Event()

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            active.append(self.request)
            self.request.settimeout(5)
            try:
                version, count = _read_exact(self.request, 2)
                methods = _read_exact(self.request, count)
                assert version == 5 and 2 in methods
                self.request.sendall(b'\x05\x02')
                assert _read_exact(self.request, 1) == b'\x01'
                user = _read_exact(self.request, _read_exact(self.request, 1)[0])
                password = _read_exact(self.request, _read_exact(self.request, 1)[0])
                assert (user, password) == (b'fixture-user', b'fixture-password')
                self.request.sendall(b'\x01\x01' if reject_auth else b'\x01\x00')
                if reject_auth:
                    return
                version, command, reserved, kind = _read_exact(self.request, 4)
                assert (version, command, reserved) == (5, 1, 0)
                if kind == 3:
                    host = _read_exact(self.request, _read_exact(self.request, 1)[0]).decode()
                elif kind == 1:
                    host = socket.inet_ntop(socket.AF_INET, _read_exact(self.request, 4))
                else:
                    host = socket.inet_ntop(socket.AF_INET6, _read_exact(self.request, 16))
                port = int.from_bytes(_read_exact(self.request, 2), 'big')
                record = {'host': host, 'port': port}
                seen.append(record)
                self.request.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
                if stall:
                    stopped.wait(5)
                    return
                if host == 'echo.fixture.invalid':
                    while chunk := self.request.recv(4096):
                        self.request.sendall(chunk)
                    return
                data = b''
                while b'\r\n\r\n' not in data:
                    chunk = self.request.recv(4096)
                    if not chunk:
                        return
                    data += chunk
                record['request'] = data.decode('iso-8859-1')
                body = json.dumps({'via_socks': True}).encode()
                self.request.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n'
                                     + f'Content-Length: {len(body)}\r\nConnection: close\r\n\r\n'.encode() + body)
            except (OSError, AssertionError):
                pass

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True
        block_on_close = False

    server = Server(('127.0.0.1', 0), Handler)
    worker = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.1}, daemon=True)
    worker.start()
    try:
        yield f'socks5://fixture-user:fixture-password@127.0.0.1:{server.server_address[1]}', seen
    finally:
        stopped.set()
        for sock in active:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def _auth(config):
    return 'Basic ' + base64.b64encode(f"{config['username']}:{config['password']}".encode()).decode()


def _local_socket(config):
    parsed = urlsplit(config['server'])
    return socket.create_connection((parsed.hostname, parsed.port), timeout=3)


def test_http_bridge_upstream_auth_remote_dns_and_no_credential_header():
    with fake_socks() as (proxy, seen):
        with browser_proxy_context(proxy) as config:
            local = httpx.Proxy(config['server'], auth=(config['username'], config['password']))
            with httpx.Client(proxy=local, trust_env=False) as client:
                response = client.get('http://bridge.fixture.invalid/check?x=1')
                assert response.json() == {'via_socks': True}
        assert seen[0]['host'] == 'bridge.fixture.invalid'
        assert seen[0]['port'] == 80
        assert seen[0]['request'].startswith('GET /check?x=1 HTTP/1.1')
        assert 'proxy-authorization' not in seen[0]['request'].lower()
        assert 'fixture-password' not in seen[0]['request']


def test_bridge_challenges_unauthenticated_local_client_before_upstream():
    with fake_socks() as (proxy, seen):
        with browser_proxy_context(proxy) as config:
            with httpx.Client(proxy=config['server'], trust_env=False) as client:
                assert client.get('http://bridge.fixture.invalid/').status_code == 407
        assert seen == []


def test_connect_tunnels_binary_bytes_without_tls_interception_and_cleans_up():
    with fake_socks() as (proxy, seen):
        with browser_proxy_context(proxy) as config:
            sock = _local_socket(config)
            sock.sendall(('CONNECT echo.fixture.invalid:443 HTTP/1.1\r\n'
                          f'Proxy-Authorization: {_auth(config)}\r\n\r\n').encode())
            data = b''
            while b'\r\n\r\n' not in data:
                data += sock.recv(1024)
            assert data.startswith(b'HTTP/1.1 200')
            payload = b'\x16\x03\x01opaque-tls-like-data\x00\xff'
            sock.sendall(payload)
            assert _read_exact(sock, len(payload)) == payload
        assert sock.recv(1) == b''
        sock.close()
        with pytest.raises(OSError):
            _local_socket(config)
        assert seen[0] == {'host': 'echo.fixture.invalid', 'port': 443}


def test_upstream_auth_failure_returns_safe_502():
    with fake_socks(reject_auth=True) as (proxy, seen):
        with browser_proxy_context(proxy) as config:
            local = httpx.Proxy(config['server'], auth=(config['username'], config['password']))
            with httpx.Client(proxy=local, trust_env=False) as client:
                response = client.get('http://bridge.fixture.invalid/')
                assert response.status_code == 502
                assert not response.content
        assert seen == []


def test_context_cleanup_interrupts_active_tunnel_promptly():
    with fake_socks(stall=True) as (proxy, _):
        context = browser_proxy_context(proxy)
        config = context.__enter__()
        sock = _local_socket(config)
        sock.sendall(('CONNECT stall.fixture.invalid:443 HTTP/1.1\r\n'
                      f'Proxy-Authorization: {_auth(config)}\r\n\r\n').encode())
        assert sock.recv(4096).startswith(b'HTTP/1.1 200')
        started = time.monotonic()
        context.__exit__(None, None, None)
        assert time.monotonic() - started < 1.5
        assert sock.recv(1) == b''
        sock.close()


def test_chromium_authenticated_socks_and_callback_bypass():
    callback = core.CallbackServer(0)
    with fake_socks() as (proxy, seen):
        try:
            with sync_playwright() as playwright:
                browser = core.launch_browser(playwright, True, proxy)
                try:
                    page = browser.new_page()
                    page.goto('http://browser.fixture.invalid/check')
                    assert json.loads(page.locator('body').inner_text())['via_socks']
                    callback.start()
                    callback.reset('fixture-state')
                    page.goto(f'http://127.0.0.1:{callback.port}/auth/callback?code=fixture-code&state=fixture-state')
                    assert callback.wait(1).code == 'fixture-code'
                finally:
                    browser.close()
        finally:
            callback.stop()
        assert any(row['host'] == 'browser.fixture.invalid' for row in seen)
        assert not any('/auth/callback' in row.get('request', '') for row in seen)
