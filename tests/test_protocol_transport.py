"""Exercise actual curl transport against loopback only; no external services."""
import gzip
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import time

import httpx
import pytest

from flow_control import AuthFlowError
from protocol_transport import CurlTransport


@pytest.fixture
def local_site():
    seen = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            seen.append((self.path, self.headers.get('Cookie'), self.headers.get('User-Agent')))
            self.send_response(302 if self.path == '/redirect' else 200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Set-Cookie', 'first=one; Path=/')
            self.send_header('Set-Cookie', 'second=two; Path=/')
            self.send_header('Content-Encoding','gzip')
            self.send_header('Location','http://does-not-exist.invalid/')
            self.end_headers()
            try:
                self.wfile.write(gzip.compress(b'x' * (5*1024*1024) if self.path == '/large' else b'{"ok":true}'))
            except (BrokenPipeError, ConnectionResetError): pass
    server = ThreadingHTTPServer(('127.0.0.1',0), Handler)
    worker = threading.Thread(target=server.serve_forever,daemon=True); worker.start()
    yield f'http://127.0.0.1:{server.server_port}', seen
    server.shutdown(); server.server_close(); worker.join(2)


def test_curl_cookies_compression_no_redirect_and_environment_proxy_ignored(local_site,monkeypatch):
    url, seen = local_site
    monkeypatch.setenv('HTTP_PROXY','http://127.0.0.1:1')
    monkeypatch.setenv('ALL_PROXY','http://127.0.0.1:1')
    transport = CurlTransport(proxy=None,deadline=time.monotonic()+5,should_stop=None)
    with httpx.Client(transport=transport,trust_env=False) as client:
        response = client.get(url+'/redirect')
        assert response.status_code == 302 and response.json() == {'ok':True}
        assert len(response.headers.get_list('set-cookie')) == 2
        assert client.get(url+'/again').json() == {'ok':True}
        assert 'first=one' in seen[1][1] and 'second=two' in seen[1][1]
        assert seen[0][1] is None and 'Chrome' in seen[0][2]
    # A fresh account transport has no cookies from the previous login.
    with httpx.Client(transport=CurlTransport(proxy=None,deadline=time.monotonic()+5,should_stop=None)) as client:
        client.get(url+'/fresh')
    assert seen[-1][1] is None and len(seen) == 3


def test_bounded_response_and_cancellation(local_site):
    url, seen = local_site
    with httpx.Client(transport=CurlTransport(proxy=None,deadline=time.monotonic()+5,should_stop=None)) as client:
        with pytest.raises(AuthFlowError,match='过大'):
            client.get(url+'/large')
    with httpx.Client(transport=CurlTransport(proxy=None,deadline=time.monotonic()+5,should_stop=lambda:True)) as client:
        with pytest.raises(AuthFlowError,match='取消'):
            client.get(url+'/must-not-send')
    assert len(seen) == 1
