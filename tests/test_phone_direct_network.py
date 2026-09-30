"""Direct phone clients must ignore ambient proxies; traffic stays on loopback."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import MagicMock, Mock, patch

import pytest

import openai_reauth as core
from phone_mailbox import MailboxClient
from phone_smsbower import SmsBowerClient


@pytest.fixture
def local_endpoints(monkeypatch):
    direct_requests = []
    proxy_requests = []

    class Endpoint(BaseHTTPRequestHandler):
        def do_GET(self):
            direct_requests.append(self.path)
            body = json.dumps({"items": []}).encode() if self.path.startswith("/api/messages/") else b"ACCESS_BALANCE:9.00"
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            direct_requests.append(self.path)
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({"access_token": "fixture-access", "refresh_token": "fixture-refresh", "id_token": "fixture-id"}).encode())

        def log_message(self, *_):
            pass

    class Proxy(BaseHTTPRequestHandler):
        def do_GET(self):
            proxy_requests.append(self.path)
            self.send_response(502)
            self.end_headers()

        do_POST = do_GET

        def log_message(self, *_):
            pass

    endpoint = ThreadingHTTPServer(("127.0.0.1", 0), Endpoint)
    proxy = ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
    workers = [threading.Thread(target=server.serve_forever, daemon=True) for server in (endpoint, proxy)]
    for worker in workers:
        worker.start()
    proxy_url = f"http://127.0.0.1:{proxy.server_port}"
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.setenv(key, proxy_url)
    for key in ("NO_PROXY", "no_proxy"):
        monkeypatch.setenv(key, "")
    try:
        yield f"http://127.0.0.1:{endpoint.server_port}", direct_requests, proxy_requests
    finally:
        for server in (endpoint, proxy):
            server.shutdown()
            server.server_close()
        for worker in workers:
            worker.join(timeout=2)


def test_phone_sms_and_mailbox_ignore_environment_proxy(local_endpoints):
    origin, direct, proxied = local_endpoints
    assert SmsBowerClient("fixture-key", endpoint=origin + "/sms")._do("getBalance") == "ACCESS_BALANCE:9.00"
    with MailboxClient(origin + "/messages/fixture-token/test@example.com", "test@example.com") as mailbox:
        assert not mailbox.snapshot().ids
    assert len(direct) == 2
    assert not proxied


def test_all_token_exchange_defaults_ignore_environment_proxy(local_endpoints):
    origin, direct, proxied = local_endpoints
    with patch.object(core, "TOKEN_URL", origin + "/token"):
        result = core.exchange_code("fixture-code", "fixture-verifier", core.DEFAULT_REDIRECT_URI, None, trust_env=False)
        assert result["access_token"] == "fixture-access"
        assert direct == ["/token"]
        assert not proxied
        core.exchange_code("fixture-code", "fixture-verifier", core.DEFAULT_REDIRECT_URI, None)
        assert direct == ["/token", "/token"]
        assert not proxied


@pytest.mark.parametrize("phone", [False, True])
def test_account_sets_same_token_exchange_network_policy_for_all_workflows(phone):
    session = core.OAuthSession("fixture-state", "fixture-verifier", core.DEFAULT_REDIRECT_URI, "https://auth.openai.com/oauth/authorize")
    callback = core.CallbackResult(code="fixture-code", state=session.state)
    with patch.object(core, "generate_oauth_session", return_value=session), \
         patch.object(core, "login_with_browser", return_value=callback), \
         patch.object(core, "exchange_code", return_value={}) as exchange, \
         patch.object(core, "build_account_payload", return_value={"credentials": {}}), patch.object(core, "log"):
        result = core.reauth_account(MagicMock(), Mock(), core.AccountInput("test@example.com", "dummy", "", 1), 30, None, True, phone_handler=Mock() if phone else None)
    assert result.ok
    assert exchange.call_args.kwargs == {"trust_env": False}
