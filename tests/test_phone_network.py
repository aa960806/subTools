"""System network selection and sharing, without real accounts or SMS orders."""
import threading
from contextlib import nullcontext
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock, patch

import pytest

import openai_reauth as core
import phone_network as network
from phone_mailbox import MailboxClient
from phone_smsbower import SmsBowerClient, COUNTRY_CATALOG, COUNTRY_PINYIN, country_dropdown_values, parse_country_choice


def config(server="proxy.example:8080", **changes):
    return dict(enabled=True, server=server, pac=False, auto_detect=False, **changes)


@pytest.mark.parametrize("server,expected", [
    ("proxy.example:8080", "http://proxy.example:8080"),
    ("https=proxy.example:8080;http=proxy.example:8080", "http://proxy.example:8080"),
    (" http = proxy.example:8080 ; https = proxy.example:8080 ; ", "http://proxy.example:8080"),
    ("socks=proxy.example:1080", "socks5://proxy.example:1080"),
    ("https=https://proxy.example:8443", "https://proxy.example:8443"),
    ("https=[::1]:8080", "http://[::1]:8080"),
    ("http://user:password@proxy.example:8080", "http://user:password@proxy.example:8080"),
    ("http://user:pass=word@proxy.example:8080", "http://user:pass%3Dword@proxy.example:8080"),
])
def test_windows_static_proxy_formats(server, expected):
    with patch.object(network, "_read_windows_proxy", return_value=config(server)):
        assert network.resolve_phone_proxy("system") == expected


@pytest.mark.parametrize("changes", [
    {"server": ""}, {"server": "https=invalid-secret"},
    {"server": "http=proxy.example:80;https=other.example:81"},
    {"server": "https=proxy.example:80;https=other.example:81"},
    {"server": "ftp=proxy.example:80"}, {"pac": True}, {"auto_detect": True},
])
def test_ambiguous_or_automatic_system_config_fails_without_secret_echo(changes):
    settings = config()
    settings.update(changes)
    with patch.object(network, "_read_windows_proxy", return_value=settings):
        with pytest.raises(ValueError) as caught:
            network.resolve_phone_proxy("system")
    assert "自定义代理" in str(caught.value)
    assert "invalid-secret" not in str(caught.value)
    assert "proxy.example" not in str(caught.value)


def test_system_disabled_and_direct_do_not_reuse_stale_addresses():
    settings = config("stale-secret")
    settings["enabled"] = False
    with patch.object(network, "_read_windows_proxy", return_value=settings) as read:
        assert network.resolve_phone_proxy("system", "http://saved.example:8080") == ""
        read.assert_called_once()
    with patch.object(network, "_read_windows_proxy") as read:
        assert network.resolve_phone_proxy("direct", "invalid-unused-proxy") == ""
        read.assert_not_called()


def test_country_choices_sort_by_pinyin_and_keep_provider_identity():
    labels = country_dropdown_values()
    codes = [parse_country_choice(value) for value in labels]
    assert set(codes) == {code for code, _, _ in COUNTRY_CATALOG} == set(COUNTRY_PINYIN)
    assert len(codes) == len(set(codes))
    assert [COUNTRY_PINYIN[code] for code in codes] == sorted(COUNTRY_PINYIN.values())
    assert codes[:5] == ["39", "23", "21", "95", "175"]
    assert codes.index("187") < codes.index("12")  # USA then USA virtual
    assert parse_country_choice("加纳（Ghana）") == "38"
    assert parse_country_choice("哥伦比亚") == "33"


def test_resolved_system_proxy_carries_browser_mailbox_sms_and_token_requests(monkeypatch):
    """Real HTTP + real browser, one loopback proxy, no external traffic."""
    received = []

    class Proxy(BaseHTTPRequestHandler):
        def respond(self):
            received.append((self.path, self.headers.get("User-Agent")))
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            if "/api/messages/" in self.path:
                body = b'{"items":[]}'
            elif "/sms" in self.path:
                body = b"ACCESS_BALANCE:1.00"
            elif "/token" in self.path:
                body = b'{"access_token":"fixture-access","refresh_token":"fixture-refresh","id_token":"fixture-id"}'
            else:
                body = b"<html><body>fixture login</body></html>"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = respond

        def log_message(self, *_):
            pass

    proxy = ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
    worker = threading.Thread(target=proxy.serve_forever, daemon=True)
    worker.start()
    origin = "http://phone-fixture.invalid"
    # Ambient proxies must not override the chosen system snapshot.
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "*")
    try:
        with patch.object(network, "_read_windows_proxy", return_value=config(f"127.0.0.1:{proxy.server_port}")):
            selected = network.resolve_phone_proxy("system")
        assert SmsBowerClient("fixture-key", endpoint=origin + "/sms", proxy=selected)._do("getBalance") == "ACCESS_BALANCE:1.00"
        with MailboxClient(origin + "/messages/fixture-token/test@example.com", "test@example.com", proxy=selected) as mailbox:
            assert not mailbox.snapshot().ids
        session = core.OAuthSession("fixture-state", "fixture-verifier", core.DEFAULT_REDIRECT_URI, origin + "/login")

        def login(page, *_args, **_kwargs):
            page.goto(origin + "/login")
            ua = page.evaluate("navigator.userAgent")
            assert ua == next(header for url, header in received if url.endswith("/login"))
            assert "Chrome/122." not in ua
            return core.CallbackResult(code="fixture-code", state=session.state)

        from playwright.sync_api import sync_playwright
        with sync_playwright() as playwright:
            browser = core.launch_browser(playwright, True, selected, phone_workflow=True)
            try:
                with patch.object(core, "TOKEN_URL", origin + "/token"), \
                     patch.object(core, "generate_oauth_session", return_value=session), \
                     patch.object(core, "login_with_browser", side_effect=login), \
                     patch.object(core, "build_account_payload", return_value={"credentials": {}}):
                    result = core.reauth_account(browser, Mock(), core.AccountInput("test@example.com", "fixture-pw", "", 1),
                                                 30, selected, True, phone_handler=Mock())
                assert result.ok, result.error
            finally:
                browser.close()
        for path in ("/sms", "/api/messages/", "/login", "/token"):
            assert any(path in url for url, _ in received)
    finally:
        proxy.shutdown()
        proxy.server_close()
        worker.join(timeout=2)


@pytest.mark.parametrize("flags,allowed", [(3, True), (7, False), (11, False)])
def test_windows_connection_flags_detect_automatic_proxy_even_without_top_level_setting(flags, allowed):
    import winreg
    def query(handle, name):
        data = {"ProxyEnable": 1, "ProxyServer": "localhost:8080",
                "DefaultConnectionSettings": b"\0" * 8 + flags.to_bytes(4, "little")}
        if name not in data:
            raise FileNotFoundError(name)
        return data[name], None
    with patch.object(winreg, "OpenKey", return_value=nullcontext(Mock())), patch.object(winreg, "QueryValueEx", side_effect=query):
        if allowed:
            assert network.system_proxy() == "http://localhost:8080"
        else:
            with pytest.raises(ValueError, match="自动代理脚本或自动检测"):
                network.system_proxy()


def test_registry_access_error_does_not_silently_use_direct_or_echo_data():
    import winreg
    with patch.object(winreg, "OpenKey", side_effect=PermissionError("fixture-private-proxy")):
        with pytest.raises(ValueError, match="无法读取") as caught:
            network.system_proxy()
    assert "fixture-private-proxy" not in str(caught.value)
