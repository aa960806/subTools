"""The browser owns the lifetime of its authenticated SOCKS adapter."""
from contextlib import contextmanager
from unittest.mock import Mock, patch

import pytest

import openai_reauth as core


@pytest.mark.parametrize("failed_launches", [0, 1, 2])
def test_proxy_resources_survive_fallback_and_close_on_browser_disconnect(failed_launches):
    state = []
    config = {"server": "http://127.0.0.1:43210"}

    @contextmanager
    def proxy_context(_):
        state.append("started")
        try:
            yield config
        finally:
            state.append("closed")

    playwright = Mock()
    browser = Mock()
    playwright.chromium.launch.side_effect = [RuntimeError("fixture")] * failed_launches + [browser]
    with patch("reauth_proxy_bridge.browser_proxy_context", proxy_context), patch.object(core, "log"):
        assert core.launch_browser(playwright, True, "fixture") is browser
    assert state == ["started"]
    assert playwright.chromium.launch.call_args.kwargs["proxy"] is config
    event, close = browser.on.call_args.args
    assert event == "disconnected"
    close(browser)
    close(browser)
    assert state == ["started", "closed"]


def test_launch_failure_closes_proxy_resources():
    state = []

    @contextmanager
    def proxy_context(_):
        try:
            yield {"server": "http://127.0.0.1:43210"}
        finally:
            state.append("closed")

    playwright = Mock()
    playwright.chromium.launch.side_effect = RuntimeError("fixture")
    with patch("reauth_proxy_bridge.browser_proxy_context", proxy_context), patch.object(core, "log"):
        with pytest.raises(RuntimeError, match="无法启动浏览器"):
            core.launch_browser(playwright, True, "fixture")
    assert playwright.chromium.launch.call_count == 3
    assert state == ["closed"]
