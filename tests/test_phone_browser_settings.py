"""Phone browser and network controls; all configuration and work are fixtures."""

import json
import threading
import tkinter as tk
from contextlib import nullcontext
from unittest.mock import MagicMock, Mock, patch

import pytest

import openai_reauth as core
import openai_reauth_gui as gui


@pytest.mark.parametrize("headless", [False, True])
def test_phone_launch_reuses_authorization_settings_and_browser_order(headless):
    playwright = Mock()
    browser = Mock(version="153.0.0.0")
    playwright.chromium.launch.side_effect = [RuntimeError("missing Chrome"), browser]
    with patch("reauth_proxy_bridge.browser_proxy_context", return_value=nullcontext(None)), \
         patch.object(core, "_system_chrome_executables", return_value=[]), patch.object(core, "log") as log:
        assert core.launch_browser(playwright, headless, None, phone_workflow=True) is browser
    calls = playwright.chromium.launch.call_args_list
    assert [call.kwargs.get("channel") for call in calls] == (["msedge", None] if headless else ["chrome", "msedge"])
    with patch("reauth_proxy_bridge.browser_proxy_context", return_value=nullcontext(None)), patch.object(core, "log"):
        authorization = Mock()
        core.launch_browser(authorization, headless, None)
    first_phone_launch = dict(calls[0].kwargs)
    assert "--no-proxy-server" in first_phone_launch["args"]
    assert first_phone_launch == authorization.chromium.launch.call_args.kwargs
    assert any("153.0.0.0" in call.args[0] for call in log.call_args_list)


def test_explicit_phone_proxy_is_not_overridden_by_direct_flag():
    playwright = Mock()
    proxy_config = {"server": "http://proxy.example:8080"}
    with patch("reauth_proxy_bridge.browser_proxy_context", return_value=nullcontext(proxy_config)), patch.object(core, "log"):
        core.launch_browser(playwright, True, "http://proxy.example:8080", phone_workflow=True)
    kwargs = playwright.chromium.launch.call_args.kwargs
    assert kwargs["proxy"] == proxy_config
    assert "--no-proxy-server" not in kwargs["args"]
    assert "--headless=new" in kwargs["args"]


def test_visible_phone_prefers_system_chrome_before_stale_channel_and_retains_fallback():
    playwright = Mock()
    system_path = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
    browser = Mock(version="152.0.7977.83")
    playwright.chromium.launch.side_effect = [RuntimeError("unavailable system install"), browser]
    with patch("reauth_proxy_bridge.browser_proxy_context", return_value=nullcontext(None)), \
         patch.object(core, "_system_chrome_executables", return_value=[system_path]), patch.object(core, "log"):
        assert core.launch_browser(playwright, False, None, phone_workflow=True) is browser
    calls = playwright.chromium.launch.call_args_list
    assert calls[0].kwargs["executable_path"] == system_path
    assert calls[1].kwargs["channel"] == "chrome"
    for call in calls:
        assert call.kwargs["headless"] is False
        assert call.kwargs["args"] == ["--disable-blink-features=AutomationControlled", "--no-proxy-server"]
        assert call.kwargs["ignore_default_args"] == ["--enable-automation"]


def test_headless_phone_preserves_authorization_edge_preference_even_with_system_chrome():
    playwright = Mock()
    with patch("reauth_proxy_bridge.browser_proxy_context", return_value=nullcontext(None)), \
         patch.object(core, "_system_chrome_executables") as system_chrome, patch.object(core, "log"):
        core.launch_browser(playwright, True, None, phone_workflow=True)
    system_chrome.assert_not_called()
    assert playwright.chromium.launch.call_args.kwargs["channel"] == "msedge"


def test_system_chrome_candidates_require_existing_files_and_deduplicate(tmp_path, monkeypatch):
    installed = tmp_path / "program-files"
    executable = installed / "Google" / "Chrome" / "Application" / "chrome.exe"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"fixture")
    monkeypatch.setattr(core.sys, "platform", "win32")
    monkeypatch.setenv("ProgramFiles", str(installed))
    monkeypatch.setenv("ProgramFiles(x86)", str(installed))
    assert core._system_chrome_executables() == [str(executable)]
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "missing"))
    assert core._system_chrome_executables() == [str(executable)]
    monkeypatch.delenv("ProgramFiles(x86)")
    assert core._system_chrome_executables() == []


@pytest.mark.parametrize("headless,channel", [(False, "chrome"), (True, "msedge")])
def test_authorization_launch_defaults_are_preserved(headless, channel):
    playwright = Mock()
    with patch("reauth_proxy_bridge.browser_proxy_context", return_value=nullcontext(None)), \
         patch.object(core, "_system_chrome_executables") as system_chrome, patch.object(core, "log"):
        core.launch_browser(playwright, headless, None)
    system_chrome.assert_not_called()
    kwargs = playwright.chromium.launch.call_args.kwargs
    assert kwargs["channel"] == channel
    assert kwargs["ignore_default_args"] == ["--enable-automation"]
    assert "--disable-blink-features=AutomationControlled" in kwargs["args"]
    assert ("--headless=new" in kwargs["args"]) == headless


@pytest.mark.parametrize("phone", [False, True])
def test_all_oauth_contexts_use_native_user_agent_with_phone_only_routing_safety(phone):
    browser = MagicMock()
    handler = Mock() if phone else None
    with patch.object(core, "login_with_browser", side_effect=core.AuthFlowError("cancelled", "fixture stopped")), patch.object(core, "log"):
        core.reauth_account(browser, Mock(), core.AccountInput("test@example.com", "dummy", "", 1), 30, None, True, phone_handler=handler)
    kwargs = browser.new_context.call_args.kwargs
    assert kwargs["locale"] == "en-US"
    assert "user_agent" not in kwargs
    if phone:
        assert kwargs["service_workers"] == "block"
    else:
        assert "service_workers" not in kwargs
    browser.new_context.return_value.close.assert_called_once()


@pytest.mark.parametrize("phone", [False, True])
def test_batch_enables_phone_network_settings_only_for_phone_handler(phone):
    handler = Mock() if phone else None
    account = core.AccountInput("test@example.com", "dummy", "", 1)
    result = core.ReauthResult(account.email, False, category="cancelled")
    with patch("playwright.sync_api.sync_playwright"), patch.object(core, "CallbackServer"), \
         patch.object(core, "launch_browser") as launch, patch.object(core, "reauth_account", return_value=result), patch.object(core, "log"):
        core.run_batch_reauth([account], recovery_dir=None, phone_handler=handler)
    assert launch.call_args.kwargs.get("phone_workflow", False) == phone


@pytest.fixture
def phone_page(tmp_path):
    with patch.object(gui, "PHONE_CONFIG_PATH", tmp_path / "phone.json"), \
         patch.object(gui, "_TASK_LOCK", threading.Lock()), patch("phone_network.system_proxy", return_value=""):
        root = tk.Tk()
        root.withdraw()
        page = gui.PhoneWindow(root, lambda _: None)
        try:
            yield page, tmp_path / "phone.json"
        finally:
            page.dispose()
            root.destroy()


def test_new_phone_settings_visible_and_disabled_proxy_ignores_remembered_address(phone_page):
    page, _ = phone_page
    assert page.show_browser_var.get()
    assert page.current_network_mode() == "system"
    page.proxy_var.set("socks5://fixture-user:fixture-password@proxy.example:8080")
    assert page.current_network_mode() == "custom"
    assert page.current_settings().proxy.startswith("socks5://")
    page.network_mode_var.set(gui.NETWORK_MODES["direct"])
    assert page.current_settings().proxy == ""
    assert "fixture-password" in page.proxy_var.get()
    page.proxy_var.set("an invalid remembered address")
    page.network_mode_var.set(gui.NETWORK_MODES["direct"])
    assert page.current_settings().proxy == ""


def test_checked_proxy_requires_address(phone_page):
    page, _ = phone_page
    page.network_mode_var.set(gui.NETWORK_MODES["custom"])
    with pytest.raises(ValueError, match="请填写代理地址"):
        page.current_settings()


def test_phone_network_and_browser_preferences_persist_without_changing_purchase_settings(phone_page):
    page, config = phone_page
    page.country_var.set(gui.country_label("38"))
    page.max_price_var.set("0.06")
    proxy = "socks5://fixture-user:fixture-password@proxy.example:8080"
    page.proxy_var.set(proxy)
    page.network_mode_var.set(gui.NETWORK_MODES["direct"])
    page.show_browser_var.set(True)
    with patch.object(gui, "_protect_setting", side_effect=lambda value: "dpapi:" + value if value else ""), \
         patch.object(gui, "_unprotect_setting", side_effect=lambda value: value.removeprefix("dpapi:")):
        page._save_settings()
        page.proxy_var.set("")
        page.show_browser_var.set(False)
        page._load_settings()
    saved = json.loads(config.read_text(encoding="utf-8"))
    assert saved["country"] == "38"
    assert saved["max_price"] == "0.06"
    assert page.proxy_var.get() == proxy
    assert page.current_network_mode() == "direct"
    assert page.show_browser_var.get()
    assert page.current_settings().proxy == ""


def test_legacy_config_keeps_previous_proxy_and_headless_behavior(phone_page):
    page, config = phone_page
    config.write_text(json.dumps({"proxy": "dpapi:fixture-proxy", "country": "38"}), encoding="utf-8")
    with patch.object(gui, "_unprotect_setting", return_value="socks5://fixture-user:fixture-password@proxy.example:8080"):
        page._load_settings()
    assert page.current_network_mode() == "custom"
    assert not page.show_browser_var.get()


@pytest.mark.parametrize("use_proxy", [False, True])
def test_start_logs_safe_effective_conditions_and_passes_only_enabled_proxy(phone_page, use_proxy):
    page, _ = phone_page
    page.set_input("test@example.com----fixture-account-password")
    page.api_key_var.set("fixture-api-key")
    page.proxy_var.set("socks5://fixture-user:fixture-password@proxy.example:8080")
    page.network_mode_var.set(gui.NETWORK_MODES["custom" if use_proxy else "direct"])
    with patch.object(gui.threading, "Thread") as thread, patch.object(page, "_save_settings"):
        page.start()
    args = thread.call_args.kwargs["args"]
    _, settings, _, headless, human_options = args
    assert bool(settings.proxy) == use_proxy
    assert not headless
    assert human_options["enabled"] is True
    summary = [line for line in page.log_text.get("1.0", "end").splitlines() if "本轮条件" in line][0]
    assert "$0.06" in summary
    assert gui.country_label("38") in summary
    assert ("SOCKS5 代理" if use_proxy else "直连（未使用代理）") in summary
    assert "可见浏览器" in summary
    for secret in ("fixture-user", "fixture-password", "proxy.example", "fixture-api-key", "fixture-account-password"):
        assert secret not in summary


def test_system_network_is_resolved_once_at_start_and_worker_uses_snapshot(phone_page):
    page, config = phone_page
    page.set_input("test@example.com----fixture-account-password")
    page.api_key_var.set("fixture-api-key")
    with patch("phone_network.system_proxy", return_value="http://proxy.example:8080") as resolve, \
         patch.object(gui.threading, "Thread") as thread:
        page.start()
    resolve.assert_called_once()
    args = thread.call_args.kwargs["args"]
    assert args[1].proxy == "http://proxy.example:8080"
    assert args[1].network_source == "system"
    assert json.loads(config.read_text())["network_mode"] == "system"
    with patch("phone_network.system_proxy", side_effect=AssertionError("must not re-read network")), \
         patch.object(gui, "run_batch_phone_verify", return_value=[]) as run:
        page._run_worker(*args)
    assert run.call_args.args[1].proxy == "http://proxy.example:8080"
    assert "proxy" not in run.call_args.kwargs  # preserve source metadata
    assert "系统代理 → HTTP 代理" in page.log_text.get("1.0", "end")


def test_system_config_error_prevents_worker_and_order_creation(phone_page):
    page, _ = phone_page
    page.set_input("test@example.com----fixture-pw")
    page.api_key_var.set("fixture-key")
    with patch("phone_network.system_proxy", side_effect=ValueError("自动代理脚本需改用自定义代理")), \
         patch.object(gui.threading, "Thread") as thread, patch.object(gui.messagebox, "showerror") as error:
        page.start()
    thread.assert_not_called()
    assert not page.running
    assert "自定义代理" in error.call_args.args[1]


@pytest.mark.parametrize("mode", ["system", "direct", "custom"])
def test_network_modes_round_trip_and_disable_unused_fields(phone_page, mode):
    page, _ = phone_page
    page.proxy_var.set("http://proxy.example:8080")
    page.network_mode_var.set(gui.NETWORK_MODES[mode])
    page._save_settings()
    page.network_mode_var.set(gui.NETWORK_MODES["direct"])
    page._load_settings()
    assert page.current_network_mode() == mode
    assert page.proxy_entry.instate(["!disabled" if mode == "custom" else "disabled"])


def test_legacy_direct_settings_and_invalid_mode_never_silently_choose_proxy(phone_page):
    page, config = phone_page
    config.write_text(json.dumps({"use_proxy": False}), encoding="utf-8")
    page._load_settings()
    assert page.current_network_mode() == "direct"
    assert "旧接码配置" in page.log_text.get("1.0", "end")
    config.write_text(json.dumps({"network_mode": ["invalid"], "api_key": "fixture-legacy-key"}), encoding="utf-8")
    page._load_settings()  # plaintext migration must not crash on a bad mode
    with pytest.raises(ValueError, match="请选择"):
        page.current_settings()


def test_both_country_choosers_sorted_without_changing_fallback_execution_order(phone_page):
    page, _ = phone_page
    ordered = gui.country_dropdown_values()
    assert list(page.country_combo["values"]) == ordered
    for code in ("187", "6"):
        page.fallback_country_var.set(gui.country_label(code))
        page._add_fallback_country()
    expected = [label for label in ordered if gui.parse_country_choice(label) not in {"38", "187", "6"}]
    assert list(page.fallback_country_combo["values"]) == expected
    assert page._fallback_countries == ["187", "6"]
    assert "本轮不会换国" in page.retry_hint_var.get()
    page.country_retry_count_var.set("2")
    assert page.current_settings().fallback_countries == ["187", "6"]
    assert "本轮不会换国" not in page.retry_hint_var.get()
