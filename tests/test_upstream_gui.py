"""Selection, timer and quote UI contracts; no real network or credentials."""
import json
import time
from unittest.mock import Mock, patch

import openai_reauth_gui as gui
import pool_gui
from account_inputs import AccountInput, account_input_from_mapping
from phone_smsbower import country_label
from test_ui_navigation import app
from test_pool import account
from pool_flow import parse_push_text


def connected_pool(app):
    app.open_pool()
    page = app.pool_page
    page.site_var.set("https://fixture.test")
    page.secret_var.set("fixture-key")
    page._connected_id = page._settings(require_groups=False).connection_id()
    page._groups = [{"id": 7, "name": "fixture"}]
    page.group_list.insert("end", "fixture")
    page.group_list.selection_set(0)
    return page


def test_rejecting_browser_relogin_does_not_block_other_retries(app):
    ambiguous = account_input_from_mapping(account())
    ambiguous.refresh_state = "refresh_unknown"
    normal = AccountInput("second@example.com", "fixture-password", "", 2)
    app.retry_accounts = [ambiguous, normal]
    with patch.object(gui.messagebox, "askyesno", return_value=False), patch.object(app, "_start_batch") as start:
        app.retry_failed()
    assert start.call_args.args[0] == [normal]
    assert ambiguous.oauth_account is not None


def test_selected_auth_retry_preserves_unselected_retry_inputs(app):
    first = AccountInput("same@example.com", "first", "", 1)
    second = AccountInput("same@example.com", "second", "", 2)
    app.retry_accounts = [first, second]
    with patch.object(gui.threading.Thread, "start"):
        app._start_batch([first], retry=True)
    app._finish_controls()
    assert app.retry_accounts == [second, first]
    assert second.password == "second"


def test_pool_filter_and_selected_actions_keep_same_email_identities(app):
    page = connected_pool(app)
    page.input_text.insert("1.0", json.dumps([account(space="space-a"), account(space="space-b")]))
    assert page.preview()
    first, second = page.jobs
    assert len(page.tree.get_children()) == 2
    page.tree.selection_set(first.uid)
    page.defer_selected()
    assert first.state == "deferred" and second.state == "ready"
    page.result_filter.status.set("已暂缓")
    assert page.tree.get_children() == (first.uid,)
    page.tree.selection_set(first.uid)
    page.defer_selected()
    assert not page.tree.get_children() and first.state == "ready"
    page.result_filter.status.set("全部状态")
    page.tree.selection_set(second.uid)
    with patch.object(page, "_start_jobs") as start:
        page.retry_selected()
    assert start.call_args.args[0] == [second]


def test_timer_defers_while_busy_and_stops_on_connection_change(app):
    page = connected_pool(app)
    page.inspect_interval_var.set("2")
    with patch.object(page, "inspect") as inspect:
        page.toggle_inspection_timer()
        inspect.assert_called_once_with(scheduled=True)
        assert page._inspect_interval == 120
        page._inspect_due = time.monotonic() - 1
        page._busy = "push"
        page._tick_inspection()
        assert inspect.call_count == 1
        page._busy = ""
        page._tick_inspection()
        assert inspect.call_count == 2
        page.site_var.set("https://other.test")
        assert page._inspect_due is None and page._inspect_interval == 0


def test_timer_completion_records_delta_and_does_not_overlap_or_persist_enable(app):
    page = connected_pool(app)
    report = {"site": "https://fixture.test", "group_ids": [7], "total": 1, "attention": 1,
              "checked_at": "fixture-time", "accounts": [{"id": 1, "email": "fixture@example.com", "issues": ["已禁用"]}]}
    with patch.object(pool_gui, "inspect_pool", return_value=report) as inspect, patch.object(pool_gui, "run_pool_push") as push:
        page.toggle_inspection_timer()
        page.worker.join(3)
        page._drain()
    inspect.assert_called_once()
    push.assert_not_called()
    assert page._inspect_due > time.monotonic()
    assert page._inspection_report["changes"]["baseline"]
    assert "inspection_enabled" not in json.loads(page.config_path.read_text())
    page.begin_close()
    assert page._inspect_due is None


def test_changed_group_scope_discards_late_inspection(app):
    page = connected_pool(app)
    page.events.put(("inspection", page._connected_id, {"group_ids": [8]}))
    page._drain()
    assert page._inspection_report is None


def test_price_catalog_apply_keeps_cap_retry_budget_and_order(app):
    app.open_phone()
    page = app.phone_page
    page.max_price_var.set("0.08")
    page.country_retry_count_var.set("0")
    page._apply_catalog_countries(["4"], False)
    page._apply_catalog_countries(["38", "187", "4"], True)
    assert page.country_var.get() == country_label("4")
    assert page._fallback_countries == ["38", "187"]
    assert page.max_price_var.get() == "0.08" and page.country_retry_count_var.get() == "0"
    page.running = True
    page._apply_catalog_countries(["38"], False)
    assert page.country_var.get() == country_label("4")


def test_catalog_discards_stale_credentials_without_queueing_key(app):
    app.open_phone()
    page = app.phone_page
    page.api_key_var.set("fixture-key")
    page.network_mode_var.set("直连")
    catalog = page.price_catalog
    with patch("phone_price_catalog.SmsBowerClient.get_price_options", return_value=[]) as request:
        catalog.refresh()
        catalog.worker.join(3)
    request.assert_called_once()
    page.api_key_var.set("replacement-key")
    catalog.drain()
    assert "变化" in catalog.status.get() and catalog.snapshot is None


def test_auth_system_proxy_is_explicit_and_legacy_direct_is_migrated(app):
    app.network_mode_var.set("系统代理")
    with patch("phone_network.system_proxy", return_value="http://fixture.test:8080"):
        assert app.current_proxy() == "http://fixture.test:8080"
    app._save_auth_settings()
    saved = json.loads(gui.AUTH_CONFIG_PATH.read_text())
    assert saved["network_mode"] == "system"
    app.network_mode_var.set("直连")
    app._load_auth_settings()
    assert app.network_mode_var.get() == "系统代理"
    gui.AUTH_CONFIG_PATH.write_text(json.dumps({"use_proxy": False, "proxy": ""}))
    app._load_auth_settings()
    assert app.network_mode_var.get() == "直连" and app.current_proxy() is None
