"""Bound country fallback and paid attempts without any external requests."""

import json
from unittest.mock import MagicMock, Mock, call, patch

import pytest

import openai_reauth as core
import phone_flow
from phone_pool import PhonePool, PhonePoolError, SmsbowerSettings, phone_retry_plan
from phone_smsbower import SmsBowerActivation, SmsBowerError
from test_phone_browser import browser, fixture_page as browser_page


@pytest.fixture
def phone_page(monkeypatch):
    page = Mock(url="https://auth.openai.com/add-phone")
    for name, result in (
        ("first_visible", Mock()), ("_fill_phone_number", True),
        ("ensure_sms_channel", "sms"),
        ("form_is_busy", False), ("visible_error_text", ""),
        ("_fill_otp_code", True),
    ):
        monkeypatch.setattr(phone_flow, name, Mock(return_value=result))
    monkeypatch.setattr(phone_flow, "log", Mock())
    monkeypatch.setattr(phone_flow, "PhoneSendGuard", MagicMock())
    return page


def fixture_pool(tmp_path, small=1, big=2, fallbacks=None):
    pool = PhonePool(SmsbowerSettings(
        api_key="fixture-only", country="38", max_price="0.06",
        number_attempts=small + 1, country_retry_count=big,
        fallback_countries=["16", "187"] if fallbacks is None else fallbacks,
    ), journal_path=tmp_path / "phone-orders.json")
    pool.client = Mock()
    pool.client.cancel.return_value = True
    pool.client.complete.return_value = True
    pool.client.request_additional.return_value = True
    pool.client.wait_for_code.return_value = "123456"
    return pool


def unavailable():
    return SmsBowerError("sms_unavailable", "SMSBower 当前国家或价格没有可用号码", "NO_NUMBERS")


def activation(order, country="38"):
    return SmsBowerActivation(order, "+233123456789", "dr", country)


def requested_countries(pool):
    return [item.kwargs["country"] for item in pool.client.get_number.call_args_list]


def test_zero_small_and_big_only_attempts_primary_once(tmp_path, phone_page):
    pool = fixture_pool(tmp_path, small=0, big=0)
    pool.client.get_number.side_effect = unavailable()
    with pytest.raises(core.AuthFlowError) as caught:
        phone_flow.complete_phone_on_page(phone_page, pool)
    assert caught.value.category == "circuit_open"
    assert requested_countries(pool) == ["38"]
    assert pool.settings.country == "38"


def test_each_country_has_own_budget_and_global_cap(tmp_path, phone_page):
    pool = fixture_pool(tmp_path, small=1, big=2)
    pool.client.get_number.side_effect = unavailable()
    with pytest.raises(core.AuthFlowError) as caught:
        phone_flow.complete_phone_on_page(phone_page, pool)
    assert caught.value.category == "circuit_open"
    assert requested_countries(pool) == ["38", "38", "16", "16", "187", "187"]
    assert all(item.kwargs["max_price"] == "0.06" for item in pool.client.get_number.call_args_list)
    assert pool.settings.country == "38"
    assert pool.settings.fallback_countries == ["16", "187"]


def test_success_on_final_fallback_attempt_stops_purchases(tmp_path, phone_page):
    pool = fixture_pool(tmp_path)
    pool.client.get_number.side_effect = [unavailable()] * 5 + [activation("last", "187")]
    with patch.object(phone_flow, "_submit_and_capture", side_effect=[(200, "{}"), (200, '{"success":true}')]):
        result = phone_flow.complete_phone_on_page(phone_page, pool)
    assert result["status"] == "verified"
    assert result["reuse_count"] == 1
    assert requested_countries(pool) == ["38", "38", "16", "16", "187", "187"]
    assert pool.active_country == "187"
    assert pool.slot.activation_id == "last"


def test_rejection_releases_number_before_country_purchase(tmp_path, phone_page):
    pool = fixture_pool(tmp_path, small=0, big=1)
    pool.client.get_number.side_effect = [activation("primary"), activation("fallback", "16")]
    with patch.object(phone_flow, "_submit_and_capture", side_effect=[
        (400, '{"error":{"code":"phone_number_already_in_use"}}'),
        (200, "{}"), (200, '{"success":true}'),
    ]):
        assert phone_flow.complete_phone_on_page(phone_page, pool)["status"] == "verified"
    assert requested_countries(pool) == ["38", "16"]
    calls = pool.client.mock_calls
    assert calls.index(call.cancel("primary")) < next(i for i, item in enumerate(calls) if item[0] == "get_number" and item.kwargs["country"] == "16")
    phone_page.goto.assert_called_once()


@pytest.mark.parametrize("small", [0, 1])
def test_cleanup_failure_stops_before_retry_or_country_switch(tmp_path, phone_page, small):
    pool = fixture_pool(tmp_path, small=small, big=1)
    pool.client.get_number.return_value = activation("unreleased")
    pool.client.cancel.return_value = False
    with patch.object(phone_flow, "_submit_and_capture", return_value=(400, '{"error":{"code":"invalid_phone_number"}}')):
        with pytest.raises(core.AuthFlowError) as caught:
            phone_flow.complete_phone_on_page(phone_page, pool)
    assert caught.value.category == "sms_cleanup_required"
    assert requested_countries(pool) == ["38"]
    assert pool.active_country == "38"
    assert pool.pending_cleanup == {"unreleased": "cancel"}
    phone_page.goto.assert_not_called()


@pytest.mark.parametrize("category", ["sms_fatal", "sms_network", "sms_cleanup_required", "rate_limited", "cancelled"])
def test_terminal_provider_failure_never_changes_country(tmp_path, phone_page, category):
    pool = fixture_pool(tmp_path)
    pool.client.get_number.side_effect = SmsBowerError(category, "固定的安全错误")
    with pytest.raises(core.AuthFlowError) as caught:
        phone_flow.complete_phone_on_page(phone_page, pool)
    assert caught.value.category == category
    assert requested_countries(pool) == ["38"]
    assert pool.active_country == "38"


@pytest.mark.parametrize("body, category", [
    ('{"error":{"code":"fraud_guard"}}', "phone_fraud"),
    ('{"error":{"code":"rate_limit_exceeded"}}', "rate_limited"),
])
def test_service_restrictions_never_rotate_numbers_or_countries(tmp_path, phone_page, body, category):
    pool = fixture_pool(tmp_path)
    pool.client.get_number.return_value = activation("one")
    with patch.object(phone_flow, "_submit_and_capture", return_value=(400, body)):
        with pytest.raises(core.AuthFlowError) as caught:
            phone_flow.complete_phone_on_page(phone_page, pool)
    assert caught.value.category == category
    assert requested_countries(pool) == ["38"]
    assert pool.active_country == "38"
    pool.client.cancel.assert_called_once_with("one")
    phone_page.goto.assert_not_called()


def test_overall_deadline_is_not_reset_when_country_changes(tmp_path, phone_page):
    pool = fixture_pool(tmp_path, small=0, big=2)
    clock = [95.0]

    def acquire(**kwargs):
        if kwargs["country"] == "38":
            assert kwargs["timeout"] == 5
            clock[0] = 99.0
        else:
            assert kwargs["timeout"] == 1
            clock[0] = 101.0
        raise unavailable()

    pool.client.get_number.side_effect = acquire
    with patch.object(phone_flow.time, "monotonic", side_effect=lambda: clock[0]):
        with pytest.raises(core.AuthFlowError) as caught:
            phone_flow.complete_phone_on_page(phone_page, pool, deadline=100)
    assert caught.value.category == "circuit_open"
    assert "总时限" in str(caught.value)
    assert requested_countries(pool) == ["38", "16"]


def test_cancellation_on_last_small_attempt_does_not_switch(tmp_path, phone_page):
    pool = fixture_pool(tmp_path, small=0, big=1)
    stopped = False

    def acquire(**kwargs):
        nonlocal stopped
        stopped = True
        raise unavailable()

    pool.client.get_number.side_effect = acquire
    with pytest.raises(core.AuthFlowError) as caught:
        phone_flow.complete_phone_on_page(phone_page, pool, should_stop=lambda: stopped)
    assert caught.value.category == "cancelled"
    assert requested_countries(pool) == ["38"]
    assert pool.active_country == "38"


def test_next_account_reuses_active_fallback_before_buying_primary(tmp_path, phone_page):
    pool = fixture_pool(tmp_path, small=0, big=1)
    pool.client.get_number.side_effect = [unavailable(), activation("fallback", "16"), activation("primary")]
    with patch.object(phone_flow, "_submit_and_capture", side_effect=[(200, "{}"), (200, '{"success":true}')] * 2):
        first = phone_flow.complete_phone_on_page(phone_page, pool)
        second = phone_flow.complete_phone_on_page(phone_page, pool)
    assert first["status"] == second["status"] == "verified"
    assert requested_countries(pool) == ["38", "16"]
    assert second['reuse_count'] == 2
    pool.client.complete.assert_not_called()
    pool.client.cancel.assert_not_called()
    pool.client.request_additional.assert_called_once_with('fallback')
    assert pool.settings.country == "38"
    assert pool.active_country == "16"


def test_next_primary_account_reuses_primary_number(tmp_path, phone_page):
    pool = fixture_pool(tmp_path)
    pool.client.get_number.return_value = activation("primary")
    with patch.object(phone_flow, "_submit_and_capture", side_effect=[(200, "{}"), (200, '{"success":true}')] * 2):
        phone_flow.complete_phone_on_page(phone_page, pool)
        result = phone_flow.complete_phone_on_page(phone_page, pool)
    assert result["reuse_count"] == 2
    assert requested_countries(pool) == ["38"]
    pool.client.request_additional.assert_called_once_with("primary")
    pool.client.complete.assert_not_called()


def test_exhausted_fallback_returns_to_primary_with_original_budget(tmp_path, phone_page):
    pool = fixture_pool(tmp_path, small=0, big=1)
    pool.client.get_number.side_effect = [unavailable(), activation('fallback', '16'), activation('primary')]
    with patch.object(phone_flow, '_submit_and_capture', side_effect=[(200, '{}'), (200, '{"success":true}')] * 4):
        results = [phone_flow.complete_phone_on_page(phone_page, pool) for _ in range(4)]
    assert [result['reuse_count'] for result in results] == [1, 2, 3, 1]
    assert requested_countries(pool) == ['38', '16', '38']
    assert pool.client.request_additional.call_count == 2
    pool.client.complete.assert_called_once_with('fallback')


def test_exhausted_fallback_failed_completion_prevents_buying_primary(tmp_path, phone_page):
    pool = fixture_pool(tmp_path, small=0, big=1)
    pool.switch_country("16")
    pool.client.get_number.return_value = activation("used-fallback", "16")
    pool.prepare_for_send()
    pool.mark_used()
    pool.slot.reuse_count = pool.slot.max_reuse_count
    pool.client.complete.return_value = False
    with pytest.raises(core.AuthFlowError) as caught:
        phone_flow.complete_phone_on_page(phone_page, pool)
    assert caught.value.category == "sms_cleanup_required"
    assert requested_countries(pool) == ["16"]
    assert pool.active_country == "16"
    assert pool.pending_cleanup == {"used-fallback": "complete"}
    pool.client.cancel.assert_not_called()


@pytest.mark.parametrize("changes", [
    {"number_attempts": 0}, {"number_attempts": -1}, {"number_attempts": 1.5},
    {"number_attempts": True}, {"country_retry_count": -1},
    {"country_retry_count": 1.5}, {"country_retry_count": True},
    {"country": "invalid-country"}, {"fallback_countries": ["invalid-country"]},
    {"fallback_countries": [""]}, {"fallback_countries": "16"},
    {"country_retry_count": 1, "fallback_countries": ["38"]},
    {"country_retry_count": 2, "fallback_countries": ["16", "United Kingdom"]},
])
def test_invalid_retry_plan_fails_before_files_or_network(tmp_path, changes):
    settings = SmsbowerSettings(api_key="fixture-only", **changes)
    report_dir = tmp_path / "should-not-exist"
    with patch.object(phone_flow, "PhonePool") as factory, patch.object(phone_flow, "run_batch_reauth") as batch:
        with pytest.raises(ValueError):
            phone_flow.run_batch_phone_verify([], settings, recovery_dir=report_dir)
    assert not report_dir.exists()
    factory.assert_not_called()
    batch.assert_not_called()


def test_country_aliases_deduplicate_and_only_planned_fallbacks_are_used():
    settings = SmsbowerSettings(country="加纳", number_attempts=2, country_retry_count=1,
                               fallback_countries=["38", "United Kingdom", "16", "USA"])
    assert phone_retry_plan(settings) == (2, ["38", "16"])


def test_batch_report_records_both_budgets_and_country_order(tmp_path):
    settings = SmsbowerSettings(api_key="private-fixture-key", country_retry_count=2,
                               number_attempts=3, fallback_countries=["16", "187"])
    with patch.object(phone_flow, "PhonePool") as factory, patch.object(phone_flow, "run_batch_reauth", return_value=[]):
        factory.return_value.close.return_value = {}
        phone_flow.run_batch_phone_verify([], settings, recovery_dir=tmp_path)
    report_text = next(tmp_path.glob("phone-results-*.json")).read_text(encoding="utf-8")
    report = json.loads(report_text)
    assert report["auto_retry_count"] == 2
    assert report["country_retry_count"] == 2
    assert report["primary_country"] == "38"
    assert report["fallback_countries"] == ["16", "187"]
    assert report["max_attempts_per_account"] == 9
    assert "private-fixture-key" not in report_text


def test_browser_sms_timeout_changes_country_and_submits_new_otp(browser, tmp_path):
    pool = fixture_pool(tmp_path, small=0, big=1)
    pool.client.get_number.side_effect = [activation("primary"), activation("fallback", "16")]
    pool.client.wait_for_code.side_effect = [None, "654321"]
    page, requests = browser_page(browser)
    try:
        result = phone_flow.complete_phone_on_page(page, pool)
        assert result["status"] == "verified"
        assert requested_countries(pool) == ["38", "16"]
        assert [kind for kind, body in requests] == ["send", "send", "validate"]
        assert requests[-1][1] == {"code": "654321"}
        pool.client.cancel.assert_called_once_with("primary")
    finally:
        page.close()
        pool.close()


def test_browser_fraud_response_ignores_all_retry_budgets(browser, tmp_path):
    pool = fixture_pool(tmp_path, small=2, big=2)
    pool.client.get_number.return_value = activation("primary")
    page, requests = browser_page(browser, send_status=400, send_body={"error": {"code": "fraud_guard"}})
    try:
        with pytest.raises(core.AuthFlowError) as caught:
            phone_flow.complete_phone_on_page(page, pool)
        assert caught.value.category == "phone_fraud"
        assert requested_countries(pool) == ["38"]
        assert [kind for kind, body in requests] == ["send"]
        pool.client.wait_for_code.assert_not_called()
        pool.client.cancel.assert_called_once_with("primary")
    finally:
        page.close()
        pool.close()
