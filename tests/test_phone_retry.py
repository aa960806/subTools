"""One bounded retry budget for paid phone verification; no external traffic."""

import json
from unittest.mock import MagicMock, Mock, call, patch

import pytest

import openai_reauth as core
import phone_flow
from phone_pool import PhonePool, SmsbowerSettings
from phone_smsbower import SmsBowerActivation, SmsBowerError


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


def fixture_pool(tmp_path, retries=2):
    pool = PhonePool(
        SmsbowerSettings(api_key="fixture-key", number_attempts=retries + 1),
        journal_path=tmp_path / "phone-orders.json",
    )
    pool.client = Mock()
    pool.client.cancel.return_value = True
    pool.client.complete.return_value = True
    pool.client.wait_for_code.return_value = "123456"
    return pool


def activation(order):
    return SmsBowerActivation(order, "+233123456789", "dr", "38")


def unavailable():
    return SmsBowerError("sms_unavailable", "SMSBower 当前没有可用号码", "NO_NUMBERS")


def test_zero_retries_tries_once_and_opens_circuit(tmp_path, phone_page):
    pool = fixture_pool(tmp_path, retries=0)
    pool.client.get_number.side_effect = unavailable()
    with pytest.raises(core.AuthFlowError) as caught:
        phone_flow.complete_phone_on_page(phone_page, pool)
    assert caught.value.category == "circuit_open"
    assert "0 次重试" in str(caught.value)
    pool.client.get_number.assert_called_once()
    phone_page.goto.assert_not_called()


def test_purchase_send_and_receive_failures_share_one_limit(tmp_path, phone_page):
    pool = fixture_pool(tmp_path)
    pool.client.get_number.side_effect = [unavailable(), activation("one"), activation("two")]
    pool.client.wait_for_code.return_value = None
    with patch.object(phone_flow, "_submit_and_capture", side_effect=[
        (400, '{"error":{"code":"invalid_phone_number"}}'), (200, "{}"),
    ]):
        with pytest.raises(core.AuthFlowError) as caught:
            phone_flow.complete_phone_on_page(phone_page, pool)
    assert caught.value.category == "circuit_open"
    assert pool.client.get_number.call_count == 3
    assert pool.client.cancel.call_args_list == [call("one"), call("two")]
    assert phone_page.goto.call_count == 1
    assert pool.close() == {}
    assert json.loads(pool.journal_path.read_text(encoding="utf-8")) == []


def test_success_on_last_allowed_attempt_keeps_reuse_state(tmp_path, phone_page):
    pool = fixture_pool(tmp_path)
    pool.client.get_number.side_effect = [unavailable(), activation("one"), activation("two")]
    with patch.object(phone_flow, "_submit_and_capture", side_effect=[
        (400, '{"error":{"code":"phone_number_already_in_use"}}'),
        (200, "{}"), (200, '{"success":true}'),
    ]):
        result = phone_flow.complete_phone_on_page(phone_page, pool)
    assert result["status"] == "verified"
    assert result["reuse_count"] == 1
    assert pool.client.get_number.call_count == 3
    assert pool.slot.activation_id == "two"
    pool.client.cancel.assert_called_once_with("one")
    pool.close()
    pool.client.complete.assert_called_once_with("two")


@pytest.mark.parametrize("category", ["sms_fatal", "rate_limited", "sms_network"])
def test_terminal_provider_error_never_uses_retries(tmp_path, phone_page, category):
    pool = fixture_pool(tmp_path, retries=4)
    pool.client.get_number.side_effect = SmsBowerError(category, "固定错误提示")
    with pytest.raises(core.AuthFlowError) as caught:
        phone_flow.complete_phone_on_page(phone_page, pool)
    assert caught.value.category == category
    pool.client.get_number.assert_called_once()
    phone_page.goto.assert_not_called()


def test_fraud_immediately_stops_without_replacement(tmp_path, phone_page):
    pool = fixture_pool(tmp_path, retries=4)
    pool.client.get_number.return_value = activation("one")
    with patch.object(phone_flow, "_submit_and_capture", return_value=(400, '{"error":{"code":"fraud_guard"}}')):
        with pytest.raises(core.AuthFlowError) as caught:
            phone_flow.complete_phone_on_page(phone_page, pool)
    assert caught.value.category == "phone_fraud"
    pool.client.get_number.assert_called_once()
    pool.client.cancel.assert_called_once_with("one")
    phone_page.goto.assert_not_called()


def test_stop_after_unavailable_does_not_buy_again(tmp_path, phone_page):
    pool = fixture_pool(tmp_path)
    stopped = False

    def request(**kwargs):
        nonlocal stopped
        stopped = True
        raise unavailable()

    pool.client.get_number.side_effect = request
    with pytest.raises(core.AuthFlowError) as caught:
        phone_flow.complete_phone_on_page(phone_page, pool, should_stop=lambda: stopped)
    assert caught.value.category == "cancelled"
    pool.client.get_number.assert_called_once()


@pytest.mark.parametrize("category", ["needs_interaction", "failed"])
def test_nonretryable_page_error_keeps_existing_category(tmp_path, phone_page, category):
    pool = fixture_pool(tmp_path)
    with patch.object(phone_flow, "_complete_phone_attempt", side_effect=core.AuthFlowError(category, "需要检查")) as attempt:
        with pytest.raises(core.AuthFlowError) as caught:
            phone_flow.complete_phone_on_page(phone_page, pool)
    assert caught.value.category == category
    attempt.assert_called_once()
    pool.client.get_number.assert_not_called()


def test_reload_failure_stops_batch_without_exposing_browser_details(tmp_path, phone_page):
    pool = fixture_pool(tmp_path)
    pool.client.get_number.return_value = activation("one")
    phone_page.goto.side_effect = RuntimeError("private-browser-url")
    with patch.object(phone_flow, "_submit_and_capture", return_value=(400, '{"error":{"code":"invalid_phone_number"}}')):
        with pytest.raises(core.AuthFlowError) as caught:
            phone_flow.complete_phone_on_page(phone_page, pool)
    assert caught.value.category == "sms_network"
    assert "private-browser-url" not in str(caught.value)
    pool.client.get_number.assert_called_once()
    pool.client.cancel.assert_called_once_with("one")


@pytest.mark.parametrize("failure", ["exhausted", "fraud", "fatal", "deadline"])
def test_circuit_stops_remaining_accounts_and_reports_cleanup(tmp_path, phone_page, failure):
    pool = fixture_pool(tmp_path, retries=0)
    pool.client.get_number.return_value = activation("one")
    # A declined cancellation must remain on disk after the batch stops.
    pool.client.cancel.return_value = False
    body = '{"error":{"code":"invalid_phone_number"}}'
    status = 400
    clock = [179.0]
    expected_category = "circuit_open"
    if failure == "fraud":
        body = '{"error":{"code":"fraud_guard"}}'
        expected_category = "phone_fraud"
    if failure == "fatal":
        pool.client.get_number.side_effect = SmsBowerError("sms_fatal", "SMSBower 余额不足")
        expected_category = "sms_fatal"
    if failure == "deadline":
        status, body = 200, "{}"

        def expired_sms(*args, **kwargs):
            clock[0] = 181.0
            return None

        pool.client.wait_for_code.side_effect = expired_sms

    accounts = [core.AccountInput(f"test{i}@example.com", "fixture", "", i) for i in range(3)]

    def login(page, account, *args, **kwargs):
        kwargs["phone_state"].update(attempted=True, status="attempted")
        return kwargs["phone_handler"](phone_page, account, deadline=180 if failure == "deadline" else None)

    with patch.object(phone_flow, "PhonePool", return_value=pool), \
         patch.object(phone_flow, "_submit_and_capture", return_value=(status, body)), \
         patch.object(phone_flow.time, "monotonic", side_effect=lambda: clock[0]), \
         patch("playwright.sync_api.sync_playwright"), \
         patch.object(core, "CallbackServer"), patch.object(core, "launch_browser"), \
         patch.object(core, "login_with_browser", side_effect=login) as worker, \
         patch.object(core, "log"):
        results = phone_flow.run_batch_phone_verify(accounts, pool.settings, recovery_dir=tmp_path)

    assert worker.call_count == 1
    assert len(results) == 1
    assert results[0].category == expected_category
    assert results[0].phone_status == "failed"
    if failure == "deadline":
        assert "总时限已用尽" in results[0].error
    report = json.loads(next(tmp_path.glob("phone-results-*.json")).read_text(encoding="utf-8"))
    assert report["attempted"] == 1
    assert report["unattempted"] == 2
    assert report["auto_retry_count"] == 0
    assert report["finished_at"]
    pool.client.get_number.assert_called_once()
    if failure != "fatal":
        assert report["pending_cleanup_count"] == 1
        assert pool.pending_cleanup == {"one": "cancel"}
        assert json.loads(pool.journal_path.read_text(encoding="utf-8"))[0]["activation_id"] == "one"
