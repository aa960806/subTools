"""Automatic prices, strict spending bounds, and asynchronous GUI quotes."""
import json
from unittest.mock import Mock, patch

import pytest

import openai_reauth_gui as gui
from phone_pool import PhonePool, PhonePoolError, SmsbowerSettings
from phone_smsbower import SmsBowerError, SmsBowerActivation
from test_phone_browser_settings import phone_page


def offer(provider="1", price="0.064", country="187", count=10):
    return dict(country=country, service="dr", provider_id=provider, price=price, count=count)


def make_pool(tmp_path, cap="0.14"):
    pool = PhonePool(SmsbowerSettings(api_key="fixture-key", country="187", max_price=cap, auto_price_match=True), tmp_path / "orders.json")
    pool.client = Mock()
    pool.client.get_prices.return_value = [offer(), offer("2", "0.126"), offer("3", "0.16")]
    pool.client.get_number.return_value = SmsBowerActivation("fixture-order", "+12025550123", "dr", "187", "0.064")
    pool.client.cancel.return_value = True
    pool.client.complete.return_value = True
    return pool


def unavailable():
    return SmsBowerError("sms_unavailable", "NO_NUMBERS", "NO_NUMBERS")


def test_first_purchase_matches_lowest_price_and_reports_actual_cost(tmp_path):
    pool = make_pool(tmp_path)
    pool.client.get_prices.return_value += [offer("4", "0.064")]
    assert pool.prepare_for_send() == "+12025550123"
    options = pool.client.get_number.call_args.kwargs
    assert options["min_price"] == options["max_price"] == "0.064"
    assert options["provider_ids"] == "1,4"
    assert pool.settings.max_price == "0.14"
    assert pool.mark_used()["price"] == "0.064"
    pool.close()


def test_no_numbers_moves_to_next_cheapest_in_budget_without_repeating_failed_quote(tmp_path):
    pool = make_pool(tmp_path)
    pool.client.get_number.side_effect = [unavailable(), SmsBowerActivation("fixture-order", "+12025550123", "dr", "187", "0.126")]
    with pytest.raises(PhonePoolError, match="后续重试将跳过"):
        pool.prepare_for_send()
    # Numeric equality matters even if the service changes decimal formatting.
    pool.client.get_prices.return_value[0]["price"] = "0.0640"
    pool.prepare_for_send()
    assert [call.kwargs["max_price"] for call in pool.client.get_number.call_args_list] == ["0.064", "0.126"]
    assert pool.client.get_prices.call_count == 2
    pool.close()


def test_failed_lowest_offer_never_causes_purchase_over_cap(tmp_path):
    pool = make_pool(tmp_path, cap="0.08")
    pool.client.get_number.side_effect = unavailable()
    with pytest.raises(PhonePoolError):
        pool.prepare_for_send()
    with pytest.raises(PhonePoolError, match="不会突破最高单价"):
        pool.prepare_for_send()
    pool.client.get_number.assert_called_once()


@pytest.mark.parametrize("rows", [[], [offer(price="0.126")], [offer(country="38")]])
def test_no_matching_quote_never_issues_purchase(tmp_path, rows):
    pool = make_pool(tmp_path, cap="0.08")
    pool.client.get_prices.return_value = rows
    with pytest.raises(PhonePoolError) as caught:
        pool.prepare_for_send()
    assert caught.value.category == "sms_unavailable"
    pool.client.get_number.assert_not_called()


def test_switch_country_refreshes_quotes_and_uses_country_specific_supplier(tmp_path):
    pool = make_pool(tmp_path)
    pool.client.get_number.side_effect = unavailable()
    with pytest.raises(PhonePoolError):
        pool.prepare_for_send()
    pool.switch_country("38")
    pool.client.get_prices.return_value = [offer("1", "0.014", "38")]
    with pytest.raises(PhonePoolError):
        pool.prepare_for_send()
    assert pool.client.get_prices.call_args.args == ("dr", "38")
    assert pool.client.get_number.call_args.kwargs["max_price"] == "0.014"
    assert pool.client.get_number.call_args.kwargs["country"] == "38"


@pytest.mark.parametrize("price", ["0.15", "NaN", "invalid"])
def test_supplier_price_mismatch_cancels_and_records_no_binding(tmp_path, price):
    pool = make_pool(tmp_path)
    pool.client.get_number.return_value.price = price
    with pytest.raises(PhonePoolError, match="订单价格") as caught:
        pool.prepare_for_send()
    assert caught.value.category == "sms_fatal"
    pool.client.cancel.assert_called_once_with("fixture-order")
    assert json.loads(pool.journal_path.read_text()) == []
    assert not pool.slot.activation_id


def test_price_mismatch_cleanup_failure_preserves_order_and_blocks_next_purchase(tmp_path):
    pool = make_pool(tmp_path)
    pool.client.get_number.return_value.price = "0.15"
    pool.client.cancel.return_value = False
    with pytest.raises(PhonePoolError) as caught:
        pool.prepare_for_send()
    assert caught.value.category == "sms_cleanup_required"
    assert pool.pending_cleanup == {"fixture-order": "cancel"}
    with pytest.raises(PhonePoolError):
        pool.prepare_for_send()
    pool.client.get_number.assert_called_once()


def test_gui_country_selection_queries_in_background_and_displays_stock(phone_page):
    page, _ = phone_page
    page.api_key_var.set("fixture-key")
    page.country_var.set(gui.country_label("187"))
    page.max_price_var.set("0.08")
    with patch.object(gui.threading, "Thread") as thread:
        page.country_combo.event_generate("<<ComboboxSelected>>")
    args = thread.call_args.kwargs["args"]
    assert args[1] == "187"
    assert page._quote_busy
    assert page.refresh_quotes_btn.instate(["disabled"])
    with patch.object(gui, "SmsBowerClient") as client:
        client.return_value.get_prices.return_value = [offer()]
        page._read_quotes_worker(*args)
    page.win.after_cancel(page._after_id)
    page._drain()
    text = page.quote_status_var.get()
    assert "$0.064" in text and "库存 10" in text
    assert "美国" in text
    assert not page._quote_busy
    assert page.current_settings().auto_price_match
    assert page.max_price_var.get() == "0.08"
    client.return_value.get_number.assert_not_called()


def test_late_quote_cannot_replace_selected_country_and_pending_query_uses_latest(phone_page):
    page, _ = phone_page
    page.api_key_var.set("fixture-key")
    page.country_var.set(gui.country_label("187"))
    with patch.object(gui.threading, "Thread") as thread:
        page.refresh_quotes()
        first = thread.call_args.kwargs["args"]
        page.country_var.set(gui.country_label("38"))
        page.refresh_quotes()
        assert thread.call_count == 1
        page._receive_quotes(first[0], "187", [offer()], "")
        assert thread.call_count == 2
        assert thread.call_args.kwargs["args"][1] == "38"
    assert "$0.064" not in page.quote_status_var.get()


def test_cap_edits_recompute_preview_without_network_or_raising_cap(phone_page):
    page, _ = phone_page
    page._quote_snapshot = ("187", [offer(price="0.126")], "12:00:00")
    page.max_price_var.set("0.08")
    assert "超过最高单价 $0.08" in page.quote_status_var.get()
    page.max_price_var.set("0.14")
    assert "自动匹配：$0.126" in page.quote_status_var.get()
    page.max_price_var.set("NaN")
    assert "必须" in page.quote_status_var.get()


def test_key_or_network_change_invalidates_quote(phone_page):
    page, _ = phone_page
    page._quote_snapshot = ("187", [offer()], "12:00:00")
    old = page._quote_generation
    page.api_key_var.set("fixture-new-key")
    assert page._quote_snapshot is None and page._quote_generation > old
    page._quote_snapshot = ("187", [offer()], "12:00:00")
    page.network_mode_var.set(gui.NETWORK_MODES["direct"])
    assert page._quote_snapshot is None


def test_read_only_worker_safe_after_close_and_masks_errors(phone_page):
    page, _ = phone_page
    with patch.object(gui, "SmsBowerClient") as client:
        client.return_value.get_prices.side_effect = RuntimeError("fixture-key-sensitive-url")
        page._read_quotes_worker(0, "187", "fixture-key", "")
    event = page.event_queue.get_nowait()
    assert "sensitive-url" not in str(event)
    page.begin_close()
    before = page.quote_status_var.get()
    page._receive_quotes(0, "187", [offer()], "")
    assert page.quote_status_var.get() == before


def test_auto_price_preference_persists_without_overwriting_limit(phone_page):
    page, config = phone_page
    page.max_price_var.set("0.08")
    for enabled in (False, True):
        page.auto_price_var.set(enabled)
        page._save_settings()
        page.auto_price_var.set(not enabled)
        page._load_settings()
        assert page.auto_price_var.get() is enabled
        assert json.loads(config.read_text())["auto_price_match"] is enabled
        assert page.max_price_var.get() == "0.08"
