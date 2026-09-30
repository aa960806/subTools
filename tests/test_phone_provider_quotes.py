"""Supply diagnostics and bounded provider selection; no real purchases."""
import json
import time
from unittest.mock import Mock, patch

import pytest

from phone_pool import PhonePool, PhonePoolError, SmsbowerSettings
from phone_smsbower import SmsBowerClient, SmsBowerError


def quotes(rows, country="187"):
    return json.dumps({country: {"dr": rows}})


def quote(price="0.064", count=12, provider=3193):
    return {"price": price, "count": count, "provider_id": provider}


def allocation():
    return json.dumps({"activationId": "fixture-order", "phoneNumber": "12025550123", "activationCost": "0.064"})


def test_quote_parser_retains_usable_offers_only_without_echoing_untrusted_fields():
    client = SmsBowerClient(api_key="fixture-key")
    data = quotes({
        "3193": quote(), "100": quote("0.13", 5, 100),
        "101": quote("NaN", 5, 101), "102": quote("-1", 5, 102),
        "103": quote("0.01", 0, 103), "104": quote("0.01", True, 104),
        "105": quote("0.01", 5, "fixture-private-field"),
        "106": quote("0.01", "1.5", 106), "107": quote("", 2, 107),
    })
    with patch.object(client, "_do", return_value=data) as request:
        result = client.get_prices("openai", "187", timeout=3)
    request.assert_called_once_with("getPricesV3", {"service": "dr", "country": "187"}, timeout=3)
    assert [(row["provider_id"], row["price"]) for row in result] == [("3193", "0.064"), ("100", "0.13")]
    assert "fixture-private" not in str(result)


@pytest.mark.parametrize("raw,category", [("BAD_KEY", "sms_fatal"), ('{"error":"NO_BALANCE"}', "sms_fatal"),
                                          ('{"187":{"dr":[]}}', "sms_provider"), ("private-secret-not-json", "sms_provider")])
def test_quote_errors_are_safe(raw, category):
    client = SmsBowerClient()
    with patch.object(client, "_do", return_value=raw), pytest.raises(SmsBowerError) as caught:
        client.get_prices("dr", "187")
    assert caught.value.category == category
    assert "private-secret" not in str(caught.value)


def test_default_no_numbers_uses_quoted_provider_only_on_next_budgeted_attempt(tmp_path):
    pool = PhonePool(SmsbowerSettings(api_key="fixture-key", country="187", max_price="0.08"), tmp_path / "orders.json")
    with patch.object(pool.client, "_do", side_effect=[
        "NO_NUMBERS", quotes({"3193": quote(), "4": quote("0.126", 200, 4)}), allocation(), "ACCESS_CANCEL",
    ]) as request, patch("openai_reauth.log"):
        with pytest.raises(SmsBowerError, match="NO_NUMBERS"):
            pool.prepare_for_send()
        assert request.call_count == 1  # no hidden allocation or quote retry
        assert pool.prepare_for_send() == "+12025550123"
        calls = request.call_args_list
        assert [call.args[0] for call in calls] == ["getNumberV2", "getPricesV3", "getNumberV2"]
        assert "providerIds" not in calls[0].args[1]
        assert calls[2].args[1] == {"service": "dr", "country": "187", "maxPrice": "0.08", "providerIds": "3193"}
        assert pool.close() == {}
    assert json.loads((tmp_path / "orders.json").read_text()) == []


def test_quote_stock_does_not_turn_unavailable_allocation_into_success(tmp_path):
    pool = PhonePool(SmsbowerSettings(api_key="fixture-key", country="187", max_price="0.08"), tmp_path / "orders.json")
    with patch.object(pool.client, "_do", side_effect=["NO_NUMBERS", quotes({"3193": quote()}), "NO_NUMBERS"]) as request, \
         patch("openai_reauth.log"):
        with pytest.raises(SmsBowerError):
            pool.prepare_for_send()
        with pytest.raises(PhonePoolError, match="仍未分配") as caught:
            pool.prepare_for_send()
    assert caught.value.category == "sms_unavailable"
    assert not pool.slot.activation_id
    assert sum(call.args[0] == "getNumberV2" for call in request.call_args_list) == 2


@pytest.mark.parametrize("minimum,maximum,expected", [("0.07", "0.14", "20"), ("", "0.08", "10"), ("", "", "10,20,30")])
def test_provider_filter_uses_price_range_without_exact_price_or_automatic_increase(minimum, maximum, expected):
    pool = PhonePool(SmsbowerSettings(country="187", min_price=minimum, max_price=maximum))
    pool._quote_retry_countries.add("187")
    response = quotes({"10": quote("0.064", 10, 10), "20": quote("0.126", 10, 20), "30": quote("0.16", 10, 30)})
    with patch.object(pool.client, "_do", side_effect=[response, "NO_NUMBERS"]) as request, patch("openai_reauth.log"):
        with pytest.raises(PhonePoolError):
            pool.prepare_for_send()
    params = request.call_args.args[1]
    assert params["providerIds"] == expected
    assert params.get("maxPrice", "") == maximum
    assert params.get("minPrice", "") == minimum


def test_quote_above_cap_does_not_raise_purchase_cap():
    pool = PhonePool(SmsbowerSettings(country="187", max_price="0.08"))
    pool._quote_retry_countries.add("187")
    with patch.object(pool.client, "_do", side_effect=[quotes({"20": quote("0.126", 20, 20)}), "NO_NUMBERS"]) as request:
        with pytest.raises(PhonePoolError, match="最低 \\$0.126"):
            pool.prepare_for_send()
    assert request.call_args.args[1] == {"country": "187", "service": "dr", "maxPrice": "0.08"}


@pytest.mark.parametrize("category", ["sms_fatal", "rate_limited", "sms_network"])
def test_quote_failure_does_not_issue_purchase(category):
    pool = PhonePool(SmsbowerSettings(country="187"))
    pool._quote_retry_countries.add("187")
    with patch.object(pool.client, "get_prices", side_effect=SmsBowerError(category, "fixture-error")), \
         patch.object(pool.client, "get_number") as buy:
        with pytest.raises(SmsBowerError) as caught:
            pool.prepare_for_send()
    assert caught.value.category == category
    buy.assert_not_called()


def test_stop_after_reading_quotes_cancels_before_buy():
    pool = PhonePool(SmsbowerSettings(country="187"))
    pool._quote_retry_countries.add("187")
    stopped = False
    def get_prices(*_args, **_kwargs):
        nonlocal stopped
        stopped = True
        return []
    with patch.object(pool.client, "get_prices", side_effect=get_prices), patch.object(pool.client, "get_number") as buy:
        with pytest.raises(PhonePoolError) as caught:
            pool.prepare_for_send(should_stop=lambda: stopped, deadline=time.monotonic() + 10)
    assert caught.value.category == "cancelled"
    buy.assert_not_called()


def test_fallback_country_does_not_inherit_previous_provider_selection():
    pool = PhonePool(SmsbowerSettings(country="187", country_retry_count=1, fallback_countries=["38"]))
    pool._quote_retry_countries.add("187")
    pool.switch_country("38")
    with patch.object(pool.client, "get_prices") as prices, patch.object(pool.client, "_do", return_value="NO_NUMBERS") as request:
        with pytest.raises(SmsBowerError):
            pool.prepare_for_send()
    prices.assert_not_called()
    assert request.call_args.args[1]["country"] == "38"
    assert "providerIds" not in request.call_args.args[1]
