"""Offline regressions for the upstream-inspired desktop additions."""
import json
import threading
import time
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from account_inputs import parse_account_line
from oauth_refresh import RefreshError, refresh_account
from pool_flow import PushJob, run_pool_push
from pool_inspection import inspection_delta
from phone_price_catalog import normalize_price_options
from phone_smsbower import SmsBowerClient
from task_history import scan_history, read_history_json, HistoryRecord
from test_pool import account, settings, AdminBackend
from test_refresh import transport
from test_conversion import access


EMAIL = "fixture@example.com"
MAIL = "https://mail.test/messages/fixture-key/fixture@example.com"
TOTP = "JBSWY3DPEHPK3PXP"


@pytest.mark.parametrize("line,password,totp,mail", [
    (EMAIL, "", "", ""),
    (f"{EMAIL}----password----{MAIL}", "password", "", MAIL),
    (f"{EMAIL}----password----{MAIL}----{TOTP}", "password", TOTP, MAIL),
    (f"{EMAIL}----password----{TOTP}----{MAIL}", "password", TOTP, MAIL),
    (f"{EMAIL}----{MAIL}----{TOTP}", "", TOTP, MAIL),
    (f"{EMAIL}--------{MAIL}----{TOTP}", "", TOTP, MAIL),
    (f"{EMAIL}\tpassword\t{MAIL}\t{TOTP}", "password", TOTP, MAIL),
    (f"{EMAIL}----part----two----{TOTP}", "part----two", TOTP, ""),
    (f"{EMAIL}----part----two----{MAIL}----{TOTP}", "part----two", TOTP, MAIL),
])
def test_structured_login_fields_are_never_appended_to_password(line, password, totp, mail):
    parsed = parse_account_line(line)
    assert (parsed.email, parsed.password, parsed.totp_secret, parsed.mailbox_url) == (EMAIL, password, totp, mail)


def test_ambiguous_password_and_mailbox_is_rejected_without_echoing_secrets():
    with pytest.raises(ValueError) as caught:
        parse_account_line(f"{EMAIL}----part----not-base32!----{MAIL}")
    assert "not-base32" not in str(caught.value)


@pytest.mark.parametrize("stop_at", [3, 4])
def test_cancel_before_http_allows_retry_without_ambiguous_refresh(tmp_path, stop_at):
    calls = []
    should_stop = Mock(side_effect=[False] * (stop_at - 1) + [True])
    response = transport({"access_token": access()}, calls=calls)
    with pytest.raises(RefreshError) as caught:
        refresh_account(account(), should_stop=should_stop, recovery_dir=tmp_path, transport=response)
    assert caught.value.category == "cancelled" and not calls
    refresh_account(account(), recovery_dir=tmp_path, transport=response)
    assert len(calls) == 1


def test_bad_client_config_is_known_unsent_and_can_be_fixed(tmp_path):
    with patch("oauth_refresh.httpx.Client", side_effect=ValueError("secret-invalid-proxy")):
        with pytest.raises(RefreshError) as caught:
            refresh_account(account(), recovery_dir=tmp_path)
    assert caught.value.category == "refresh_unsent" and "secret" not in str(caught.value)
    refresh_account(account(), recovery_dir=tmp_path, transport=transport({"access_token": access()}))


@pytest.mark.parametrize("expired", [True, False])
def test_previously_refreshed_pool_job_checks_expiry_again(expired):
    job = PushJob(EMAIL, account=account(expires_at=1 if expired else int(time.time()) + 3600), refresh_state="refreshed")
    backend = AdminBackend()
    refresh = Mock(return_value=account(expires_at=int(time.time()) + 3600))
    run_pool_push([job], settings(), stop=threading.Event(), on_progress=lambda _: None,
                  client_factory=backend.client, refresh=refresh)
    assert refresh.call_count == int(expired)
    assert job.state == "created"


def test_inspection_diff_does_not_call_removed_accounts_recovered():
    def report(rows, groups=(7,)):
        return {"site": "https://fixture.test", "group_ids": list(groups), "accounts": rows}
    old = report([{"id": 1, "issues": ["expired", "disabled"]}, {"id": 2, "issues": ["expired"]}])
    new = report([{"id": 1, "issues": ["expired", "proxy"]}, {"id": 3, "issues": ["identity"]}])
    delta = inspection_delta(old, new)
    assert delta["removed_ids"] == [2]
    assert delta["resolved"] == [{"id": 1, "issue": "disabled"}]
    assert delta["persistent"] == [{"id": 1, "issue": "expired"}]
    assert len(delta["new"]) == 2
    assert inspection_delta(old, report(new["accounts"], (8,)))["baseline"]


def test_price_catalog_uses_provider_mapping_and_filters_invalid_quotes():
    prices = {"ghana": {"dr": {"cost": "0.03", "count": 200}},
              "38": {"dr": {"cost": "0.04", "count": 100}},
              "4": {"dr": {"cost": "0.02", "count": 90}},
              "187": {"dr": {"cost": "NaN", "count": 20}},
              "not-country": {"cost": "0.01", "count": 10},
              "999": {"cost": "0.01", "count": 7},
              "12": {"cost": "0.001", "count": 0}}
    countries = {"ghana": {"id": 900, "activate_org_code": 38, "eng": "Ghana"}}
    rows = normalize_price_options(prices, countries, "dr")
    assert [row["country"] for row in rows] == ["999", "4", "38"]
    assert not rows[0]["supported"]
    assert rows[-1]["price"] == "0.03" and rows[-1]["title"] == "加纳（Ghana）"
    client = SmsBowerClient(api_key="fixture")
    with patch.object(client, "_do", side_effect=[json.dumps(prices), json.dumps(countries)]) as request:
        assert client.get_price_options() == rows
    assert [call.args[0] for call in request.call_args_list] == ["getPrices", "getCountries"]


def test_history_scan_does_not_decrypt_and_only_lists_known_records(tmp_path):
    for folder, name in (("pool-fixture", "queue.dpapi.json"), ("auth-fixture", "accounts.json"),
                         ("token-refresh", "token.dpapi.json")):
        (tmp_path / folder).mkdir()
        (tmp_path / folder / name).write_text("not decrypted while listing", encoding="utf-8")
    (tmp_path / "phone-results-fixture.json").write_text("{}", encoding="utf-8")
    (tmp_path / "phone-orders.json").write_text("sensitive-orders", encoding="utf-8")
    rows = scan_history(tmp_path)
    assert {row.kind for row in rows} == {"授权结果", "推池任务", "接码报告"}
    assert len(rows) == 3
    outside = tmp_path.parent / "outside-history.json"
    with pytest.raises(ValueError):
        read_history_json(HistoryRecord(outside, "授权结果", 0), tmp_path)
