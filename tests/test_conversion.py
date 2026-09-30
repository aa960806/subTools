"""Offline conversion regressions; no real credentials or network calls."""

import base64
import copy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import reauth_formats as f
from reauth_conversion import load_conversion_files, parse_conversion_text


AUTH = "https://api.openai.com/auth"
PROFILE = "https://api.openai.com/profile"


def jwt(claims, *, synthetic=False):
    def enc(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")
    header = {"alg": "none" if synthetic else "RS256", "typ": "JWT"}
    if synthetic:
        header["cpa_synthetic"] = True
    return enc(header) + "." + enc(claims) + ("." if synthetic else ".fixture-signature")


def access(**claims):
    return jwt({"exp": 1893456000, "iat": 1893452400,
                PROFILE: {"email": "fixture@example.com"},
                AUTH: {"chatgpt_account_id": "space-fixture", "chatgpt_plan_type": "plus"}, **claims})


def web(**overrides):
    return {"user": {"email": "fixture@example.com", "id": "user-fixture", "custom": "keep"},
            "account": {"id": "space-fixture", "planType": "plus"},
            "accessToken": access(), "sessionToken": "fixture-session-secret",
            "expires": "2031-01-01T00:00:00Z", **overrides}


def nine(**overrides):
    return {"provider": "codex", "authType": "oauth", "email": "fixture@example.com",
            "accessToken": access(), "refreshToken": "fixture-refresh",
            "providerSpecificData": {"chatgptAccountId": "space-fixture", "chatgptPlanType": "plus"},
            **overrides}


def cpa(**overrides):
    return {"type": "codex", "email": "fixture@example.com", "account_id": "space-fixture",
            "access_token": access(), "refresh_token": "fixture-refresh", **overrides}


def parse(value):
    return parse_conversion_text(json.dumps(value))


def warnings(accounts, target="sub2"):
    return "\n".join(f.conversion_warnings(accounts, target))


def test_web_session_keeps_session_separate_and_never_fabricates_tokens_or_client():
    source = web()
    original = copy.deepcopy(source)
    kind, accounts = parse(source)
    creds = accounts[0]["credentials"]
    assert kind == "web_session"
    assert source == original
    assert creds["expires_at"] == 1893456000  # access exp, not the 2031 session expiry
    assert not creds["refresh_token"] and not creds["id_token"]
    assert "client_id" not in creds
    meta = accounts[0]["extra"][f.CONVERSION_META_KEY]
    assert meta["unmapped"]["sessionToken"] == "fixture-session-secret"
    assert meta["unmapped"]["user"]["custom"] == "keep"
    assert "缺少 refresh_token" in warnings(accounts)
    assert "sessionToken 不能代替" in warnings(accounts)
    payload = f.build_cpa_payload(accounts[0])
    assert tuple(payload) == f.CPA_FIELDS
    assert payload["id_token"] == ""
    assert "fixture-session-secret" not in warnings(accounts, "cpa")
    assert f.CONVERSION_META_KEY in warnings(accounts, "cpa")


def test_session_expiry_alone_is_not_an_access_expiry():
    _, accounts = parse(web(accessToken="opaque-access"))
    assert "expires_at" not in accounts[0]["credentials"]
    assert f.build_cpa_payload(accounts[0])["expired"] == ""
    assert "只有网页会话" in warnings(accounts)


def test_nine_router_preserves_real_tokens_client_and_refresh_timestamp():
    record = nine(idToken="issued-id-fixture", clientId="source-client", isActive=False,
                  expiresAt=1893456000123, lastRefresh="2026-09-17T08:00:00.456Z", createdAt="2020-01-01T00:00:00Z")
    kind, accounts = parse(record)
    assert kind == "9router"
    creds = f.build_export_payload(accounts)["accounts"][0]["credentials"]
    assert creds["refresh_token"] == "fixture-refresh"
    assert creds["id_token"] == "issued-id-fixture"
    assert creds["client_id"] == "source-client"
    assert creds["expires_at"] == 1893456000
    payload = f.build_cpa_payload(accounts[0])
    assert payload["disabled"] is True
    assert payload["last_refresh"] == "2026-09-17T16:00:00.456+08:00"
    assert "手动停用" in warnings(accounts)
    assert "createdAt" in accounts[0]["extra"][f.CONVERSION_META_KEY]["unmapped"]


def test_nine_router_does_not_treat_local_id_as_workspace_id():
    _, accounts = parse(nine(id="local-row-id", accessToken="opaque", providerSpecificData={}))
    assert "chatgpt_account_id" not in accounts[0]["credentials"]
    assert "缺少 account_id" in warnings(accounts)


@pytest.mark.parametrize("flag,value", [("disabled", "false"), ("isActive", 1)])
def test_source_flags_must_be_boolean(flag, value):
    with pytest.raises(ValueError, match="布尔"):
        parse(nine(**{flag: value}))


def test_cpa_from_reference_ignores_synthetic_claims_but_retains_original_token():
    placeholder = jwt({"email": "fixture@example.com", AUTH: {
        "chatgpt_account_id": "wrong-space", "chatgpt_plan_type": "free"}}, synthetic=True)
    _, accounts = parse(cpa(id_token=placeholder, id_token_synthetic=True))
    assert accounts[0]["credentials"]["plan_type"] == "plus"
    assert "合成占位" in warnings(accounts)
    assert "plan_type" in warnings(accounts) and "冲突" in warnings(accounts)
    payload = f.build_cpa_payload(accounts[0])
    assert payload["id_token"] == placeholder
    assert tuple(payload) == f.CPA_FIELDS
    # The JWT header still identifies the placeholder after its top-level flag is dropped.
    _, reloaded = parse(payload)
    assert "合成占位" in warnings(reloaded)
    assert reloaded[0]["credentials"]["plan_type"] == "plus"


def test_top_level_synthetic_marker_blocks_enrichment_even_with_normal_header():
    marked = jwt({AUTH: {"chatgpt_plan_type": "free"}})
    _, accounts = parse(cpa(id_token=marked, id_token_synthetic=True))
    assert accounts[0]["credentials"]["plan_type"] == "plus"
    assert "合成占位" in warnings(accounts)


def test_missing_fields_are_filled_for_cpa_without_mutating_sub2():
    at = jwt({"email": "fixture@example.com", AUTH: {"chatgpt_account_id": "space-fixture"}})
    account = {"name": "Display name", "platform": "openai", "type": "oauth", "credentials": {"access_token": at}}
    original = copy.deepcopy(account)
    kind, accounts = parse(account)
    payload = f.build_cpa_payload(accounts[0])
    assert kind == "sub2"
    assert payload["email"] == "fixture@example.com"
    assert payload["account_id"] == "space-fixture"
    assert f.build_export_payload(accounts)["accounts"] == [original]


def test_expired_access_cannot_hide_behind_outer_future_expiry(monkeypatch):
    monkeypatch.setattr(f.time, "time", lambda: 1800000000)
    _, accounts = parse(cpa(access_token=access(exp=1700000000), expired="2030-01-01T00:00:00Z", refresh_token=""))
    text = warnings(accounts)
    assert "已过期" in text and "到期时间冲突" in text and "缺少 refresh_token" in text
    assert accounts[0]["credentials"]["expires_at"] == 1893456000
    status = f.account_conversion_status(accounts[0])
    assert "已过期" in status["state"] and "冲突" in status["state"]


def test_unknown_expiry_is_unknown_not_valid():
    _, accounts = parse(cpa(access_token="opaque", refresh_token=""))
    status = f.account_conversion_status(accounts[0])
    assert status["expires"] == "未知"
    assert status["state"] == "有效期未知"


def test_explicit_identity_is_preserved_with_conflict_warning():
    _, accounts = parse(cpa(email="explicit@example.com", account_id="explicit-space"))
    payload = f.build_cpa_payload(accounts[0])
    assert payload["email"] == "explicit@example.com"
    assert payload["account_id"] == "explicit-space"
    text = warnings(accounts)
    assert "email" in text and "chatgpt_account_id" in text and "冲突" in text
    assert "explicit@example.com" not in text and "explicit-space" not in text


def test_id_vs_access_conflict_is_reported_without_explicit_override():
    identity = jwt({"email": "fixture@example.com", AUTH: {"chatgpt_account_id": "id-space"}})
    _, accounts = parse(cpa(account_id="", id_token=identity))
    assert "chatgpt_account_id" in warnings(accounts) and "冲突" in warnings(accounts)


def test_mixed_inputs_keep_same_email_spaces_and_wrapper_metadata(tmp_path):
    sub = {"exported_at": "2026-01-01T00:00:00Z", "proxies": [{"proxy_key": "keep"}], "custom": 42,
           "accounts": [{"name": "fixture@example.com", "platform": "openai", "type": "oauth",
                         "credentials": {"email": "fixture@example.com", "access_token": "opaque", "chatgpt_account_id": "team-space"}}]}
    kind, accounts = parse([sub, cpa(), web(), nine()])
    assert kind == "mixed" and len(accounts) == 4
    output = f.build_export_payload(accounts)
    assert output["proxies"] == sub["proxies"] and output["custom"] == 42
    assert output["accounts"][0] == sub["accounts"][0]
    files = f.write_cpa_files(tmp_path, accounts)
    assert len(files) == len(set(files)) == 4
    assert json.loads(files[0].read_text())["account_id"] == "team-space"


def test_mixed_bom_and_consecutive_documents():
    kind, accounts = parse_conversion_text("\ufeff" + json.dumps(web()) + "\n" + json.dumps(cpa()))
    assert kind == "mixed" and len(accounts) == 2


def test_bad_pasted_record_is_not_silently_ignored():
    with pytest.raises(ValueError, match=r"\[2\]"):
        parse([web(), {"invalid": True}])


def test_batch_files_keep_valid_files_and_report_failed_positions(tmp_path):
    for name, payload in [("1.json", web()), ("2.json", cpa())]:
        (tmp_path / name).write_text(json.dumps(payload), encoding="utf-8-sig")
    (tmp_path / "3.json").write_text("{broken fixture-secret", encoding="utf-8")
    files = sorted(tmp_path.iterdir()) + [tmp_path / "missing.json"]
    loaded = load_conversion_files(files)
    assert loaded.kind == "mixed" and loaded.accepted_files == 2
    assert len(loaded.accounts) == 2 and [item[0] for item in loaded.failures] == [3, 4]
    assert "fixture-secret" not in str(loaded.failures)
    assert len(parse_conversion_text(loaded.text)[1]) == 2


@pytest.mark.parametrize("record", [nine(provider="anthropic"), web(platform="anthropic"), {"sessionToken": "session-only"}])
def test_wrong_provider_and_session_only_are_not_credentials(record):
    with pytest.raises(ValueError):
        parse(record)


def test_legacy_login_parser_does_not_gain_session_or_mixed_inputs():
    for item in [web(), nine(), [cpa(), web()]]:
        with pytest.raises(ValueError):
            f.parse_accounts_from_text(json.dumps(item))


def test_ambiguous_token_aliases_reject_instead_of_mixing_credentials():
    with pytest.raises(ValueError, match="access_token.*冲突"):
        parse(web(access_token="different-token"))


def test_identity_alias_conflicts_are_kept_and_reported():
    _, accounts = parse(web(email="other@example.com"))
    assert accounts[0]["credentials"]["email"] == "fixture@example.com"
    assert accounts[0]["extra"][f.CONVERSION_META_KEY]["unmapped"]["email"] == "other@example.com"
    assert "email" in warnings(accounts) and "冲突" in warnings(accounts)


def test_naive_time_not_guessed_and_refresh_not_set_to_conversion_time(monkeypatch):
    monkeypatch.setattr(f.time, "time", lambda: 1800000000)
    _, accounts = parse(nine(accessToken="opaque", expiresAt="2030-01-01T00:00:00", lastRefresh="2026-01-01T00:00:00"))
    payload = f.build_cpa_payload(accounts[0])
    assert payload["expired"] == payload["last_refresh"] == ""
    assert "缺少时区" in warnings(accounts)


def test_no_refresh_claim_when_only_session_token_exists_in_unmapped():
    _, accounts = parse(web(accessToken="opaque"))
    assert f.account_conversion_status(accounts[0])["refresh"] == "缺少刷新令牌"


def test_refresh_only_nine_router_warns_and_keeps_token():
    _, accounts = parse(nine(accessToken=""))
    assert f.build_cpa_payload(accounts[0])["refresh_token"] == "fixture-refresh"
    assert "缺少 access_token" in warnings(accounts)
