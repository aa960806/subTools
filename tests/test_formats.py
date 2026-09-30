import json
import base64
import sys
from pathlib import Path

import pytest


TOOL = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL))
import reauth_formats as formats  # noqa: E402


def account(**overrides):
    value = {
        "name": "user@example.com",
        "platform": "openai",
        "type": "oauth",
        "credentials": {
            "access_token": "access-dummy",
            "refresh_token": "refresh-dummy",
            "id_token": "id-dummy",
            "email": "user@example.com",
            "chatgpt_account_id": "acct-dummy",
            "expires_at": 1_800_000_000,
            "model_mapping": {"gpt-5*": "gpt-5"},
        },
        "extra": {"email": "user@example.com", "privacy_mode": "enabled"},
        "concurrency": 100,
        "priority": 2,
        "rate_multiplier": 1,
        "auto_pause_on_expired": True,
    }
    value.update(overrides)
    return value


def test_wrapper_preserved_and_importer_shape():
    source = {
        "exported_at": "2026-09-17T00:00:00.000Z",
        "proxies": [],
        "accounts": [account()],
    }
    loaded = formats.accounts_from_sub2_data(source)
    assert isinstance(loaded, formats.Accounts)
    assert loaded.wrappers[0]["exported_at"] == source["exported_at"]
    output = formats.build_export_payload(loaded)
    assert output["type"] == "sub2api-data"
    assert output["proxies"] == []
    assert output["accounts"][0]["credentials"]["model_mapping"] == {"gpt-5*": "gpt-5"}


def test_cpa_is_exact_nine_fields_and_warns_about_loss():
    loaded = formats.Accounts([account()])
    payload = formats.build_cpa_payload(loaded[0])
    assert tuple(payload) == formats.CPA_FIELDS
    warnings = formats.conversion_warnings(loaded, "cpa")
    assert any("丢失" in item for item in warnings)
    assert any("model_mapping" in item for item in warnings)


def test_cpa_round_trip_preserves_metadata_without_claiming_disabled_support():
    payload = {
        "type": "codex",
        "email": "user@example.com",
        "expired": "2026-09-25T10:02:18.123+08:00",
        "id_token": "id-dummy",
        "account_id": "acct-dummy",
        "disabled": True,
        "access_token": "access-dummy",
        "last_refresh": "2026-09-17T10:02:18.456+08:00",
        "refresh_token": "refresh-dummy",
    }
    loaded = formats.accounts_from_cpa_data(payload)
    converted = loaded[0]
    assert isinstance(converted["credentials"]["expires_at"], int)
    assert formats.build_cpa_payload(converted) == payload
    assert any("手动停用" in warning for warning in formats.conversion_warnings(loaded, "sub2"))


def test_cpa_type_and_time_validation():
    payload = {
        "type": "codex", "email": "u@example.com", "expired": "2026-09-25T10:02:18.123+08:00",
        "id_token": "", "account_id": "", "disabled": False, "access_token": "a",
        "last_refresh": "2026-09-17T10:02:18.456+08:00", "refresh_token": "r",
    }
    assert formats.parse_datetime_to_unix(payload["expired"]) == formats.parse_datetime_to_unix("2026-09-25T02:02:18.123Z")
    with pytest.raises(ValueError):
        formats.cpa_to_sub2_account({**payload, "disabled": "false"})
    loaded = formats.accounts_from_cpa_data({**payload, "expired": "2026-09-25T10:02:18"})
    assert "expires_at" not in loaded[0]["credentials"]
    assert any("缺少时区" in warning for warning in loaded.warnings)


def test_bom_duplicate_json_and_safe_filename(tmp_path):
    with pytest.raises(ValueError):
        formats.parse_json_documents('{"a": 1, "a": 2}')
    assert formats.parse_json_documents("\ufeff{}") == [{}]
    assert formats.safe_email_filename("CON") != "CON"
    first = tmp_path / "user@example.com.json"
    first.write_text("{}", encoding="utf-8")
    written = formats.write_cpa_files(tmp_path, [account()])
    assert written[0].name != first.name
    assert written[0].exists()


@pytest.mark.parametrize("invalid", [True, False, float("inf"), float("nan"), "2026-09-17T12:00:00", "nonsense", -1])
def test_invalid_expiry_not_invented(invalid):
    assert formats.parse_datetime_to_unix(invalid) is None
    value = account()
    value["credentials"]["expires_at"] = invalid
    assert formats.build_cpa_payload(value)["expired"] == ""
    assert formats.build_cpa_payload(value)["last_refresh"] == ""


def test_seconds_milliseconds_equivalent():
    assert formats.parse_datetime_to_unix(1800000000000) == 1800000000
    assert formats.parse_datetime_to_unix("1800000000000") == 1800000000
    assert formats.parse_datetime_to_unix("1800000000") == 1800000000


def test_multiple_wrappers_keep_proxy_definitions():
    proxy = {"proxy_key": "sample-proxy", "name": "sample", "protocol": "http", "host": "127.0.0.1", "port": 8080}
    first = {"accounts": [account(proxy_key="sample-proxy")], "proxies": [proxy], "exported_at": "2026-09-17T00:00:00Z"}
    second = {"accounts": [account()], "proxies": [], "exported_at": "2026-09-18T00:00:00Z"}
    _, loaded = formats.parse_accounts_from_text(json.dumps(first) + "\n" + json.dumps(second))
    output = formats.build_export_payload(loaded)
    assert len(output["accounts"]) == 2
    assert output["proxies"] == [proxy]
    second["proxies"] = [{**proxy, "port": 8081}]
    _, conflicting = formats.parse_accounts_from_text(json.dumps(first) + "\n" + json.dumps(second))
    with pytest.raises(ValueError, match="proxy_key"):
        formats.build_export_payload(conflicting)


@pytest.mark.parametrize("changes", [{"platform": "anthropic"}, {"type": "apikey"}])
def test_reject_mixed_platform_wrapper(changes):
    with pytest.raises(ValueError):
        formats.accounts_from_sub2_data({"accounts": [account(), account(**changes)], "proxies": []})


def test_directory_reports_invalid_file_without_identifiers(tmp_path):
    (tmp_path / "0-secret-email@example.com.json").write_text('{broken', encoding="utf-8")
    (tmp_path / "1-good.json").write_text(json.dumps(formats.build_cpa_payload(account())), encoding="utf-8-sig")
    loaded = formats.load_cpa_accounts(tmp_path)
    assert len(loaded) == 1
    assert any("已跳过" in warning for warning in loaded.warnings)
    assert not any("secret-email" in warning for warning in loaded.warnings)


def test_duplicate_case_insensitive_names_never_overwrite(tmp_path):
    first = account()
    second = account()
    second["credentials"]["email"] = "USER@example.com"
    written = formats.write_cpa_files(tmp_path, [first, second, first])
    assert len({path.name.casefold() for path in written}) == 3
    original = written[0].read_bytes()
    another = formats.write_cpa_files(tmp_path, [first])
    assert another[0] not in written
    assert written[0].read_bytes() == original
    assert len(list(tmp_path.iterdir())) == 4  # No hidden backup or sidecar.


def test_export_failure_does_not_damage_existing_file(tmp_path, monkeypatch):
    output = tmp_path / "out.json"
    output.write_text("existing", encoding="utf-8")
    def fail_replace(*_args):
        raise OSError("simulated publication failure")
    monkeypatch.setattr(formats.os, "replace", fail_replace)
    with pytest.raises(OSError):
        formats.write_export_file(output, [account()])
    assert output.read_text(encoding="utf-8") == "existing"
    assert [path.name for path in tmp_path.iterdir()] == ["out.json"]


def test_unknown_cpa_fields_remain_in_sub2_metadata_and_warn_on_cpa_export():
    cpa = formats.build_cpa_payload(account())
    cpa["unrecognized_setting"] = {"mode": "test"}
    loaded = formats.accounts_from_cpa_data(cpa)
    output = formats.build_export_payload(loaded)
    assert output["accounts"][0]["extra"][formats.CPA_META_KEY]["unmapped"] == {"unrecognized_setting": {"mode": "test"}}
    assert tuple(formats.build_cpa_payload(loaded[0])) == formats.CPA_FIELDS
    assert any("非标准扩展字段" in warning for warning in formats.conversion_warnings(loaded, "cpa"))


def test_new_token_time_only_recorded_when_issued(monkeypatch):
    monkeypatch.setattr(formats.time, "time", lambda: 1800000000)
    claims = {"email": "u@example.com", "https://api.openai.com/auth": {"chatgpt_account_id": "acct-dummy"}}
    id_token = "header." + base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=") + ".sig"
    token = {"access_token": "access-dummy", "refresh_token": "refresh-dummy", "id_token": id_token, "expires_in": 3600}
    fresh = formats.build_account_payload(token, "U@example.com")
    assert fresh["credentials"]["expires_at"] == 1800003600
    assert formats.parse_datetime_to_unix(formats.build_cpa_payload(fresh)["last_refresh"]) == 1800000000
    with pytest.raises(ValueError, match="expires_in"):
        formats.build_account_payload({**token, "expires_in": None}, "u@example.com")
    with pytest.raises(ValueError, match="不一致"):
        formats.build_account_payload(token, "another@example.com")
    with pytest.raises(ValueError, match="refresh_token"):
        formats.build_account_payload({**token, "refresh_token": ""}, "u@example.com")
    with pytest.raises(ValueError, match="邮箱"):
        formats.build_account_payload({**token, "id_token": "opaque"}, "u@example.com")


def jwt(payload):
    return "header." + base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=") + ".sig"


def test_missing_refresh_uses_only_access_issued_at_with_warning(monkeypatch):
    value = account()
    value["credentials"]["access_token"] = jwt({"iat": 1800000000})
    value["credentials"]["id_token"] = jwt({"iat": 1700000000})
    monkeypatch.setattr(formats.time, "time", lambda: 1900000000)
    cpa = formats.build_cpa_payload(value)
    assert cpa["last_refresh"].endswith("+08:00")
    assert formats.parse_datetime_to_unix(cpa["last_refresh"]) == 1800000000
    assert any("按 access_token 的签发时间 iat 推算" in warning for warning in formats.conversion_warnings([value], "cpa"))
    value["credentials"]["access_token"] = "opaque-access"
    assert formats.build_cpa_payload(value)["last_refresh"] == ""
    assert any("last_refresh" in warning and "空字符串" in warning for warning in formats.conversion_warnings([value], "cpa"))


def test_recorded_refresh_wins_over_access_issued_at():
    value = account()
    value["credentials"]["access_token"] = jwt({"iat": 1800000000})
    value["extra"][formats.CPA_META_KEY] = {"last_refresh": "2026-09-17T10:02:18.456+08:00"}
    assert formats.build_cpa_payload(value)["last_refresh"] == "2026-09-17T10:02:18.456+08:00"
    assert not any("iat 推算" in warning for warning in formats.conversion_warnings([value], "cpa"))
