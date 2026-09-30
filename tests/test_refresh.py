"""Offline refresh rotation, failure decisions and pool integration contracts."""
import copy
import json
import sys
import threading
from pathlib import Path
from urllib.parse import parse_qs
from unittest.mock import Mock

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from account_inputs import account_input_from_mapping
from oauth_refresh import RefreshError, refresh_account, recover_refresh_account, run_refresh_first
from pool_flow import parse_push_text, run_pool_push
from openai_reauth import ReauthResult, CLIENT_ID
from local_secrets import unprotect_secret
from test_pool import account, settings, AdminBackend
from test_conversion import access, cpa, AUTH
from test_conversion import jwt


def transport(data, status=200, calls=None):
    def handler(request):
        if calls is not None:
            calls.append(request)
        return httpx.Response(status, json=data)
    return httpx.MockTransport(handler)


def save_refresh_record(folder, source, phase, **fields):
    import hashlib
    from local_secrets import protect_secret
    creds = source["credentials"]
    digest = hashlib.sha256(((creds.get("client_id") or CLIENT_ID) + "\0" + creds["refresh_token"]).encode()).hexdigest()
    path = folder / "token-refresh" / (digest + ".dpapi.json")
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps({"version": 1, "encrypted": protect_secret(json.dumps({
        "phase": phase, "source": source, **fields}))}), encoding="utf-8")
    return path


def test_refresh_rotation_preserves_settings_and_uses_original_client(tmp_path):
    source = account(client_id="app-fixture", id_token="original-id", model_mapping={"m": "m"})
    source.update(proxy_id=42, load_factor=9, priority=8)
    original = copy.deepcopy(source)
    calls = []
    updated = refresh_account(source, transport=transport({"access_token": access(), "refresh_token": "rotated-secret", "expires_in": 3600}, calls=calls), recovery_dir=tmp_path)
    assert source == original
    assert updated["credentials"]["refresh_token"] == "rotated-secret"
    assert updated["credentials"]["id_token"] == "original-id"
    assert updated["proxy_id"] == 42 and updated["load_factor"] == 9 and updated["priority"] == 8
    assert updated["credentials"]["model_mapping"] == {"m": "m"}
    form = parse_qs(calls[0].content.decode())
    assert form["client_id"] == ["app-fixture"] and form["grant_type"] == ["refresh_token"]
    assert len(calls) == 1 and calls[0].url == "https://auth.openai.com/oauth/token"
    disk = next(tmp_path.glob("token-refresh/*.json")).read_text(encoding="utf-8")
    assert all(secret not in disk for secret in ("rotated-secret", "fixture-refresh", "fixture-access"))
    saved = json.loads(unprotect_secret(json.loads(disk)["encrypted"]))
    assert saved["phase"] == "validated" and saved["account"]["credentials"]["refresh_token"] == "rotated-secret"
    source["credentials"]["model_mapping"] = {"new": "new"}
    cached = refresh_account(source, transport=transport({}, 500, calls), recovery_dir=tmp_path)
    assert len(calls) == 1 and cached["credentials"]["model_mapping"] == {"new": "new"}


def test_refresh_omitted_rotating_fields_keep_existing_values():
    source = account(id_token="original-id")
    updated = refresh_account(source, transport=transport({"access_token": access()}))
    assert updated["credentials"]["refresh_token"] == "fixture-refresh"
    assert updated["credentials"]["id_token"] == "original-id"


@pytest.mark.parametrize("status,data,category", [
    (400, {"error": "invalid_grant", "error_description": "never-show-secret"}, "refresh_failed"),
    (429, {"error": "too_many_requests", "message": "never-show-secret"}, "refresh_unknown"),
    (503, {"error": "never-show-secret"}, "refresh_unknown"),
    (302, {}, "refresh_unknown"),
    (200, {}, "refresh_unknown"),
    (200, {"access_token": "opaque-secret", "expires_in": 3600}, "refresh_unknown"),
    (200, {"access_token": access(exp=1)}, "refresh_unknown"),
    (200, {"access_token": access(), "refresh_token": None}, "refresh_unknown"),
    (200, {"access_token": access(**{AUTH: {"chatgpt_account_id": "different"}})}, "refresh_unknown"),
])
def test_failure_classification_never_retries_or_exposes_response(status, data, category):
    calls = []
    with pytest.raises(RefreshError) as caught:
        refresh_account(account(), transport=transport(data, status, calls))
    assert caught.value.category == category and len(calls) == 1
    assert all(secret not in str(caught.value) for secret in ("never-show-secret", "opaque-secret", "fixture-refresh"))


def test_network_ambiguity_blocks_replay_after_restart(tmp_path):
    calls = []
    def handler(request):
        calls.append(request)
        raise httpx.ReadTimeout("fixture-sensitive-detail")
    for _ in range(2):
        with pytest.raises(RefreshError) as caught:
            refresh_account(account(), transport=httpx.MockTransport(handler), recovery_dir=tmp_path)
        assert caught.value.category == "refresh_unknown"
        assert "fixture-sensitive-detail" not in str(caught.value)
    assert len(calls) == 1


def test_encryption_failure_prevents_token_request(tmp_path, monkeypatch):
    monkeypatch.setattr("oauth_refresh.protect_secret", lambda value: "")
    calls = []
    with pytest.raises(RefreshError) as caught:
        refresh_account(account(), transport=transport({}, calls=calls), recovery_dir=tmp_path)
    assert caught.value.category == "storage" and not calls


def test_unknown_rotation_response_still_saved_encrypted(tmp_path):
    with pytest.raises(RefreshError):
        refresh_account(account(), transport=transport({"access_token": "opaque", "refresh_token": "rotation-secret"}), recovery_dir=tmp_path)
    outer = json.loads(next(tmp_path.glob("token-refresh/*.json")).read_text(encoding="utf-8"))
    assert "rotation-secret" not in str(outer)
    saved = json.loads(unprotect_secret(outer["encrypted"]))
    assert saved["phase"] == "received" and saved["response"]["refresh_token"] == "rotation-secret"


def test_received_response_recovers_account_without_replaying_refresh(tmp_path, monkeypatch):
    source = account(id_token=jwt({"email": "fixture@example.com", AUTH: {"user_id": "user-fixture", "organization_id": "org-fixture"}}),
                     organization_id="org-fixture")
    source["credentials"]["access_token"] = jwt({"exp": 1893456000, AUTH: {"user_id": "user-fixture", "poid": "org-fixture"},
                                                   "https://api.openai.com/profile": {"email": "fixture@example.com"}})
    response = {"access_token": source["credentials"]["access_token"],
                "id_token": source["credentials"]["id_token"], "refresh_token": "rotated-secret"}
    network = Mock(side_effect=AssertionError("offline recovery must not create an HTTP client"))
    monkeypatch.setattr("oauth_refresh.httpx.Client", network)
    from local_secrets import protect_secret
    import hashlib
    digest = hashlib.sha256((CLIENT_ID + "\0fixture-refresh").encode()).hexdigest()
    path = tmp_path / "token-refresh" / (digest + ".dpapi.json")
    path.parent.mkdir()
    path.write_text(json.dumps({"version": 1, "encrypted": protect_secret(json.dumps({"phase": "received", "source": source,
                                                                                      "response": response}))}), encoding="utf-8")
    updated = recover_refresh_account(source, recovery_dir=tmp_path)
    assert updated["credentials"]["refresh_token"] == "rotated-secret"
    assert updated["credentials"]["chatgpt_account_id"] == "space-fixture"
    network.assert_not_called()
    saved = json.loads(unprotect_secret(json.loads(path.read_text(encoding="utf-8"))["encrypted"]))
    assert saved["phase"] == "validated"


def test_received_response_with_changed_organization_stays_blocked(tmp_path):
    source = account(id_token=jwt({"email": "fixture@example.com", AUTH: {"user_id": "user-fixture", "organization_id": "org-fixture"}}),
                     organization_id="org-fixture")
    response = {"access_token": jwt({"exp": 1893456000, AUTH: {"user_id": "user-fixture", "poid": "another-org"},
                                     "https://api.openai.com/profile": {"email": "fixture@example.com"}}),
                "refresh_token": "rotated-secret"}
    from local_secrets import protect_secret
    import hashlib
    digest = hashlib.sha256((CLIENT_ID + "\0fixture-refresh").encode()).hexdigest()
    path = tmp_path / "token-refresh" / (digest + ".dpapi.json")
    path.parent.mkdir()
    path.write_text(json.dumps({"version": 1, "encrypted": protect_secret(json.dumps({"phase": "received", "source": source,
                                                                                      "response": response}))}), encoding="utf-8")
    with pytest.raises(RefreshError, match="无法确认账号及工作空间"):
        recover_refresh_account(source, recovery_dir=tmp_path)
    assert json.loads(unprotect_secret(json.loads(path.read_text(encoding="utf-8"))["encrypted"]))["phase"] == "received"


@pytest.mark.parametrize("response", [None, [], "invalid", {"refresh_token": "rotated-secret"}])
def test_invalid_saved_response_never_replays_refresh(tmp_path, monkeypatch, response):
    source = account(expires_at=1893456000)
    path = save_refresh_record(tmp_path, source, "received", response=response)
    network = Mock(side_effect=AssertionError("saved response must not be replayed"))
    monkeypatch.setattr("oauth_refresh.httpx.Client", network)
    with pytest.raises(RefreshError) as caught:
        recover_refresh_account(source, recovery_dir=tmp_path)
    assert caught.value.category == "refresh_unknown"
    network.assert_not_called()
    assert json.loads(unprotect_secret(json.loads(path.read_text())["encrypted"]))["phase"] == "received"


@pytest.mark.parametrize("age", [60, 121])
def test_saved_duration_uses_receipt_time_and_cannot_gain_a_new_lifetime(tmp_path, monkeypatch, age):
    received_at = 1800000000
    monkeypatch.setattr("oauth_refresh.time.time", lambda: received_at + age)
    source = account()
    token = jwt({"email": "fixture@example.com", AUTH: {"chatgpt_account_id": "space-fixture", "user_id": "user-fixture"}})
    save_refresh_record(tmp_path, source, "received", received_at=received_at,
                        response={"access_token": token, "expires_in": 120, "refresh_token": "rotated-secret"})
    network = Mock(side_effect=AssertionError("saved response must not be replayed"))
    monkeypatch.setattr("oauth_refresh.httpx.Client", network)
    if age < 120:
        recovered = recover_refresh_account(source, recovery_dir=tmp_path)
        assert recovered["credentials"]["expires_at"] == received_at + 120
    else:
        with pytest.raises(RefreshError, match="已经过期"):
            recover_refresh_account(source, recovery_dir=tmp_path)
    network.assert_not_called()


def test_legacy_response_without_receipt_time_or_jwt_expiry_stays_unknown(tmp_path, monkeypatch):
    source = account()
    token = jwt({"email": "fixture@example.com", AUTH: {"chatgpt_account_id": "space-fixture", "user_id": "user-fixture"}})
    save_refresh_record(tmp_path, source, "received", response={"access_token": token, "expires_in": 3600})
    network = Mock(side_effect=AssertionError("legacy response must not be replayed"))
    monkeypatch.setattr("oauth_refresh.httpx.Client", network)
    with pytest.raises(RefreshError, match="缺少有效到期时间"):
        recover_refresh_account(source, recovery_dir=tmp_path)
    network.assert_not_called()


def test_authorization_recovers_confirmed_rotation_before_unknown_state_gate(tmp_path):
    item = account_input_from_mapping(cpa())
    item.refresh_state = "refresh_unknown"
    save_refresh_record(tmp_path, item.oauth_account, "received",
                        response={"access_token": access(), "refresh_token": "rotated-secret"})
    authorize, refresh = Mock(), Mock(side_effect=AssertionError("recovery must not rotate again"))
    results = run_refresh_first([item], authorize=authorize, refresh=refresh, recovery_dir=tmp_path)
    assert results[0].ok and item.refresh_state == "refreshed"
    assert results[0].account["credentials"]["refresh_token"] == "rotated-secret"
    authorize.assert_not_called()
    refresh.assert_not_called()


@pytest.mark.parametrize("phase", ["pending", "rejected"])
def test_fresh_input_cannot_bypass_an_unconfirmed_or_rejected_rotation(tmp_path, phase):
    source = account(expires_at=1893456000)
    save_refresh_record(tmp_path, source, phase)
    jobs = parse_push_text(json.dumps(source))
    backend, refresh, authorize = AdminBackend(), Mock(), Mock()
    run_pool_push(jobs, settings(), stop=threading.Event(), on_progress=lambda _: None,
                  client_factory=backend.client, refresh=refresh, authorize=authorize, recovery_dir=tmp_path)
    assert jobs[0].state == ("refresh_failed" if phase == "rejected" else "refresh_unknown")
    assert not backend.records
    refresh.assert_not_called()
    authorize.assert_not_called()


def test_explicit_relogin_can_resolve_a_persisted_rejected_refresh(tmp_path):
    source = account(expires_at=1893456000)
    source["extra"] = {"password": "fixture-password"}
    save_refresh_record(tmp_path, source, "rejected")
    jobs = parse_push_text(json.dumps(source))
    backend = AdminBackend()
    def login(inputs, **kwargs):
        assert kwargs["skip_phone_verification"]
        kwargs["on_progress"](1, 1, ReauthResult(inputs[0].email, True, account=account(refresh_token="new-login")))
    run_pool_push(jobs, settings(), stop=threading.Event(), on_progress=lambda _: None,
                  client_factory=backend.client, authorize=login, recovery_dir=tmp_path, relogin_ids=(jobs[0].uid,))
    assert jobs[0].state == "created"
    assert backend.records[jobs[0].account_id]["credentials"]["refresh_token"] == "new-login"


def test_authorization_json_refreshes_first_and_never_automatically_logs_in():
    item = account_input_from_mapping(cpa())
    assert item.oauth_account and item.password == ""
    authorize = Mock()
    refresh = Mock(side_effect=RefreshError("refresh_unknown", "等待核对"))
    for _ in range(2):
        results = run_refresh_first([item], authorize=authorize, refresh=refresh)
        assert results[0].category == "refresh_unknown"
    authorize.assert_not_called()
    refresh.assert_called_once()


def test_authorization_refresh_success_emits_result_without_browser():
    item = account_input_from_mapping(cpa())
    authorize, progress = Mock(), Mock()
    result = run_refresh_first([item], authorize=authorize, refresh=lambda value, **_: value, on_progress=progress)
    assert result[0].ok and progress.call_args.args[:2] == (1, 1)
    authorize.assert_not_called()


def test_pool_failure_waits_for_explicit_relogin_and_preserves_identity():
    source = account()
    source["extra"] = {"password": "fixture-password"}
    jobs = parse_push_text(json.dumps(source))
    backend = AdminBackend()
    refresh = Mock(side_effect=RefreshError("refresh_failed", "刷新被拒绝"))
    authorize = Mock()
    opts = dict(stop=threading.Event(), on_progress=lambda _: None, client_factory=backend.client,
                refresh=refresh, authorize=authorize)
    run_pool_push(jobs, settings(), **opts)
    assert jobs[0].state == "refresh_failed" and not backend.records
    run_pool_push(jobs, settings(), **opts)
    refresh.assert_called_once()
    authorize.assert_not_called()
    def login(inputs, **kwargs):
        assert kwargs["skip_phone_verification"]
        kwargs["on_progress"](1, 1, ReauthResult(inputs[0].email, True, account=account(refresh_token="new-login")))
    opts["authorize"] = login
    run_pool_push(jobs, settings(proxy_id=42, load_factor=13), relogin_ids=(jobs[0].uid,), **opts)
    assert jobs[0].state == "created"
    assert backend.records[jobs[0].account_id]["proxy_id"] == 42
    assert backend.records[jobs[0].account_id]["load_factor"] == 13


def test_pool_refresh_rotation_precedes_backend_write(tmp_path):
    jobs = parse_push_text(json.dumps(account()))
    backend = AdminBackend()
    def refresh(source, **kwargs):
        assert not backend.records
        return refresh_account(source, transport=transport({"access_token": access(), "refresh_token": "fresh-rotation"}), **kwargs)
    run_pool_push(jobs, settings(), stop=threading.Event(), on_progress=lambda _: None, client_factory=backend.client,
                  refresh=refresh, recovery_dir=tmp_path)
    assert jobs[0].state == "created" and jobs[0].refresh_state == "refreshed"
    assert backend.records[jobs[0].account_id]["credentials"]["refresh_token"] == "fresh-rotation"


def test_pool_push_uses_fresh_input_without_rotating_token(tmp_path):
    source = account(expires_at=1893456000)
    jobs = parse_push_text(json.dumps(source))
    backend = AdminBackend()
    refresh = Mock(side_effect=AssertionError("fresh token must not refresh"))
    run_pool_push(jobs, settings(), stop=threading.Event(), on_progress=lambda _: None,
                  client_factory=backend.client, refresh=refresh, recovery_dir=tmp_path)
    refresh.assert_not_called()
    assert jobs[0].state == "created"
    assert backend.records[jobs[0].account_id]["credentials"]["refresh_token"] == "fixture-refresh"


def test_pool_push_recovers_received_response_before_upload(tmp_path):
    source = account(id_token=jwt({"email": "fixture@example.com", AUTH: {"user_id": "user-fixture", "organization_id": "org-fixture"}}),
                     organization_id="org-fixture", expires_at=1893456000)
    source["credentials"]["access_token"] = jwt({"exp": 1893456000, AUTH: {"user_id": "user-fixture", "poid": "org-fixture"},
                                                   "https://api.openai.com/profile": {"email": "fixture@example.com"}})
    from local_secrets import protect_secret
    import hashlib
    digest = hashlib.sha256((CLIENT_ID + "\0fixture-refresh").encode()).hexdigest()
    path = tmp_path / "token-refresh" / (digest + ".dpapi.json")
    path.parent.mkdir()
    path.write_text(json.dumps({"version": 1, "encrypted": protect_secret(json.dumps({"phase": "received", "source": source,
        "response": {"access_token": source["credentials"]["access_token"], "id_token": source["credentials"]["id_token"],
                     "refresh_token": "rotated-secret"}}))}), encoding="utf-8")
    jobs = parse_push_text(json.dumps(source))
    backend = AdminBackend()
    refresh = Mock(side_effect=AssertionError("received response must not be submitted again"))
    run_pool_push(jobs, settings(), stop=threading.Event(), on_progress=lambda _: None,
                  client_factory=backend.client, refresh=refresh, recovery_dir=tmp_path)
    refresh.assert_not_called()
    assert jobs[0].state == "created"
    assert backend.records[jobs[0].account_id]["credentials"]["refresh_token"] == "rotated-secret"


@pytest.mark.parametrize("rotate", [True, False])
def test_expired_cache_uses_latest_confirmed_refresh_token(tmp_path, monkeypatch, rotate):
    instant = [1800000000]
    monkeypatch.setattr("oauth_refresh.time.time", lambda: instant[0])
    calls = []
    source = account()
    token = "rotated-fixture" if rotate else "fixture-refresh"
    response = {"access_token": access(), "refresh_token": token, "expires_in": 1}
    refresh_account(source, transport=transport(response, calls=calls), recovery_dir=tmp_path)
    instant[0] += 2
    refresh_account(source, transport=transport(response, calls=calls), recovery_dir=tmp_path)
    assert len(calls) == 2
    assert parse_qs(calls[1].content.decode())["refresh_token"] == [token]


def test_other_instance_cannot_submit_same_refresh_token(tmp_path):
    import subprocess
    from oauth_refresh import _refresh_lease
    lock = tmp_path / "refresh.lock"
    code = ("import sys\nfrom oauth_refresh import _refresh_lease, RefreshError\nfrom pathlib import Path\n"
            "try:\n    with _refresh_lease(Path(sys.argv[1])): sys.exit(3)\n"
            "except RefreshError as error: sys.exit(0 if error.category == 'refresh_busy' else 4)\n")
    with _refresh_lease(lock):
        child = subprocess.run([sys.executable, "-c", code, str(lock)], capture_output=True, timeout=10)
        assert child.returncode == 0
    with _refresh_lease(lock):
        pass  # Process exit/close releases the lease without deleting the lock file.


def test_stopped_refresh_does_not_make_request(tmp_path):
    calls = []
    with pytest.raises(RefreshError) as caught:
        refresh_account(account(), should_stop=lambda: True, transport=transport({}, calls=calls), recovery_dir=tmp_path)
    assert caught.value.category == "cancelled" and not calls


@pytest.mark.parametrize("different", ["workspace", "user"])
def test_explicit_relogin_cannot_upload_another_identity(different):
    jobs = parse_push_text(json.dumps(account()))
    jobs[0].refresh_state = "refresh_unknown"
    backend = AdminBackend()
    replacement = account(space="another-space") if different == "workspace" else account(user="another-user")
    def login(inputs, **kwargs):
        kwargs["on_progress"](1, 1, ReauthResult(inputs[0].email, True, account=replacement))
    run_pool_push(jobs, settings(), stop=threading.Event(), on_progress=lambda _: None,
                  client_factory=backend.client, authorize=login, relogin_ids=(jobs[0].uid,))
    assert jobs[0].state == "identity" and not backend.records
    assert jobs[0].account["credentials"]["chatgpt_account_id"] == "space-fixture"


def test_relogin_keeps_imported_models_and_scheduling():
    source = {**account(model_mapping={"model-fixture": "model-fixture"}), "priority": 7, "concurrency": 2}
    jobs = parse_push_text(json.dumps(source))
    jobs[0].refresh_state = "refresh_failed"
    backend = AdminBackend()
    def login(inputs, **kwargs):
        kwargs["on_progress"](1, 1, ReauthResult(inputs[0].email, True, account=account(refresh_token="new-login")))
    run_pool_push(jobs, settings(scheduling_mode="preserve"), stop=threading.Event(), on_progress=lambda _: None,
                  client_factory=backend.client, authorize=login, relogin_ids=(jobs[0].uid,))
    actual = backend.records[jobs[0].account_id]
    assert actual["credentials"]["model_mapping"] == source["credentials"]["model_mapping"]
    assert actual["priority"] == 7 and actual["concurrency"] == 2


def test_interrupted_refresh_restores_without_permission_to_relogin(tmp_path):
    from pool_recovery import PoolJournal
    jobs = parse_push_text(json.dumps(account()))
    jobs[0].refresh_state = "refreshing"
    journal = PoolJournal.create(tmp_path)
    journal.save(settings(), jobs)
    _, restored = journal.load()
    assert restored[0].refresh_state == "refresh_unknown"
    backend, login, refresh = AdminBackend(), Mock(), Mock()
    run_pool_push(restored, settings(), stop=threading.Event(), on_progress=lambda _: None,
                  client_factory=backend.client, authorize=login, refresh=refresh)
    login.assert_not_called()
    refresh.assert_not_called()
    assert not backend.records


def test_phone_parser_retains_original_login_behavior():
    from phone_flow import parse_phone_jobs
    # An unrecognized stale token payload must not prevent reading phone login data.
    source = {"name": "fixture@example.com", "extra": {"password": "fixture-password", "refresh_token": "unused"}}
    parsed = parse_phone_jobs(json.dumps(source))[0]
    assert parsed.password == "fixture-password" and parsed.oauth_account is None


def test_new_id_token_replaces_synthetic_marker_including_cache(tmp_path):
    from reauth_formats import CPA_META_KEY, _synthetic_marker
    source = account(id_token="old-synthetic")
    source["extra"] = {CPA_META_KEY: {"unmapped": {"id_token_synthetic": True, "custom": "retain"}}}
    data = {"access_token": access(), "id_token": "new-provider-id", "refresh_token": "new-rotation"}
    fresh = refresh_account(source, transport=transport(data), recovery_dir=tmp_path)
    cached = refresh_account(source, transport=transport({}, 500), recovery_dir=tmp_path)
    for row in (fresh, cached):
        assert not _synthetic_marker(row)
        assert row["extra"][CPA_META_KEY]["unmapped"]["custom"] == "retain"
        assert row["credentials"]["id_token"] == "new-provider-id"
