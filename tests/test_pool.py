"""Sub2 admin contract fixtures and push regressions; no external services."""

import copy
import json
import sys
import threading
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from openai_reauth import ReauthResult
from pool_client import PoolClient, PoolError, PoolSettings, normalize_site
from pool_flow import PendingWrite, PushJob, find_existing, load_push_files, parse_push_text, prepare_account, push_one, run_pool_push as _run_pool_push
from pool_recovery import PoolJournal
from test_conversion import access, cpa, jwt, nine, web, AUTH


def run_pool_push(*args, **kwargs):
    # These fixtures exercise backend writes; token transport is tested separately.
    kwargs.setdefault("refresh", lambda account, **_: copy.deepcopy(account))
    return _run_pool_push(*args, **kwargs)


def settings(**changes):
    return PoolSettings(**{"site": "https://sub2.test", "auth_kind": "api_key", "credential": "fixture-admin-key",
                            "group_ids": (7, 8), "priority": 12, "concurrency": 4, **changes})


def account(email="fixture@example.com", space="space-fixture", user="user-fixture", **creds):
    return {"name": email, "platform": "openai", "type": "oauth", "credentials": {
        "email": email, "chatgpt_account_id": space, "chatgpt_user_id": user,
        "access_token": "fixture-access", "refresh_token": "fixture-refresh", **creds}}


class AdminBackend:
    """Mirrors current DTO redaction and sensitive-key-preserving PUT semantics."""
    def __init__(self, records=()):
        self.records = {a["id"]: copy.deepcopy(a) for a in records}
        self.requests = []
        self.replays = {}
        self.lost_responses = 0
        self.fail_status = None
        self.group_records = [{"id": i, "name": f"group-{i}", "platform": "openai", "status": "active"} for i in (7, 8)]
        self.proxy_records = [{"id": 42, "name": "fixture-proxy", "status": "active"}]

    @staticmethod
    def dto(record):
        result = copy.deepcopy(record)
        creds = result.get("credentials", {})
        status = {}
        for key in ("access_token", "refresh_token", "id_token"):
            if creds.pop(key, None):
                status["has_" + key] = True
        result["credentials_status"] = status
        return result

    def __call__(self, request):
        body = json.loads(request.content) if request.content and request.content != b"null" else None
        self.requests.append((request.method, request.url.path, body, dict(request.headers)))
        if self.fail_status:
            return httpx.Response(self.fail_status, json={"message": "fixture-admin-key fixture-access should not be logged"})
        path = request.url.path.removeprefix("/api/v1/admin")
        if path == "/groups/all":
            return httpx.Response(200, json={"code": 0, "data": self.group_records})
        if path == "/proxies/all":
            return httpx.Response(200, json={"code": 0, "data": self.proxy_records})
        if request.method == "GET" and path == "/accounts":
            # Deliberately clamp the page size: client must follow total, not requested size.
            page = int(request.url.params["page"])
            items = list(self.records.values())[page-1:page]
            return httpx.Response(200, json={"code": 0, "data": {"items": [self.dto(a) for a in items], "total": len(self.records)}})
        if request.method == "GET":
            item = self.records.get(int(path.split("/")[-1]))
            return httpx.Response(200, json={"code": 0, "data": self.dto(item)}) if item else httpx.Response(404)
        key = request.headers.get("Idempotency-Key")
        if request.method == "POST":
            if key in self.replays:
                result = self.replays[key]
            else:
                result = {**body, "id": max(self.records, default=0) + 1, "status": "active"}
                self.records[result["id"]] = result
                self.replays[key] = result
        else:
            old = self.records[int(path.split("/")[-1])]
            creds = copy.deepcopy(body["credentials"])
            for name in ("access_token", "refresh_token", "id_token"):
                if name not in creds and name in old["credentials"]:
                    creds[name] = old["credentials"][name]
            result = {**old, **body, "credentials": creds}
            self.records[result["id"]] = result
        if self.lost_responses:
            self.lost_responses -= 1
            raise httpx.ReadTimeout("lost after commit", request=request)
        return httpx.Response(200, json={"code": 0, "data": self.dto(result)})

    def client(self, config=None, stop=None):
        return PoolClient(config or settings(), stop, transport=httpx.MockTransport(self))


@pytest.mark.parametrize("value,expected", [
    ("https://SUB2.test/", "https://sub2.test"),
    ("https://sub2.test/api/v1/admin/", "https://sub2.test"),
    ("http://localhost:8080/prefix/api/v1", "http://localhost:8080/prefix"),
    ("https://[::1]:443/", "https://[::1]"),
])
def test_site_normalization(value, expected):
    assert normalize_site(value) == expected


@pytest.mark.parametrize("value", ["", "sub2.test", "file:///C:/secret", "https://a:b@sub2.test", "https://sub2.test/?key=secret", "https://sub2.test/#token", "https://sub2.test/../admin", "https://sub2.test/%2e%2e", "https://sub2.test:bad"])
def test_invalid_or_credential_bearing_addresses_rejected(value):
    with pytest.raises(ValueError):
        normalize_site(value)


@pytest.mark.parametrize("auth_kind,header,expected", [("api_key", "x-api-key", "fixture-admin-key"), ("bearer", "authorization", "Bearer fixture-admin-key")])
def test_admin_header_and_group_filter(auth_kind, header, expected):
    backend = AdminBackend()
    backend.group_records += [{"id": 9, "name": "closed", "platform": "openai", "status": "inactive"},
                              {"id": 10, "name": "other", "platform": "anthropic", "status": "active"}]
    with backend.client(settings(auth_kind=auth_kind)) as client:
        assert [g["id"] for g in client.groups()] == [7, 8]
    headers = backend.requests[0][3]
    assert headers[header] == expected
    assert ("authorization" if header == "x-api-key" else "x-api-key") not in headers


def test_redirect_is_not_followed_and_key_is_not_forwarded():
    requests = []
    def handler(req):
        requests.append(req)
        return httpx.Response(302, headers={"Location": "https://other.test/collect"})
    with PoolClient(settings(), transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(PoolError, match="重定向"):
            client.groups()
    assert len(requests) == 1 and requests[0].url.host == "sub2.test"


@pytest.mark.parametrize("status,category", [(401, "auth"), (403, "auth"), (429, "rate_limited"), (404, "failed"), (500, "server")])
def test_errors_are_categorized_and_do_not_echo_response_secrets(status, category):
    backend = AdminBackend()
    backend.fail_status = status
    with backend.client() as client:
        with pytest.raises(PoolError) as error:
            client.groups()
    assert error.value.category == category
    assert "fixture-admin-key" not in str(error.value)
    assert "fixture-access" not in str(error.value)


def test_paginated_inventory_does_not_stop_at_server_page_cap():
    backend = AdminBackend([{**account(email=f"u{i}@example.com", user=f"u{i}"), "id": i} for i in (1, 2, 3)])
    with backend.client() as client:
        assert len(client.accounts()) == 3
    assert len(backend.requests) == 3


def test_malformed_inventory_prevents_any_write():
    def handler(req):
        return httpx.Response(200, json={"code": 0, "data": {"items": [], "total": 5}})
    with PoolClient(settings(), transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(PoolError, match="分页不完整"):
            client.accounts()


def test_mixed_lines_json_arrays_and_totp():
    raw = "u@example.com----password-fixture\n" + json.dumps([web(), cpa(), nine()])
    raw += "\ntotp\\@example.com----password-fixture----JBSWY3DPEHPK3PXP"
    jobs = parse_push_text(raw)
    assert len(jobs) == 5
    assert jobs[0].login.totp_secret == "" and jobs[0].account is None
    assert jobs[-1].login.email == "totp@example.com"
    assert jobs[-1].login.totp_secret == "JBSWY3DPEHPK3PXP"
    assert all(job.account for job in jobs[1:4])
    assert "password-fixture" not in repr(jobs)


def test_invalid_paste_cannot_drop_bad_records():
    with pytest.raises(ValueError, match="第 2 行"):
        parse_push_text("u@example.com----password-fixture\ninvalid-secret-fixture")


def test_file_import_skips_bad_files_and_masks_error_content(tmp_path):
    (tmp_path / "1.json").write_text(json.dumps(web()), encoding="utf-8-sig")
    (tmp_path / "2.txt").write_text("u@example.com----password-fixture", encoding="utf-8")
    (tmp_path / "3.txt").write_text("password-secret-fixture", encoding="utf-8")
    text, report = load_push_files(sorted(tmp_path.iterdir()))
    assert len(parse_push_text(text)) == 2
    assert report[2][2] == 0 and "password-secret-fixture" not in report[2][3]


def test_identity_keeps_same_email_workspaces_and_same_team_members_separate():
    incoming = account()
    other_space = {**account(space="other-space"), "id": 1}
    other_member = {**account(email="member@example.com", user="other-user"), "id": 2}
    assert find_existing(incoming, [other_space, other_member]) is None
    actual = {**account(), "id": 3}
    assert find_existing(incoming, [other_space, other_member, actual])["id"] == 3


def test_ambiguous_duplicate_and_legacy_missing_identity_block_updates():
    with pytest.raises(PoolError, match="多条"):
        find_existing(account(), [{**account(), "id": 1}, {**account(), "id": 2}])
    with pytest.raises(PoolError, match="缺少空间"):
        find_existing(account(), [{**account(space=""), "id": 1}])
    with pytest.raises(PoolError, match="不完整"):
        find_existing(account(user=""), [{**account(email="", user="server-only-user"), "id": 1}])


def test_create_uses_selected_groups_priority_concurrency_and_never_sends_password():
    source = account(password="password-secret", totp_secret="totp-secret", session_token="session-secret")
    source["extra"] = {"password": "extra-secret", "openai_reauth_conversion": {"unmapped": web()}}
    backend = AdminBackend()
    job = PushJob("fixture@example.com", account=source)
    with backend.client() as client:
        push_one(client, settings(), job, [])
    saved = backend.records[job.account_id]
    assert job.state == "created"
    assert saved["group_ids"] == [7, 8] and saved["priority"] == 12 and saved["concurrency"] == 4
    text = json.dumps([row[2] for row in backend.requests])
    assert not any(secret in text for secret in ("password-secret", "totp-secret", "session-secret", "extra-secret"))


def test_backend_proxy_and_load_factor_are_written_and_verified():
    backend = AdminBackend()
    job = PushJob("fixture@example.com", account=account())
    config = settings(proxy_id=42, load_factor=0)
    run_pool_push([job], config, stop=threading.Event(), on_progress=lambda _: None, client_factory=backend.client)
    saved = backend.records[job.account_id]
    assert job.state == "created"
    assert saved["proxy_id"] == 42 and saved["load_factor"] == 0
    body = next(row[2] for row in backend.requests if row[0] == "POST")
    assert body["proxy_id"] == 42 and body["load_factor"] == 0


def test_stale_backend_proxy_blocks_batch_before_any_account_write():
    backend = AdminBackend()
    job = PushJob("fixture@example.com", account=account())
    with pytest.raises(PoolError, match="代理已失效"):
        run_pool_push([job], settings(proxy_id=999), stop=threading.Event(), on_progress=lambda _: None,
                      client_factory=backend.client)
    assert not any(row[0] in ("POST", "PUT") for row in backend.requests)


def test_encrypted_journal_is_checkpointed_before_the_first_write(tmp_path):
    backend = AdminBackend()
    saved_before_writes = []

    class Journal:
        path = tmp_path / "queue.dpapi.json"

        def save(self, _settings, _jobs):
            saved_before_writes.append(not any(row[0] in ("POST", "PUT") for row in backend.requests))

    run_pool_push([PushJob("fixture@example.com", account=account())], settings(), stop=threading.Event(),
                  on_progress=lambda _: None, client_factory=backend.client, journal=Journal())
    assert saved_before_writes and saved_before_writes[0]


def test_recovered_post_with_existing_identity_becomes_put_and_keeps_configuration(tmp_path):
    backend = AdminBackend()
    config = settings(proxy_id=42, load_factor=17, model_whitelist=("gpt-5",))
    journal = PoolJournal(tmp_path / "queue.dpapi.json", protect=lambda value: "dpapi:" + value,
                          unprotect=lambda value: value[6:])
    original = PushJob("fixture@example.com", account=account())
    backend.lost_responses = 2
    with pytest.raises(PoolError):
        run_pool_push([original], config, stop=threading.Event(), on_progress=lambda _: None,
                      client_factory=backend.client, journal=journal)
    assert original.pending is not None and len(backend.records) == 1
    post_count_before_recovery = len([row for row in backend.requests if row[0] == "POST"])

    _saved, restored_jobs = journal.load()
    restored = restored_jobs[0]
    assert restored.pending is not None and restored.pending.needs_reconcile
    with backend.client(config) as client:
        push_one(client, config, restored, client.accounts())

    assert restored.state == "updated" and restored.pending is None
    assert len([row for row in backend.requests if row[0] == "POST"]) == post_count_before_recovery
    put = next(row[2] for row in backend.requests if row[0] == "PUT")
    assert put["group_ids"] == [7, 8]
    assert put["priority"] == 12 and put["concurrency"] == 4
    assert put["proxy_id"] == 42 and put["load_factor"] == 17
    assert put["credentials"]["model_mapping"] == {"gpt-5": "gpt-5"}


def test_recovery_read_error_stays_uncertain_and_preserves_pending_request():
    backend = AdminBackend()
    config = settings()
    body = {**account(), "group_ids": [7, 8], "priority": 12, "concurrency": 4}
    pending = PendingWrite(config.destination_id(), "PUT", "/accounts/1", body, "fixture-key", needs_reconcile=True)
    job = PushJob("fixture@example.com", account=account(), pending=pending)
    backend.records[1] = {**account(), "id": 1, "group_ids": [7, 8], "priority": 12, "concurrency": 4}
    backend.fail_status = 401
    with backend.client(config) as client:
        with pytest.raises(PoolError) as error:
            push_one(client, config, job, [copy.deepcopy(backend.records[1])])
    assert error.value.uncertain and job.pending is pending and job.pending.needs_reconcile


def test_session_update_preserves_existing_refresh_extra_status_and_model_mapping():
    old = {**account(refresh_token="old-refresh", model_mapping={"a": "b"}), "id": 9,
           "group_ids": [99], "priority": 99, "concurrency": 1, "extra": {"keep": True}, "status": "disabled"}
    backend = AdminBackend([old])
    job = PushJob("fixture@example.com", account=account(access_token="new-access", refresh_token=""))
    with backend.client() as client:
        records = client.accounts()
        push_one(client, settings(), job, records)
    assert job.state == "updated" and job.account_id == 9
    saved = backend.records[9]
    assert saved["credentials"]["refresh_token"] == "old-refresh"
    assert saved["credentials"]["access_token"] == "new-access"
    assert saved["credentials"]["model_mapping"] == {"a": "b"}
    assert saved["extra"] == {"keep": True} and saved["status"] == "disabled"
    assert saved["group_ids"] == [7, 8]
    assert "refresh_token" not in next(row[2]["credentials"] for row in backend.requests if row[0] == "PUT")
    assert "保留后台已有刷新令牌" in job.message


def test_new_full_oauth_replaces_real_refresh_token():
    backend = AdminBackend([{**account(refresh_token="old-refresh"), "id": 1, "group_ids": [7], "priority": 5, "concurrency": 1}])
    job = PushJob("fixture@example.com", account=account(refresh_token="rotated-refresh"))
    with backend.client() as client:
        push_one(client, settings(), job, client.accounts())
    assert backend.records[1]["credentials"]["refresh_token"] == "rotated-refresh"


def test_expired_access_only_and_identity_conflicts_are_not_pushed():
    with pytest.raises(PoolError, match="已过期"):
        prepare_account(account(refresh_token="", expires_at=100))
    with pytest.raises(PoolError, match="冲突"):
        prepare_account(account(access_token=access(**{AUTH: {"chatgpt_account_id": "different"}})))


def test_synthetic_id_is_omitted_on_push_not_saved_as_real_id():
    placeholder = jwt({AUTH: {"chatgpt_account_id": "wrong-space"}}, synthetic=True)
    prepared = prepare_account(account(id_token=placeholder))
    assert "id_token" not in prepared["credentials"]


def test_timeout_after_commit_reuses_key_and_body_and_does_not_create_twice():
    backend = AdminBackend()
    backend.lost_responses = 2
    job = PushJob("fixture@example.com", account=account())
    with backend.client() as client:
        with pytest.raises(PoolError) as error:
            push_one(client, settings(), job, [])
        assert error.value.uncertain and job.pending is not None
        original_key = job.pending.key
        push_one(client, settings(), job, client.accounts())
    posts = [row for row in backend.requests if row[0] == "POST"]
    assert len(backend.records) == 1 and job.state == "created" and job.pending is None
    assert len(posts) == 3
    assert all(row[3]["idempotency-key"] == original_key and row[2] == posts[0][2] for row in posts)


def test_unknown_write_cannot_be_retried_to_changed_site_or_groups():
    backend = AdminBackend()
    backend.lost_responses = 2
    job = PushJob("fixture@example.com", account=account())
    with backend.client() as client:
        with pytest.raises(PoolError):
            push_one(client, settings(), job, [])
        count = len(backend.requests)
        with pytest.raises(PoolError, match="原站点"):
            push_one(client, settings(group_ids=(8,)), job, [])
        assert len(backend.requests) == count


def test_same_batch_duplicates_update_the_first_created_record():
    backend = AdminBackend()
    jobs = [PushJob("fixture@example.com", account=account()), PushJob("fixture@example.com", account=account(access_token="second-access"))]
    run_pool_push(jobs, settings(), stop=threading.Event(), on_progress=lambda _: None, client_factory=backend.client)
    assert [job.state for job in jobs] == ["created", "updated"]
    assert len(backend.records) == 1


def test_preflight_bad_groups_cannot_start_login_or_write():
    backend = AdminBackend()
    backend.group_records = []
    jobs = parse_push_text("u@example.com----password-fixture")
    def authorize(*_, **__):
        pytest.fail("preflight must precede login")
    with pytest.raises(PoolError, match="分组"):
        run_pool_push(jobs, settings(), stop=threading.Event(), on_progress=lambda _: None, client_factory=backend.client, authorize=authorize)
    assert jobs[0].state == "not_processed"
    assert not backend.records


def test_phone_required_is_skipped_and_next_oauth_account_is_pushed(tmp_path):
    backend = AdminBackend()
    jobs = parse_push_text("phone@example.com----password-fixture\nfixture@example.com----password-fixture")
    def authorize(inputs, **kwargs):
        assert kwargs["skip_phone_verification"] is True
        assert "phone_handler" not in kwargs
        kwargs["on_progress"](1, 2, ReauthResult(inputs[0].email, False, category="phone_required", error="phone"))
        kwargs["on_progress"](2, 2, ReauthResult(inputs[1].email, True, account=account(), category="success"))
    run_pool_push(jobs, settings(), stop=threading.Event(), on_progress=lambda _: None, client_factory=backend.client,
                  authorize=authorize, recovery_dir=tmp_path)
    assert [job.state for job in jobs] == ["phone_required", "created"]
    reports = list(tmp_path.glob("pool-*/report.json"))
    assert len(reports) == 1
    text = reports[0].read_text(encoding="utf-8")
    assert all(secret not in text for secret in ("password-fixture", "fixture-access", "fixture-admin-key"))


def test_pre_cancelled_batch_does_not_touch_backend():
    backend = AdminBackend()
    stop = threading.Event()
    stop.set()
    job = PushJob("fixture@example.com", account=account())
    with pytest.raises(PoolError):
        run_pool_push([job], settings(), stop=stop, on_progress=lambda _: None, client_factory=backend.client)
    assert not backend.requests and job.state == "not_processed"


def test_fatal_http_auth_stops_batch_and_keeps_remaining_unprocessed():
    backend = AdminBackend()
    backend.fail_status = 401
    jobs = [PushJob("fixture@example.com", account=account()), PushJob("second@example.com", account=account(email="second@example.com"))]
    with pytest.raises(PoolError):
        run_pool_push(jobs, settings(), stop=threading.Event(), on_progress=lambda _: None, client_factory=backend.client)
    assert all(job.state == "not_processed" for job in jobs)
    assert len(backend.requests) == 1


def test_oauth_success_is_retained_for_push_retry_without_logging_in_again():
    backend = AdminBackend()
    jobs = parse_push_text("fixture@example.com----password-fixture")
    calls = []
    def authorize(inputs, **kwargs):
        calls.append(True)
        backend.lost_responses = 2
        kwargs["on_progress"](1, 1, ReauthResult(inputs[0].email, True, account=account(), category="success"))
    with pytest.raises(PoolError):
        run_pool_push(jobs, settings(), stop=threading.Event(), on_progress=lambda _: None, client_factory=backend.client, authorize=authorize)
    assert jobs[0].account is not None and jobs[0].state == "uncertain"
    run_pool_push(jobs, settings(), stop=threading.Event(), on_progress=lambda _: None, client_factory=backend.client, authorize=authorize)
    assert calls == [True] and jobs[0].state == "created" and len(backend.records) == 1


@pytest.mark.parametrize("bad_groups", [True, "7,8", {"7": True}, [{"id": 7}], [True, 8]])
def test_invalid_write_response_never_counts_as_success(bad_groups):
    backend = AdminBackend()
    def handler(req):
        response = backend(req)
        if req.method == "POST":
            data = response.json()
            data["data"]["group_ids"] = bad_groups
            return httpx.Response(200, json=data)
        return response
    job = PushJob("fixture@example.com", account=account())
    with PoolClient(settings(), transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(PoolError) as error:
            push_one(client, settings(), job, [])
    assert error.value.uncertain and job.pending and job.state != "created"


def test_readback_failure_after_write_keeps_exact_pending_request():
    backend = AdminBackend()
    def handler(req):
        if req.method == "GET":
            return httpx.Response(403)
        response = backend(req)
        return httpx.Response(200, json={"code": 0, "data": {"id": response.json()["data"]["id"]}})
    job = PushJob("fixture@example.com", account=account())
    with PoolClient(settings(), transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(PoolError) as error:
            push_one(client, settings(), job, [])
    assert error.value.uncertain and job.pending and len(backend.records) == 1


def test_first_write_timeout_then_auth_error_cannot_erase_uncertainty():
    backend = AdminBackend()
    backend.lost_responses = 1
    def handler(req):
        if backend.requests:
            return httpx.Response(401)
        return backend(req)
    job = PushJob("fixture@example.com", account=account())
    with PoolClient(settings(), transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(PoolError) as error:
            push_one(client, settings(), job, [])
        assert error.value.uncertain and job.pending and len(backend.records) == 1
        key = job.pending.key
        with pytest.raises(PoolError) as error:
            push_one(client, settings(), job, [])
        assert error.value.uncertain and job.pending.key == key


def test_stopping_after_lost_write_keeps_request_for_reconciliation():
    stop = threading.Event()
    backend = AdminBackend()
    def handler(req):
        backend(req)
        stop.set()
        raise httpx.ReadTimeout("lost after commit", request=req)
    job = PushJob("fixture@example.com", account=account())
    with PoolClient(settings(), stop, transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(PoolError) as error:
            push_one(client, settings(), job, [])
    assert error.value.uncertain and job.pending and len(backend.requests) == 1


def test_inventory_without_credentials_cannot_create_duplicates():
    def handler(req):
        item = {"id": 1, "name": "fixture@example.com", "platform": "openai", "type": "oauth"}
        return httpx.Response(200, json={"code": 0, "data": {"items": [item], "total": 1}})
    with PoolClient(settings(), transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(PoolError, match="身份"):
            client.accounts()
