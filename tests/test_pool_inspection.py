"""Only GET requests and sanitized inventory snapshots, never account repair."""
import json
import threading
from unittest.mock import patch

import httpx
import pytest

from pool_inspection import ReadOnlyPoolClient, inspect_pool
from pool_flow import PushJob, push_one
from test_pool import AdminBackend, account, settings


def reader(backend):
    return lambda config, stop: ReadOnlyPoolClient(config, stop, transport=httpx.MockTransport(backend))


def test_inspection_is_paginated_read_only_and_omits_all_secrets():
    old = {**account(), "id": 1, "status": "error", "schedulable": False, "group_ids": [7], "proxy_id": 999,
           "name": "fixture@example.com----private-password----private-totp", "error_message": "private-api-key",
           "temp_unschedulable_reason": "private-token", "rate_limit_reset_at": "2030-01-01T00:00:00Z"}
    old["credentials"]["expires_at"] = 100
    backend = AdminBackend([old, {**account(), "id": 2, "status": "active", "group_ids": [7]}])
    report = inspect_pool(settings(), threading.Event(), client_factory=reader(backend), now=1000)
    assert report["total"] == 2 and report["attention"] == 2 and report["read_only"]
    issues = report["accounts"][0]["issues"]
    assert set(("后台标记异常", "调度已关闭", "限流冷却", "access token 已过期", "代理失效或停用", "同身份重复账号")) <= set(issues)
    assert all(row[0] == "GET" for row in backend.requests)
    assert len([row for row in backend.requests if row[1].endswith("/accounts")]) == 2
    serialized = json.dumps(report)
    assert all(secret not in serialized for secret in ("private-", "fixture-access", "fixture-refresh", "fixture-admin-key"))


def test_inspection_supports_group_filter_and_does_not_infer_missing_refresh_as_absent():
    backend = AdminBackend([{**account(), "id": 1, "group_ids": [7], "status": "active"},
                            {"id": 2, "platform": "openai", "type": "oauth", "group_ids": [8], "status": "active"}])
    report = inspect_pool(settings(), threading.Event(), group_ids=(8,), client_factory=reader(backend))
    assert [row["id"] for row in report["accounts"]] == [2]
    assert report["accounts"][0]["has_refresh_token"] is None
    assert "身份字段不完整" in report["accounts"][0]["issues"]


def test_explicit_absent_refresh_and_missing_expiry_are_reported():
    backend = AdminBackend([{**account(refresh_token=""), "id": 1, "status": "disabled"}])
    def handle(req):
        response = backend(req)
        if req.url.path.endswith("/accounts"):
            value = response.json()
            value["data"]["items"][0]["credentials_status"]["has_refresh_token"] = False
            return httpx.Response(200, json=value)
        return response
    report = inspect_pool(settings(), threading.Event(), client_factory=lambda config, stop:
                          ReadOnlyPoolClient(config, stop, transport=httpx.MockTransport(handle)))
    assert set(("缺少刷新令牌", "已禁用", "凭据到期时间未知", "未绑定分组")) <= set(report["accounts"][0]["issues"])


@pytest.mark.parametrize("method,path", [("POST", "/accounts"), ("PUT", "/accounts/1"), ("DELETE", "/accounts/1"),
                                        ("POST", "/accounts/1/models/sync-upstream"), ("GET", "/accounts/1/refresh")])
def test_read_only_client_cannot_access_writes_or_probe_endpoints(method, path):
    backend = AdminBackend()
    with reader(backend)(settings(), threading.Event()) as client:
        with pytest.raises(ValueError, match="巡检仅允许"):
            client.request(method, path)
    assert not backend.requests


def test_cancelled_inspection_does_not_request_backend():
    backend, stop = AdminBackend(), threading.Event()
    stop.set()
    with pytest.raises(Exception, match="已停止"):
        inspect_pool(settings(), stop, client_factory=reader(backend))
    assert not backend.requests


@pytest.mark.parametrize("other_user,expected", [("", "同身份重复账号"), ("different", "同邮箱同空间用户 ID 冲突")])
def test_inspection_uses_same_workspace_and_email_fallback_as_upload(other_user, expected):
    backend = AdminBackend([{**account(), "id": 1}, {**account(user=other_user), "id": 2}])
    report = inspect_pool(settings(), threading.Event(), client_factory=reader(backend))
    assert all(expected in row["issues"] for row in report["accounts"])


def test_credential_email_does_not_export_login_password_suffix():
    backend = AdminBackend([{**account(email="fixture@example.com----private-password"), "id": 1}])
    report = inspect_pool(settings(), threading.Event(), client_factory=reader(backend))
    assert report["accounts"][0]["email"] == "fixture@example.com"
    assert "private-password" not in json.dumps(report)


@pytest.mark.parametrize("proxy_id,load_factor", [(None, None), (0, 0), (42, 18)])
def test_identity_update_preserves_or_overrides_proxy_and_load(proxy_id, load_factor):
    old = {**account(), "id": 8, "group_ids": [7], "priority": 20, "concurrency": 2, "proxy_id": 42, "load_factor": 12}
    backend = AdminBackend([old])
    config = settings(proxy_id=proxy_id, load_factor=load_factor, scheduling_mode="preserve")
    job = PushJob("fixture@example.com", account=account())
    with backend.client(config) as client:
        push_one(client, config, job, client.accounts())
    assert len(backend.records) == 1 and job.account_id == 8
    assert backend.records[8]["proxy_id"] == (42 if proxy_id is None else proxy_id)
    assert backend.records[8]["load_factor"] == (12 if load_factor is None else load_factor)
    assert backend.records[8]["priority"] == 20 and backend.records[8]["concurrency"] == 2


@pytest.mark.parametrize("field", ["proxy_id", "load_factor"])
def test_backend_dropping_selected_configuration_keeps_result_uncertain(field):
    from pool_client import PoolClient, PoolError
    backend = AdminBackend()
    def handle(req):
        response = backend(req)
        data = response.json()
        if req.method == "POST":
            data["data"][field] = 999
        return httpx.Response(200, json=data)
    config = settings(proxy_id=42, load_factor=12)
    job = PushJob("fixture@example.com", account=account())
    with PoolClient(config, transport=httpx.MockTransport(handle)) as client:
        with pytest.raises(PoolError) as caught:
            push_one(client, config, job, [])
    assert caught.value.uncertain and job.pending is not None
