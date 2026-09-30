"""Batch preparation and account upsert for the standalone pool-push page."""

from __future__ import annotations

import copy
import json
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from openai_reauth import AccountInput, run_batch_reauth
from account_inputs import account_input_from_mapping, input_records, parse_account_line, login_description
from pool_client import PoolClient, PoolError, PoolSettings, write_key
from oauth_refresh import RefreshError, refresh_account, recover_refresh_account, clear_synthetic_marker, credentials_fresh
from reauth_conversion import parse_conversion_text
from reauth_formats import (
    _atomic_write_json, _conversion_identity, _conversion_user_info, _is_synthetic_token,
    _object_without_duplicates, _reject_constant, _string, _synthetic_marker,
    decode_jwt, parse_datetime_to_unix,
)


@dataclass
class PendingWrite:
    destination: tuple
    method: str
    path: str
    body: dict = field(repr=False)
    key: str = field(repr=False)
    needs_reconcile: bool = False


@dataclass
class PushJob:
    email: str
    account: dict | None = field(default=None, repr=False)
    login: AccountInput | None = field(default=None, repr=False)
    uid: str = field(default_factory=lambda: uuid.uuid4().hex)
    state: str = "ready"
    message: str = "等待推送"
    account_id: int | None = None
    completed_destination: tuple | None = None
    pending: PendingWrite | None = field(default=None, repr=False)
    refresh_state: str = ""


def _login_line(line, index):
    return parse_account_line(line, index)


def parse_push_text(text: str) -> list[PushJob]:
    jobs = []
    for line, value in input_records(text):
        try:
            if isinstance(value, dict):
                # A login-only JSON is useful too; never reinterpret invalid tokens as passwords.
                has_token = any(value.get(key) for key in ("access_token", "accessToken", "refresh_token", "refreshToken"))
                nested = [value.get(key) for key in ("credentials", "providerSpecificData")]
                has_token = has_token or any(isinstance(item, dict) and any(item.get(key) for key in
                    ("access_token", "accessToken", "refresh_token", "refreshToken")) for item in nested)
                if has_token or "sessionToken" in value or "session_token" in value:
                    _, accounts = parse_conversion_text(json.dumps(value, ensure_ascii=False, allow_nan=False))
                    for account in accounts:
                        info = _conversion_identity(account)
                        message = "已有 OAuth 凭据，先刷新后推送"
                        if not _string(account["credentials"].get("refresh_token")):
                            message = "已有 access token，等待推送；缺少刷新令牌，到期需重新获取"
                        try:
                            login = account_input_from_mapping(value, line)
                        except ValueError:
                            login = None
                        jobs.append(PushJob(info["email"] or _string(account.get("name")), account=account, login=login, message=message))
                    continue
                login = account_input_from_mapping(value, line)
            else:
                login = parse_account_line(value, line)
            jobs.append(PushJob(login.email, login=login, message=login_description(login)))
        except ValueError as exc:
            raise ValueError(f"第 {line} 行附近：{exc}") from None
    if not jobs:
        raise ValueError("请输入账号密码或账号 JSON")
    return jobs


def load_push_files(paths):
    chunks, report = [], []
    for index, path in enumerate(paths, 1):
        try:
            content = Path(path).read_text(encoding="utf-8-sig")
            jobs = parse_push_text(content)
        except (OSError, UnicodeError, ValueError) as exc:
            reason = str(exc) if isinstance(exc, ValueError) and not isinstance(exc, UnicodeError) else "无法读取 UTF-8 文件"
            report.append((index, Path(path).name, 0, reason))
            continue
        chunks.append(content.strip())
        report.append((index, Path(path).name, len(jobs), ""))
    return "\n\n".join(chunks), report


def identity_of(account):
    creds = account.get("credentials")
    if not isinstance(creds, dict):
        return ("", "", "")
    info = _conversion_identity(account)
    return (info["chatgpt_account_id"], info["chatgpt_user_id"], info["email"].casefold())


def find_existing(incoming, records):
    space, user, email = identity_of(incoming)
    if not space or not (user or email):
        raise PoolError("缺少工作空间或用户标识，无法安全判断重复账号；请补齐凭据后推送", category="identity")
    matches = []
    for record in records:
        if record.get("platform") != "openai" or record.get("type") != "oauth" or record.get("parent_account_id"):
            continue
        other_space, other_user, other_email = identity_of(record)
        same_user = user and other_user and user == other_user
        same_email = email and other_email and email == other_email
        if not other_space and (same_user or same_email):
            raise PoolError("后台存在同用户但缺少空间标识的账号，请先补齐或处理后重试", category="identity")
        if other_space != space:
            continue
        if user and other_user:
            if user == other_user:
                matches.append(record)
            elif same_email:
                raise PoolError("同邮箱同空间的用户 ID 冲突，请核对后台账号", category="identity")
        elif same_email:
            matches.append(record)
        elif not email or not other_email:
            raise PoolError("同一空间的用户信息不完整，无法确定是否重复", category="identity")
    if len(matches) > 1:
        raise PoolError("后台存在多条相同身份的账号，请先合并或清理重复项", category="identity")
    return matches[0] if matches else None


OAUTH_FIELDS = ("access_token", "refresh_token", "id_token", "client_id", "email", "chatgpt_account_id",
                "chatgpt_user_id", "plan_type", "organization_id", "expires_at", "model_mapping")


def prepare_account(account):
    original = account.get("credentials") or {}
    info = _conversion_identity(account)
    # Identity conflicts require resolution before they can select a remote account.
    access = _string(original.get("access_token"))
    identity_token = _string(original.get("id_token"))
    synthetic = _is_synthetic_token(identity_token, _synthetic_marker(account))
    sources = [_conversion_user_info("", access)]
    if not synthetic:
        sources.append(_conversion_user_info(identity_token, ""))
    for key in ("email", "chatgpt_account_id", "chatgpt_user_id"):
        values = [info.get(key)] + [source.get(key) for source in sources]
        values = [str(v).casefold() if key == "email" else v for v in values if v]
        if len(set(values)) > 1:
            raise PoolError(f"{key} 与 token 声明冲突，请先在转换页核对来源", category="identity")
    creds = {key: copy.deepcopy(original[key]) for key in OAUTH_FIELDS if original.get(key) not in (None, "")}
    creds.update({key: value for key, value in info.items() if value})
    if synthetic:
        creds.pop("id_token", None)
    if not (creds.get("access_token") or creds.get("refresh_token")):
        raise PoolError("缺少可推送的 OAuth 凭据")
    if not creds.get("refresh_token"):
        expiries = [parse_datetime_to_unix(original.get("expires_at")), parse_datetime_to_unix(decode_jwt(access).get("exp"))]
        if any(value is not None and value <= time.time() for value in expiries):
            raise PoolError("access_token 已过期且缺少 refresh_token，请先重新授权", category="expired")
    expiry = parse_datetime_to_unix(original.get("expires_at"))
    if expiry is None:
        expiry = parse_datetime_to_unix(decode_jwt(access).get("exp"))
    if expiry is not None:
        creds["expires_at"] = expiry
    else:
        creds.pop("expires_at", None)
    prepared = {"name": _string(account.get("name")) or info["email"], "platform": "openai", "type": "oauth", "credentials": creds}
    find_existing(prepared, [])  # Require a safe deduplication identity before any write.
    return prepared


def _is_passthrough(account):
    extra = account.get("extra") or {}
    if not isinstance(extra, dict):
        return False
    enabled = extra.get("openai_passthrough")
    if type(enabled) is bool:
        return enabled
    return extra.get("openai_oauth_passthrough") is True


def push_one(client: PoolClient, settings: PoolSettings, job: PushJob, records, *, checkpoint=None):
    resuming = job.pending is not None
    if job.pending:
        try:
            if job.pending.destination != settings.destination_id():
                raise PoolError("上次写入结果未确认，请保持原站点、分组和配置后重试核对", category="pending", uncertain=True)
            request = job.pending
            if request.needs_reconcile:
                # After restart the backend's idempotency cache may have expired.
                # Resolve identity before replaying a create; never create a second copy.
                existing = find_existing(request.body, records)
                if request.method == "PUT":
                    target = client.get_account(int(request.path.rsplit("/", 1)[1]))
                    if not find_existing(request.body, [target]):
                        raise PoolError("待恢复的后台账号身份已变化，请人工核对", category="identity", uncertain=True)
                elif existing:
                    target = client.get_account(existing["id"])
                    if not find_existing(request.body, [target]):
                        raise PoolError("待恢复的后台账号身份已变化，请人工核对", category="identity", uncertain=True)
                    body = copy.deepcopy(request.body)
                    body.pop("platform", None)
                    path = f"/accounts/{target['id']}"
                    request = PendingWrite(settings.destination_id(), "PUT", path, body,
                                           write_key(settings.site, "PUT", path, body))
                    job.pending = request
                request.needs_reconcile = False
        except PoolError as exc:
            # A recovery read cannot prove that the prior write failed. Keep
            # the exact request encrypted for a later, explicit reconciliation.
            exc.uncertain = True
            raise
    else:
        prepared = prepare_account(job.account)
        existing = find_existing(prepared, records)
        method, path = "POST", "/accounts"
        body = copy.deepcopy(prepared)
        if existing:
            latest = client.get_account(existing["id"])
            match = find_existing(prepared, [latest])
            if not match:
                raise PoolError("后台账号身份已变化，已停止更新，请重新读取", category="identity")
            if settings.model_whitelist and _is_passthrough(latest):
                raise PoolError("该账号已启用自动透传，白名单不会生效；请先在后台关闭自动透传再推送", category="models")
            method, path = "PUT", f"/accounts/{latest['id']}"
            # The admin DTO omits secrets. Preserve non-secret settings while
            # leaving absent tokens omitted for server-side sensitive-key merge.
            prior = {key: value for key, value in (latest.get("credentials") or {}).items()
                     if key not in ("access_token", "refresh_token", "id_token", "password", "cookie", "session_key",
                                    "totp_secret", "two_factor_secret", "mailbox_url", "sessionToken", "session_token")}
            body["credentials"] = {**prior, **body["credentials"]}
            body.pop("platform")
        if settings.model_whitelist is not None:
            body["credentials"]["model_mapping"] = {name: name for name in settings.model_whitelist}
        body["group_ids"] = list(settings.group_ids)
        if settings.scheduling_mode == "override" or not existing:
            for name in ("priority", "concurrency"):
                value = job.account.get(name, getattr(settings, name)) if settings.scheduling_mode == "preserve" else getattr(settings, name)
                if type(value) is not int or value < 0:
                    raise PoolError("输入账号的优先级或并发数无效", category="config")
                body[name] = value
        if settings.proxy_id is not None:
            # Backend uses 0 to clear an existing proxy; omit it for new direct accounts.
            if existing or settings.proxy_id:
                body["proxy_id"] = settings.proxy_id
        if settings.load_factor is not None:
            body["load_factor"] = settings.load_factor
        elif not existing and settings.scheduling_mode == "preserve" and job.account.get("load_factor") is not None:
            value = job.account["load_factor"]
            if type(value) is not int or not 0 <= value <= 10000:
                raise PoolError("输入账号的负载系数无效", category="config")
            body["load_factor"] = value
        request = PendingWrite(settings.destination_id(), method, path, body, write_key(settings.site, method, path, body))
        job.pending = request
    if checkpoint:
        checkpoint()
    write_returned = False
    try:
        result = client.write(request.method, request.path, request.body, request.key)
        write_returned = True
        expected_fields = {name for name in ("priority", "concurrency", "proxy_id", "load_factor") if name in request.body}
        if not all(field in result for field in {"group_ids", "credentials", "platform", "type"} | expected_fields):
            result = client.get_account(result["id"])
        if settings.model_whitelist is not None:
            expected = request.body["credentials"]["model_mapping"]
            if not isinstance(result.get("credentials"), dict) or "model_mapping" not in result["credentials"]:
                result = client.get_account(result["id"])
            saved_credentials = result.get("credentials")
            actual = saved_credentials.get("model_mapping") if isinstance(saved_credentials, dict) else None
            if actual != expected or settings.model_whitelist and _is_passthrough(result):
                raise PoolError("后台返回的模型限制与本次白名单不一致或启用了自动透传，结果待核对", category="protocol", uncertain=True)
        group_ids = result.get("group_ids")
        if (not isinstance(group_ids, list) or any(type(value) is not int or value <= 0 for value in group_ids) or
                set(group_ids) != set(settings.group_ids) or
                request.method == "PUT" and request.path != f"/accounts/{result['id']}"):
            raise PoolError("后台写入后的分组或配置与请求不一致，结果待核对", category="protocol", uncertain=True)
        for name in expected_fields:
            actual = result.get(name)
            if actual is None and name in ("proxy_id", "load_factor"):
                actual = 0
            if type(actual) is not int or actual != request.body[name]:
                raise PoolError("后台写入后的代理或调度配置与请求不一致，结果待核对", category="protocol", uncertain=True)
        if not find_existing(request.body, [result]):
            raise PoolError("后台写入后的账号身份与请求不一致，结果待核对", category="protocol", uncertain=True)
    except PoolError as exc:
        # Read-back failure occurs after a successful write and must stay pending.
        if write_returned or resuming:
            exc.uncertain = True
        if not exc.uncertain:
            job.pending = None
        raise
    job.account_id = result["id"]
    job.completed_destination = settings.destination_id()
    job.state = "updated" if request.method == "PUT" else "created"
    job.message = "已更新凭据及配置" if request.method == "PUT" else "已创建并绑定分组"
    if settings.model_whitelist is not None:
        job.message += f"；已设置 {len(set(settings.model_whitelist))} 个白名单模型" if settings.model_whitelist else "；已清除模型限制"
    if not request.body["credentials"].get("refresh_token"):
        has_refresh = (result.get("credentials_status") or {}).get("has_refresh_token")
        job.message += "；保留后台已有刷新令牌" if has_refresh else "；刷新能力需核对"
    job.pending = None
    # The write response is redacted; retain only identity for this run's index.
    updated = {**request.body, **result, "platform": "openai", "type": "oauth"}
    updated["credentials"] = {**request.body["credentials"], **(result.get("credentials") or {})}
    records[:] = [record for record in records if record["id"] != result["id"]]
    records.append(updated)


def run_pool_push(jobs: list[PushJob], settings: PoolSettings, *, stop: threading.Event,
                  on_progress, timeout=180, proxy=None, headless=True, recovery_dir=None,
                  client_factory=PoolClient, authorize=run_batch_reauth, journal=None, journal_jobs=None,
                  refresh=None, relogin_ids=()):
    """Push credential inputs, then reuse one OAuth batch for login inputs."""
    settings.validate()
    refresh = refresh or refresh_account
    for job in jobs:
        job.state, job.message = "ready", "等待处理"
    report_file = None
    if journal is None and recovery_dir is not None:
        from pool_recovery import PoolJournal
        journal = PoolJournal.create(recovery_dir)
    if journal is not None:
        report_file = journal.path.with_name("report.json")
    elif recovery_dir is not None:
        run_dir = Path(recovery_dir) / ("pool-" + time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8])
        report_file = run_dir / "report.json"
    def checkpoint():
        if journal is not None:
            journal.save(settings, journal_jobs if journal_jobs is not None else jobs)

    def publish(job):
        checkpoint()
        on_progress(job)
        if report_file:
            _atomic_write_json(report_file, {"site": settings.site, "results": [
                {"email": item.email, "state": item.state, "message": item.message, "account_id": item.account_id}
                for item in jobs]}, overwrite=True)

    def upload(client, job, records):
        if stop.is_set():
            return
        job.state, job.message = "pushing", "正在核对并推送"
        publish(job)
        try:
            push_one(client, settings, job, records, checkpoint=checkpoint)
        except PoolError as exc:
            job.state = "uncertain" if exc.uncertain else exc.category
            job.message = str(exc)
            publish(job)
            if exc.uncertain or exc.category in ("auth", "rate_limited", "network", "server", "protocol", "endpoint", "groups", "cancelled", "storage"):
                raise
            return
        publish(job)

    try:
        checkpoint()  # Encryption and disk permissions must succeed before any network operation.
        with client_factory(settings, stop) as client:
            client.validate_groups()
            records = client.accounts()
            for job in jobs:
                if stop.is_set():
                    break
                # Reconcile an ambiguous backend write before changing any tokens.
                if (job.account is not None and not job.pending
                        and (job.account.get("credentials") or {}).get("refresh_token")):
                    try:
                        recovered = recover_refresh_account(job.account, should_stop=stop.is_set,
                                                            recovery_dir=recovery_dir)
                    except RefreshError as exc:
                        job.refresh_state = exc.category
                        job.state, job.message = exc.category, str(exc)
                        publish(job)
                        if exc.category in ("storage", "cancelled"):
                            raise PoolError(str(exc), category=exc.category) from None
                        if job.uid not in relogin_ids or exc.category not in ("refresh_failed", "refresh_unknown"):
                            continue
                        recovered = None
                    if recovered is not None:
                        job.account = recovered
                        job.refresh_state = "refreshed"
                        checkpoint()
                    if job.uid in relogin_ids and job.refresh_state in ("refresh_failed", "refresh_unknown", "refreshing"):
                        if job.login is None:
                            job.state, job.message = "refresh_unknown", "缺少登录资料，请补充资料后选择重登"
                            publish(job)
                            continue
                        # Keep the source identity for checking the later login result.
                        job.state = "relogin"
                        continue
                    if job.refresh_state in ("refresh_failed", "refresh_unknown", "refreshing"):
                        job.state, job.message = "refresh_unknown", "刷新未确认成功，请点击重试失败并选择是否重新登录"
                        publish(job)
                        continue
                    if credentials_fresh(job.account):
                        upload(client, job, records)
                        continue
                    job.state, job.refresh_state, job.message = "refreshing", "refreshing", "正在刷新已有凭据，未启动浏览器"
                    publish(job)
                    try:
                        job.account = refresh(job.account, proxy=proxy, should_stop=stop.is_set,
                                              recovery_dir=recovery_dir)
                        job.refresh_state = "refreshed"
                        checkpoint()
                    except RefreshError as exc:
                        job.refresh_state = exc.category
                        job.state, job.message = exc.category, str(exc)
                        publish(job)
                        if exc.category in ("storage", "cancelled"):
                            raise PoolError(str(exc), category=exc.category) from None
                        continue
                if job.account is not None or job.pending:
                    upload(client, job, records)
            login_jobs = [job for job in jobs if (job.account is None or job.state == "relogin") and job.login is not None and not job.pending]
            if login_jobs and not stop.is_set():
                def authorized(index, _total, result):
                    job = login_jobs[index - 1]
                    if result.ok and result.account:
                        if job.account is not None:
                            try:
                                matching = find_existing(result.account, [{**job.account, "id": 1}])
                            except PoolError:
                                matching = None
                            if not matching:
                                job.state, job.message = "identity", "重登返回的工作空间或账号不同，未推送；请核对后重新导入"
                                publish(job)
                                return
                            # Retain imported model/scheduling settings when replacing login credentials.
                            original = copy.deepcopy(job.account)
                            original["credentials"].update(result.account["credentials"])
                            if result.account["credentials"].get("id_token") and not _synthetic_marker(result.account):
                                clear_synthetic_marker(original)
                            job.account = original
                        else:
                            job.account = result.account
                        job.refresh_state = "refreshed"
                        checkpoint()
                        if not stop.is_set():
                            upload(client, job, records)
                    else:
                        job.state = result.category
                        job.message = "待补手机：已跳过，其他账号继续" if result.category == "phone_required" else (result.error or "授权未完成")
                        publish(job)
                authorize([job.login for job in login_jobs], timeout=timeout, proxy=proxy, headless=headless,
                          should_stop=stop.is_set, on_progress=authorized, recovery_dir=recovery_dir,
                          skip_phone_verification=True)
    finally:
        for job in jobs:
            if job.state in ("ready", "pushing", "relogin"):
                job.state, job.message = "not_processed", "未处理，可稍后重试"
                publish(job)
    return jobs
