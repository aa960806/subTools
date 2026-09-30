"""Refresh existing OAuth credentials once; never initiate browser login."""
from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import time
from contextlib import contextmanager
from pathlib import Path

import httpx

from local_secrets import protect_secret, unprotect_secret, is_protected
from reauth_formats import (_atomic_write_json, _conversion_identity, _conversion_user_info,
                            decode_jwt, parse_datetime_to_unix, CPA_META_KEY, _format_cst,
                            _synthetic_marker, _is_synthetic_token)
from datetime import datetime, timezone


class RefreshError(RuntimeError):
    def __init__(self, category, message):
        super().__init__(message)
        self.category = category


def credentials_fresh(account, *, margin=60):
    """Use the earliest known expiry; unknown expiry is never proof of freshness."""
    creds = account.get("credentials") or {}
    expiries = [parse_datetime_to_unix(creds.get("expires_at")),
                parse_datetime_to_unix(decode_jwt(creds.get("access_token", "")).get("exp"))]
    expiries = [value for value in expiries if value is not None]
    return bool(creds.get("access_token") and expiries and min(expiries) > time.time() + margin)


def clear_synthetic_marker(account):
    metadata = (account.get("extra") or {}).get(CPA_META_KEY) or {}
    unmapped = metadata.get("unmapped")
    if isinstance(unmapped, dict):
        unmapped.pop("id_token_synthetic", None)


def _identity_check(source, fresh):
    old = _conversion_identity(source)
    for key in ("email", "chatgpt_account_id", "chatgpt_user_id"):
        values = [old.get(key)] + [item.get(key) for item in fresh]
        values = [str(value).casefold() if key == "email" else value for value in values if value]
        if len(set(values)) > 1:
            raise RefreshError("refresh_unknown", "刷新凭据的账号或工作空间身份不一致，已保留原输入，等待人工核对")


def _stable_account_id(source, fresh):
    """Keep an exported account ID only when both token sets prove continuity."""
    old = _conversion_identity(source)
    creds = source.get("credentials") or {}
    before = [_conversion_user_info("", creds.get("access_token", "")),
              _conversion_user_info(creds.get("id_token", ""), "", marked=_synthetic_marker(source))]
    for field in ("email", "chatgpt_user_id", "organization_id"):
        value = old.get(field)
        if not value or not any(item.get(field) for item in before) or not any(item.get(field) for item in fresh):
            return ""
        values = [item.get(field) for item in [*before, *fresh] if item.get(field)]
        values.append(value)
        if field == "email":
            values = [item.casefold() for item in values]
        if len(set(values)) != 1:
            return ""
    return old.get("chatgpt_account_id", "")


def _refresh_parameters(account):
    from openai_reauth import CLIENT_ID
    creds = account.get("credentials") or {}
    refresh = creds.get("refresh_token")
    if not isinstance(refresh, str) or not refresh.strip():
        raise RefreshError("refresh_failed", "缺少 refresh token，请选择是否重新登录")
    client_id = creds.get("client_id") or decode_jwt(creds.get("access_token", "")).get("client_id") or CLIENT_ID
    if not isinstance(client_id, str) or not client_id.strip():
        raise RefreshError("refresh_unknown", "无法确定 OAuth 客户端，请选择是否重新登录")
    return client_id, refresh


@contextmanager
def _refresh_lease(path):
    handle = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        handle = path.open("a+b")
        handle.seek(0, os.SEEK_END)
        if not handle.tell():
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
    except OSError:
        if handle is not None:
            handle.close()
        raise RefreshError("storage", "无法建立刷新记录锁，已停止；请检查恢复目录权限") from None
    try:
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise RefreshError("refresh_busy", "另一个任务正在刷新相同凭据，请等待结束后再试") from None
        yield
    finally:
        # Do not unlink: contenders must lock the same file across process exits.
        handle.close()


def recover_refresh_account(account, *, should_stop=None, recovery_dir=None):
    """Validate saved responses without submitting or replaying any token."""
    if recovery_dir is None:
        return None
    return refresh_account(account, should_stop=should_stop, recovery_dir=recovery_dir, allow_network=False)


def refresh_account(account, *, proxy=None, should_stop=None, recovery_dir=None, transport=None, allow_network=True):
    options = dict(proxy=proxy, should_stop=should_stop, recovery_dir=recovery_dir, transport=transport,
                   allow_network=allow_network)
    if should_stop and should_stop():
        raise RefreshError("cancelled", "已停止刷新")
    if recovery_dir is None:
        return _refresh_account(account, **options)
    client_id, refresh = _refresh_parameters(account)
    digest = hashlib.sha256((client_id + "\0" + refresh).encode()).hexdigest()
    with _refresh_lease(Path(recovery_dir) / "token-refresh" / (digest + ".lock")):
        return _refresh_account(account, **options)


def _refresh_account(account, *, proxy=None, should_stop=None, recovery_dir=None, transport=None, allow_network=True):
    """Persist rotation before validation. No redirects, retries or secret error bodies."""
    from openai_reauth import TOKEN_URL, CODEX_UA, CODEX_ORIGINATOR
    def check_stop():
        if should_stop and should_stop():
            raise RefreshError("cancelled", "已停止刷新")
    check_stop()
    source = copy.deepcopy(account)
    creds = source.get("credentials") or {}
    client_id, refresh = _refresh_parameters(source)
    _identity_check(source, [_conversion_user_info("", creds.get("access_token", "")),
                             _conversion_user_info(creds.get("id_token", ""), "", marked=_synthetic_marker(source))])
    path = None
    if recovery_dir is not None:
        digest = hashlib.sha256((client_id + "\0" + refresh).encode()).hexdigest()
        path = Path(recovery_dir) / "token-refresh" / (digest + ".dpapi.json")

    def save(phase, **fields):
        if path is None:
            return
        try:
            encrypted = protect_secret(json.dumps({"phase": phase, "source": source, **fields}, ensure_ascii=False, allow_nan=False))
            if not is_protected(encrypted):
                raise ValueError
            _atomic_write_json(path, {"version": 1, "encrypted": encrypted}, overwrite=True)
        except Exception:
            raise RefreshError("storage", "刷新记录加密保存失败，已停止；请检查恢复目录和本机加密") from None

    received = None
    received_at = None
    if path is not None and path.exists():
        try:
            outer = json.loads(path.read_text(encoding="utf-8"))
            if outer.get("version") != 1 or not is_protected(outer.get("encrypted")):
                raise ValueError
            previous = json.loads(unprotect_secret(outer["encrypted"]))
            if previous["phase"] == "validated":
                saved = previous["account"]
                _identity_check(source, [_conversion_identity(saved)])
                result = copy.deepcopy(source)
                result["credentials"].update({key: value for key, value in saved["credentials"].items()
                                              if key in ("access_token", "refresh_token", "id_token", "client_id", "expires_at",
                                                         "email", "chatgpt_account_id", "chatgpt_user_id", "plan_type", "organization_id")})
                if CPA_META_KEY in saved.get("extra", {}):
                    result.setdefault("extra", {}).setdefault(CPA_META_KEY, {}).update(
                        last_refresh=saved["extra"][CPA_META_KEY]["last_refresh"])
                if not _synthetic_marker(saved):
                    clear_synthetic_marker(result)
                if not allow_network or credentials_fresh(result, margin=0):
                    return result
                if result["credentials"]["refresh_token"] != refresh:
                    # Follow only a confirmed rotation; never replay the old token.
                    return refresh_account(result, proxy=proxy, should_stop=should_stop,
                                           recovery_dir=recovery_dir, transport=transport)
                source, creds = result, result["credentials"]
            elif previous["phase"] == "received":
                if previous.get("source") != source:
                    raise RefreshError("refresh_unknown", "刷新记录与当前输入不一致，等待人工核对")
                received = previous.get("response")
                if not isinstance(received, dict):
                    raise RefreshError("refresh_unknown", "已保存的刷新响应格式无效，不重复提交；等待人工核对")
                if "received_at" in previous:
                    received_at = parse_datetime_to_unix(previous["received_at"])
                    if received_at is None or received_at <= 0 or received_at > time.time():
                        raise RefreshError("refresh_unknown", "刷新响应的接收时间无效，不重复提交；等待人工核对")
            elif previous["phase"] != "prepared":
                category = "refresh_failed" if previous["phase"] == "rejected" else "refresh_unknown"
                raise RefreshError(category, "此刷新令牌已有失败或待核对记录，不重复提交；请选择是否重新登录")
        except RefreshError:
            raise
        except Exception:
            raise RefreshError("refresh_unknown", "无法核对此令牌的本机刷新记录，不重复提交；请选择是否重新登录") from None

    if received is not None:
        data = received
    else:
        if not allow_network:
            return None
        # A prepared record is safe to resume: no request has been attempted yet.
        save("prepared")
        check_stop()
        try:
            client = httpx.Client(proxy=proxy, transport=transport, follow_redirects=False, trust_env=False,
                                  timeout=httpx.Timeout(25, connect=10))
        except Exception:
            raise RefreshError("refresh_unsent", "刷新请求尚未发送，请检查网络配置后重试") from None
        try:
            with client:
                check_stop()
                # From this durable boundary onward a crash is ambiguous, even if
                # the server's response never reaches us. Do not replay the token.
                save("pending")
                response = client.post(TOKEN_URL, data={"grant_type": "refresh_token", "client_id": client_id,
                                                       "refresh_token": refresh},
                                       headers={"User-Agent": CODEX_UA, "originator": CODEX_ORIGINATOR,
                                                "Accept": "application/json"})
        except httpx.HTTPError:
            raise RefreshError("refresh_unknown", "刷新请求未获确认，令牌可能已轮换；不会自动重试或重登") from None
        try:
            data = response.json()
        except ValueError:
            raise RefreshError("refresh_unknown", f"刷新响应不是有效 JSON（HTTP {response.status_code}），请决定是否重登") from None
        if response.status_code != 200:
            code = data.get("error") if isinstance(data, dict) else None
            if isinstance(code, dict):
                code = code.get("code")
            if response.status_code in (400, 401) and code in ("invalid_grant", "invalid_token", "refresh_token_reused", "refresh_token_expired", "refresh_token_invalidated"):
                save("rejected")
                raise RefreshError("refresh_failed", "刷新令牌被服务拒绝，请选择是否重新登录")
            raise RefreshError("refresh_unknown", f"刷新未确认成功（HTTP {response.status_code}），不自动重登")
        received_at = time.time()
        save("received", response=data, received_at=received_at)
    if not isinstance(data, dict) or not isinstance(data.get("access_token"), str) or not data["access_token"].strip():
        raise RefreshError("refresh_unknown", "刷新响应缺少 access token，已保存响应等待核对")
    if any(key in data and (not isinstance(data[key], str) or not data[key].strip()) for key in ("refresh_token", "id_token")):
        raise RefreshError("refresh_unknown", "刷新响应的令牌字段无效，已保存响应等待核对")
    claims = [_conversion_user_info("", data["access_token"]), _conversion_user_info(data.get("id_token", ""), "")]
    _identity_check(source, claims)
    if not any(item.get("chatgpt_account_id") for item in claims):
        retained = _stable_account_id(source, claims)
        if retained:
            claims[0]["chatgpt_account_id"] = retained
    if not any(item.get("chatgpt_account_id") for item in claims) or not any(item.get("email") or item.get("chatgpt_user_id") for item in claims):
        raise RefreshError("refresh_unknown", "刷新响应无法确认账号及工作空间，已保存响应等待核对")
    now = received_at if received_at is not None else time.time()
    expiry = parse_datetime_to_unix(decode_jwt(data["access_token"]).get("exp"))
    duration = data.get("expires_in")
    try:
        seconds = float(duration) if not isinstance(duration, bool) else 0
    except (TypeError, ValueError):
        seconds = 0
    # Legacy saved responses without a receipt time must rely on the JWT expiry.
    if received_at is not None and math.isfinite(seconds) and 0 < seconds <= 315360000:
        expiry = min(expiry, int(now + seconds)) if expiry is not None else int(now + seconds)
    if expiry is None or expiry <= time.time():
        raise RefreshError("refresh_unknown", "刷新响应缺少有效到期时间或已经过期，等待核对")
    updated = copy.deepcopy(source)
    target = updated["credentials"]
    for item in claims:
        target.update({key: value for key, value in item.items() if value})
    for key in ("access_token", "refresh_token", "id_token"):
        if key in data:
            target[key] = data[key]
    if "id_token" in data and not _is_synthetic_token(data["id_token"]):
        clear_synthetic_marker(updated)
    target.update(client_id=client_id, expires_at=expiry)
    meta = updated.setdefault("extra", {}).setdefault(CPA_META_KEY, {})
    meta["last_refresh"] = _format_cst(datetime.fromtimestamp(now, timezone.utc))
    save("validated", account=updated)
    return updated


def run_refresh_first(inputs, *, authorize, refresh=None, on_progress=None, should_stop=None, **options):
    """GUI authorization entry. Failed refreshes only produce decision-needed results."""
    from openai_reauth import ReauthResult, log
    refresh = refresh or refresh_account
    if not any(item.oauth_account for item in inputs):
        return authorize(inputs, on_progress=on_progress, should_stop=should_stop, **options)
    results = []
    for index, item in enumerate(inputs, 1):
        if should_stop and should_stop():
            break
        if item.oauth_account:
            try:
                recovered = recover_refresh_account(item.oauth_account, should_stop=should_stop,
                                                    recovery_dir=options.get("recovery_dir"))
                if recovered is not None:
                    item.oauth_account = recovered
                    item.refresh_state = "refreshed"
                if recovered is None and item.refresh_state in ("refresh_failed", "refresh_unknown", "refreshing"):
                    raise RefreshError("refresh_unknown", "前次刷新未完成，需选择是否重新登录")
                if recovered is None or not credentials_fresh(item.oauth_account):
                    log(f"{item.email}: 优先刷新已有凭据")
                    item.refresh_state = "refreshing"
                    item.oauth_account = refresh(item.oauth_account, proxy=options.get("proxy"), should_stop=should_stop,
                                                 recovery_dir=options.get("recovery_dir"))
                    item.refresh_state = "refreshed"
                    log(f"{item.email}: 刷新成功，未启动浏览器")
                else:
                    log(f"{item.email}: 已恢复本机已确认的刷新凭据，未重新请求")
                result = ReauthResult(item.email, True, account=item.oauth_account, category="success")
            except RefreshError as exc:
                item.refresh_state = exc.category
                result = ReauthResult(item.email, False, error=str(exc), category=exc.category)
        else:
            batch = authorize([item], should_stop=should_stop, **options)
            if not batch:
                break
            result = batch[0]
        results.append(result)
        if on_progress:
            on_progress(index, len(inputs), result)
        if result.category in ("cancelled", "storage", "rate_limited"):
            break
    return results
