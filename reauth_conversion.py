"""Extended offline inputs for the conversion page, separate from login inputs."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reauth_formats import (
    Accounts, CONVERSION_META_KEY, CPA_META_KEY, _base_account, _conversion_user_info,
    _parse_datetime, _string, accounts_from_cpa_data, accounts_from_sub2_data,
    decode_jwt, is_cpa_payload, is_sub2_account_payload, is_sub2_wrapper,
    parse_datetime_to_unix, parse_json_documents,
)


def _get(record, path):
    for key in path.split("."):
        if not isinstance(record, dict):
            return None
        record = record.get(key)
    return record


def _remove(record, path):
    key, _, rest = path.partition(".")
    if rest and isinstance(record.get(key), dict):
        _remove(record[key], rest)
        if not record[key]:
            record.pop(key)
    elif not rest:
        record.pop(key, None)


TOKEN_PATHS = {
    field: tuple(f"{prefix}{alias}" for prefix in ("", "token.", "credentials.") for alias in aliases)
    for field, aliases in {
        "access_token": ("accessToken", "access_token"),
        "refresh_token": ("refreshToken", "refresh_token"),
        "id_token": ("idToken", "id_token"),
    }.items()
}
IDENTITY_PATHS = {
    "email": ("user.email", "email", "credentials.email", "providerSpecificData.email"),
    "chatgpt_account_id": ("account.id", "account_id", "chatgptAccountId", "chatgpt_account_id",
                           "providerSpecificData.chatgptAccountId", "providerSpecificData.chatgpt_account_id",
                           "credentials.chatgpt_account_id"),
    "chatgpt_user_id": ("user.id", "user_id", "chatgptUserId", "chatgpt_user_id",
                        "providerSpecificData.chatgptUserId", "providerSpecificData.chatgpt_user_id",
                        "credentials.chatgpt_user_id"),
    "plan_type": ("account.planType", "account.plan_type", "planType", "plan_type", "chatgpt_plan_type",
                  "providerSpecificData.chatgptPlanType", "providerSpecificData.chatgpt_plan_type",
                  "credentials.plan_type"),
    "organization_id": ("organization_id", "organizationId", "credentials.organization_id",
                        "providerSpecificData.organizationId", "providerSpecificData.organization_id"),
    "client_id": ("client_id", "clientId", "credentials.client_id", "providerSpecificData.clientId"),
}


def _extended_kind(record):
    if not isinstance(record, dict):
        return None
    if record.get("provider") == "codex" and record.get("authType") == "oauth":
        return "9router"
    # Never reinterpret an unsupported provider/platform as an OpenAI session.
    if record.get("provider") or record.get("platform") or record.get("type"):
        return None
    has_access = any(_string(_get(record, path)) for path in TOKEN_PATHS["access_token"])
    identity = isinstance(record.get("user"), dict) or any(
        _string(_get(record, path)) for path in IDENTITY_PATHS["email"])
    return "web_session" if has_access and identity else None


def _extended_account(record: dict, kind: str) -> Accounts:
    remaining = copy.deepcopy(record)
    messages = []

    def select(field, paths, *, timestamp=False):
        candidates = []
        for path in paths:
            value = _get(record, path)
            if value is None or value == "":
                continue
            if timestamp:
                parsed = _parse_datetime(value)
                if parsed is None:
                    messages.append(f"{field} 包含无法解析或缺少时区的时间；原值保留在来源元数据中。")
                    continue
                normalized = parsed.timestamp()
            else:
                if not isinstance(value, str):
                    raise ValueError(f"{field} 必须是字符串")
                value = value.strip()
                if not value:
                    continue
                normalized = value.casefold() if field == "email" else value
            candidates.append((value, normalized, path))
        if len({item[1] for item in candidates}) > 1:
            if field in TOKEN_PATHS:
                raise ValueError(f"{field} 的多个别名内容冲突，请保留正确的一项后重试")
            messages.append(f"{field} 的多个来源字段冲突；保留首个有效字段，其余原值保存在来源元数据中。")
        for _, normalized, path in candidates:
            if normalized == candidates[0][1]:
                _remove(remaining, path)
        return candidates[0][0] if candidates else None

    creds = {key: select(key, paths) or "" for key, paths in TOKEN_PATHS.items()}
    if not (creds["access_token"] or creds["refresh_token"]):
        raise ValueError("缺少 access_token 或 refresh_token；sessionToken 不能代替 OAuth 凭据")
    marked = record.get("id_token_synthetic") is True
    info = _conversion_user_info(creds["id_token"], creds["access_token"], marked=marked)
    for key, paths in IDENTITY_PATHS.items():
        value = select(key, paths)
        if not value and key == "chatgpt_account_id" and kind == "9router":
            # Prefer token account identity over 9router's potentially local record ID.
            value = info.get(key)
        value = value or info.get(key)
        if value:
            creds[key] = value
    if not creds.get("email"):
        raise ValueError("缺少 email，且 token 中没有可读邮箱")
    # A web session's expires describes its session, not necessarily its access token.
    expiry = select("expires_at", ("expiresAt", "expired", "expires_at", "credentials.expires_at"), timestamp=True)
    session_expiry = select("session_expires", ("expires",), timestamp=True)
    if expiry is None:
        expiry = decode_jwt(creds["access_token"]).get("exp")
    parsed_expiry = parse_datetime_to_unix(expiry)
    if parsed_expiry is not None:
        creds["expires_at"] = parsed_expiry
    elif session_expiry is not None:
        messages.append("只有网页会话 expires，无法确认 access_token 的到期时间；不将会话时间写为 token 有效期。")
    refreshed = select("last_refresh", ("last_refresh", "lastRefresh", "credentials.last_refresh"), timestamp=True)
    if refreshed is not None:
        creds["last_refresh"] = refreshed
    for flag in ("disabled", "isActive"):
        if flag in record and not isinstance(record[flag], bool):
            raise ValueError(f"{flag} 必须是布尔值")
    if "disabled" in record and "isActive" in record and record["disabled"] == record["isActive"]:
        messages.append("disabled 与 isActive 冲突；保留 disabled，请核对原始状态。")
    disabled = record.get("disabled", not record.get("isActive", True))
    account = _base_account(creds["email"], creds)
    account["name"] = _string(record.get("name")) or creds["email"]
    account["extra"][CPA_META_KEY] = {"disabled": disabled}
    if marked:
        account["extra"][CPA_META_KEY]["unmapped"] = {"id_token_synthetic": True}
    metadata: dict[str, Any] = {"source": kind}
    if session_expiry is not None:
        metadata["session_expires"] = session_expiry
    if messages:
        metadata["warnings"] = messages
    for path in ("provider", "authType", "name", "disabled", "isActive", "id_token_synthetic"):
        _remove(remaining, path)
    if remaining:
        metadata["unmapped"] = remaining
    account["extra"][CONVERSION_META_KEY] = metadata
    return Accounts([account], warnings=messages)


def parse_conversion_text(text: str) -> tuple[str, Accounts]:
    """Accept mixed arrays/documents, but never silently skip pasted records."""
    accounts = Accounts()
    kinds = set()

    def visit(item, position):
        if isinstance(item, list):
            if not item:
                raise ValueError(f"{position}：账号数组为空")
            for index, child in enumerate(item, 1):
                visit(child, f"{position}[{index}]")
            return
        try:
            if is_sub2_wrapper(item) or is_sub2_account_payload(item):
                kind, found = "sub2", accounts_from_sub2_data(item)
            elif is_cpa_payload(item):
                kind, found = "cpa", accounts_from_cpa_data(item)
            elif kind := _extended_kind(item):
                found = _extended_account(item, kind)
            else:
                raise ValueError("无法识别；支持 OpenAI sub2、CPA、ChatGPT 网页 Session 和 9router Codex OAuth")
        except ValueError as exc:
            raise ValueError(f"{position}：{exc}") from exc
        found.warnings = [f"{position}：{message}" for message in found.warnings]
        accounts.extend(found)
        kinds.add(kind)

    for index, item in enumerate(parse_json_documents(text), 1):
        visit(item, f"第 {index} 段")
    return (next(iter(kinds)) if len(kinds) == 1 else "mixed"), accounts


@dataclass
class ConversionImport:
    accounts: Accounts = field(default_factory=Accounts)
    kind: str = ""
    text: str = ""
    accepted_files: int = 0
    # Positions map to the sorted directory/selection; filenames stay in the local UI.
    files: list[Path] = field(default_factory=list)
    failures: list[tuple[int, str]] = field(default_factory=list)


def load_conversion_files(paths) -> ConversionImport:
    result = ConversionImport()
    chunks, kinds = [], set()
    for index, path in enumerate(paths, 1):
        path = Path(path)
        result.files.append(path)
        try:
            content = path.read_text(encoding="utf-8-sig").strip()
            kind, accounts = parse_conversion_text(content)
        except (OSError, UnicodeError, ValueError) as exc:
            reason = str(exc) if isinstance(exc, ValueError) and not isinstance(exc, UnicodeError) else "无法读取 UTF-8 文件"
            result.failures.append((index, reason))
            continue
        result.accounts.extend(accounts)
        result.accepted_files += 1
        kinds.add(kind)
        chunks.append(content)
    result.kind = next(iter(kinds)) if len(kinds) == 1 else "mixed"
    result.text = "\n\n".join(chunks)
    result.accounts.warnings.extend(f"第 {index} 个文件已跳过：{reason}" for index, reason in result.failures)
    return result
