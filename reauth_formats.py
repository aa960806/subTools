"""Offline, standard-library-only conversion of OpenAI OAuth account exports.

CPA deliberately contains only its nine standard fields. Conversion warnings
describe fields it cannot carry; no sidecars or implicit backups are written.
Decoded JWT claims are unverified metadata, never evidence of authentication.
"""

from __future__ import annotations

import base64
import copy
import json
import math
import os
import re
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
CST = timezone(timedelta(hours=8))
CPA_FIELDS = ("type", "email", "expired", "id_token", "account_id", "disabled",
              "access_token", "last_refresh", "refresh_token")
CPA_META_KEY = "openai_reauth_cpa"
CONVERSION_META_KEY = "openai_reauth_conversion"


class Accounts(list):
    """A list that also retains source wrappers and human-readable warnings."""

    def __init__(self, values=(), *, wrappers=None, warnings=None):
        super().__init__(values)
        self.wrappers = copy.deepcopy(wrappers or [])
        self.warnings = list(warnings or [])

    def extend(self, values):
        if isinstance(values, Accounts):
            self.wrappers.extend(copy.deepcopy(values.wrappers))
            self.warnings.extend(values.warnings)
        super().extend(values)


def _string(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def decode_jwt(token: str) -> dict[str, Any]:
    if not isinstance(token, str):
        return {}
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    try:
        data = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except (ValueError, UnicodeError):
        return {}
    return data if isinstance(data, dict) else {}


def extract_user_info(id_token: str, access_token: str) -> dict[str, str]:
    claims, access = decode_jwt(id_token), decode_jwt(access_token)
    auth = claims.get("https://api.openai.com/auth")
    access_auth = access.get("https://api.openai.com/auth")
    profile = claims.get("https://api.openai.com/profile")
    access_profile = access.get("https://api.openai.com/profile")
    auth = auth if isinstance(auth, dict) else {}
    access_auth = access_auth if isinstance(access_auth, dict) else {}
    profile = profile if isinstance(profile, dict) else {}
    access_profile = access_profile if isinstance(access_profile, dict) else {}
    organization_id = _string(auth.get("organization_id") or access_auth.get("organization_id")
                              or access_auth.get("poid"))
    if not organization_id:
        organizations = auth.get("organizations")
        if isinstance(organizations, list):
            defaults = [org for org in organizations if isinstance(org, dict) and org.get("is_default") is True]
            if len(defaults) == 1:
                organization_id = _string(defaults[0].get("id"))
    return {
        "email": _string(claims.get("email") or profile.get("email") or access_profile.get("email")),
        "chatgpt_account_id": _string(auth.get("chatgpt_account_id") or access_auth.get("chatgpt_account_id")),
        "chatgpt_user_id": _string(auth.get("chatgpt_user_id") or access_auth.get("chatgpt_user_id")
                                   or auth.get("user_id") or access_auth.get("user_id")),
        "plan_type": _string(auth.get("chatgpt_plan_type") or access_auth.get("chatgpt_plan_type")),
        "organization_id": organization_id,
    }


def _is_synthetic_token(token: str, marked: bool = False) -> bool:
    """Recognize placeholders, not signatures: all decoded claims are unverified."""
    if marked:
        return True
    parts = _string(token).split(".")
    if len(parts) != 3:
        return False
    try:
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
    except (ValueError, UnicodeError):
        header = {}
    return (not parts[2] or isinstance(header, dict) and
            (header.get("cpa_synthetic") is True or str(header.get("alg", "")).lower() == "none"))


def _conversion_user_info(id_token: str, access_token: str, *, marked: bool = False) -> dict[str, str]:
    # Keep the real OAuth path's extraction policy separate from offline imports.
    if _is_synthetic_token(id_token, marked):
        id_token = ""
    info = extract_user_info(id_token, access_token)
    info["email"] = info["email"] or _string(decode_jwt(access_token).get("email"))
    return info


def _synthetic_marker(account: dict[str, Any]) -> bool:
    unmapped = _cpa_metadata(account).get("unmapped")
    return isinstance(unmapped, dict) and unmapped.get("id_token_synthetic") is True


def _conversion_identity(account: dict[str, Any]) -> dict[str, str]:
    creds = account["credentials"]
    info = _conversion_user_info(_string(creds.get("id_token")), _string(creds.get("access_token")),
                                 marked=_synthetic_marker(account))
    for field in info:
        info[field] = _string(creds.get(field)) or info[field]
    # An explicit email in extra/name still takes precedence over token metadata.
    explicit_email = _string(creds.get("email")) or _string((account.get("extra") or {}).get("email"))
    if not explicit_email and "@" in _string(account.get("name")):
        explicit_email = account["name"].strip()
    info["email"] = explicit_email or info["email"]
    return info


def _parse_datetime(value: Any) -> datetime | None:
    if value is None or value == "" or isinstance(value, bool):
        return None
    try:
        if isinstance(value, (int, float)) or (isinstance(value, str) and re.fullmatch(r"[+-]?\d+(?:\.\d+)?", value.strip())):
            number = float(value)
            if not math.isfinite(number) or number <= 0:
                return None
            # Modern Unix milliseconds are unambiguous at this magnitude.
            if number >= 100_000_000_000:
                number /= 1000
            return datetime.fromtimestamp(number, timezone.utc)
        if not isinstance(value, str):
            return None
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            return None  # Never silently assign a timezone to ambiguous input.
        return parsed
    except (ValueError, OverflowError, OSError):
        return None


def parse_datetime_to_unix(value: Any) -> int | None:
    parsed = _parse_datetime(value)
    return int(parsed.timestamp()) if parsed else None


def _format_cst(dt: datetime, millis_width: int = 3) -> str:
    if dt.tzinfo is None:
        raise ValueError("时间必须包含时区")
    local = dt.astimezone(CST)
    if millis_width == 3:
        return local.isoformat(timespec="milliseconds")
    fraction = f"{local.microsecond:06d}"[:millis_width].ljust(millis_width, "0")
    return local.strftime("%Y-%m-%dT%H:%M:%S") + "." + fraction + "+08:00"


def _cpa_time(value: Any) -> str:
    parsed = _parse_datetime(value)
    return _format_cst(parsed) if parsed else ""


def _base_account(email: str, credentials: dict[str, Any]) -> dict[str, Any]:
    return {"name": email, "platform": "openai", "type": "oauth", "credentials": credentials,
            "extra": {"email": email}, "concurrency": 1, "priority": 1,
            "rate_multiplier": 1, "auto_pause_on_expired": True}


def build_account_payload(token: dict[str, Any], fallback_email: str) -> dict[str, Any]:
    """Build a newly issued account; only this path records a new refresh time."""
    for key in ("access_token", "refresh_token", "id_token"):
        if not _string(token.get(key)):
            raise ValueError(f"token 响应缺少 {key}")
    access_token = _string(token.get("access_token"))
    info = extract_user_info(_string(token.get("id_token")), access_token)
    email = info["email"]
    if not email:
        raise ValueError("token 未提供账号邮箱，无法验证账号归属")
    if email.casefold() != _string(fallback_email).casefold():
        raise ValueError("token 邮箱与待授权账号不一致，已拒绝导出")
    if not info["chatgpt_account_id"]:
        raise ValueError("token 缺少 chatgpt_account_id，无法确认账号")
    credentials: dict[str, Any] = {"access_token": access_token, "email": email, "client_id": CLIENT_ID}
    for name in ("refresh_token", "id_token"):
        if _string(token.get(name)):
            credentials[name] = token[name]
    credentials.update({key: value for key, value in info.items() if key != "email" and value})
    received_at = time.time()
    expires_in = token.get("expires_in")
    try:
        duration = float(expires_in) if not isinstance(expires_in, bool) else 0
    except (ValueError, TypeError):
        duration = 0
    expires_at = None
    if math.isfinite(duration) and duration > 0:
        try:
            expiry = datetime.fromtimestamp(received_at + duration, timezone.utc)
            expires_at = int(expiry.timestamp())
        except (ValueError, OverflowError, OSError):
            pass
    if expires_at is None:
        expires_at = parse_datetime_to_unix(decode_jwt(access_token).get("exp"))
    if expires_at is None or expires_at <= received_at:
        raise ValueError("token 响应缺少有效 expires_in，access_token 也没有可用 exp")
    credentials["expires_at"] = expires_at
    account = _base_account(email, credentials)
    account["extra"][CPA_META_KEY] = {"disabled": False, "last_refresh": _format_cst(datetime.fromtimestamp(received_at, timezone.utc))}
    return account


def _validate_account(account: Any, *, infer: bool = False) -> None:
    if not isinstance(account, dict) or not isinstance(account.get("credentials"), dict):
        raise ValueError("sub2 账号 credentials 必须是对象")
    if _string(account.get("platform")) not in (("", "openai") if infer else ("openai",)):
        raise ValueError("仅支持 platform=openai 的账号")
    if _string(account.get("type")) not in (("", "oauth") if infer else ("oauth",)):
        raise ValueError("仅支持 type=oauth 的 sub2 账号")
    credentials = account["credentials"]
    if not any(_string(credentials.get(key)) for key in ("access_token", "refresh_token")):
        raise ValueError("账号缺少可用的 access_token 或 refresh_token")
    for key in ("access_token", "refresh_token", "id_token", "email", "chatgpt_account_id"):
        if key in credentials and credentials[key] is not None and not isinstance(credentials[key], str):
            raise ValueError(f"credentials.{key} 必须是字符串")
    if "extra" in account and not isinstance(account["extra"], dict):
        raise ValueError("sub2 账号 extra 必须是对象")
    for key in ("concurrency", "priority"):
        value = account.get(key, 1)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"{key} 必须是非负整数")
    rate = account.get("rate_multiplier", 1)
    if rate is not None and (isinstance(rate, bool) or not isinstance(rate, (int, float)) or not math.isfinite(rate) or rate < 0):
        raise ValueError("rate_multiplier 必须是非负数字")


def _validate_cpa(payload: Any) -> None:
    if not isinstance(payload, dict) or payload.get("type") != "codex":
        raise ValueError("CPA type 必须是 codex")
    if "disabled" in payload and not isinstance(payload["disabled"], bool):
        raise ValueError("CPA disabled 必须是布尔值")
    for key in CPA_FIELDS:
        if key != "disabled" and key in payload and payload[key] is not None and not isinstance(payload[key], str):
            raise ValueError(f"CPA {key} 必须是字符串")
    if not any(_string(payload.get(key)) for key in ("access_token", "refresh_token")):
        raise ValueError("CPA 缺少可用的 access_token 或 refresh_token")


def _cpa_metadata(account: dict[str, Any]) -> dict[str, Any]:
    extra = account.get("extra") or {}
    metadata = extra.get(CPA_META_KEY) if isinstance(extra, dict) else None
    return metadata if isinstance(metadata, dict) else {}


def _last_refresh_source(account: dict[str, Any]) -> tuple[str, Any]:
    credentials = account["credentials"]
    metadata = _cpa_metadata(account)
    recorded = metadata.get("last_refresh", credentials.get("last_refresh"))
    if recorded is not None and recorded != "":
        return "recorded", recorded
    issued_at = decode_jwt(_string(credentials.get("access_token"))).get("iat")
    if _parse_datetime(issued_at) is not None:
        return "access_iat", issued_at
    return "missing", None


def build_cpa_payload(account: dict[str, Any]) -> dict[str, Any]:
    _validate_account(account, infer=True)
    creds = account["credentials"]
    metadata = _cpa_metadata(account)
    info = _conversion_identity(account)
    email = info["email"]
    if not email:
        raise ValueError("转换 CPA 需要 email，不能将账号显示名称当作邮箱")
    expiry = creds.get("expires_at")
    if parse_datetime_to_unix(expiry) is None:
        expiry = decode_jwt(_string(creds.get("access_token"))).get("exp")
    original_expiry = metadata.get("expired")
    if parse_datetime_to_unix(original_expiry) == parse_datetime_to_unix(expiry) and _parse_datetime(original_expiry):
        expiry = original_expiry  # Keep source subsecond precision.
    disabled = metadata.get("disabled", (account.get("extra") or {}).get("disabled", False))
    if not isinstance(disabled, bool):
        raise ValueError("disabled 必须是布尔值")
    _, last_refresh = _last_refresh_source(account)
    return {"type": "codex", "email": email, "expired": _cpa_time(expiry),
            "id_token": _string(creds.get("id_token")), "account_id": info["chatgpt_account_id"],
            "disabled": disabled, "access_token": _string(creds.get("access_token")),
            "last_refresh": _cpa_time(last_refresh),
            "refresh_token": _string(creds.get("refresh_token"))}


def cpa_to_sub2_account(payload: dict[str, Any]) -> dict[str, Any]:
    _validate_cpa(payload)
    access_token, id_token = _string(payload.get("access_token")), _string(payload.get("id_token"))
    info = _conversion_user_info(id_token, access_token, marked=payload.get("id_token_synthetic") is True)
    email = _string(payload.get("email")) or info["email"]
    if not email:
        raise ValueError("CPA 缺少 email，且 token 中没有可读邮箱")
    credentials: dict[str, Any] = {"access_token": access_token, "email": email,
                                   "client_id": _string(payload.get("client_id")) or CLIENT_ID}
    credentials.update({key: value for key, value in info.items() if key != "email" and value})
    if _string(payload.get("account_id")):
        credentials["chatgpt_account_id"] = payload["account_id"].strip()
    elif _string(payload.get("chatgpt_account_id")):
        credentials["chatgpt_account_id"] = payload["chatgpt_account_id"].strip()
    for key, aliases in {"plan_type": ("plan_type", "chatgpt_plan_type"),
                         "chatgpt_user_id": ("chatgpt_user_id", "user_id"),
                         "organization_id": ("organization_id",)}.items():
        value = next((_string(payload.get(alias)) for alias in aliases if _string(payload.get(alias))), "")
        if value:
            credentials[key] = value
    for name in ("refresh_token", "id_token"):
        if _string(payload.get(name)):
            credentials[name] = payload[name]
    expires_at = parse_datetime_to_unix(payload.get("expired"))
    if expires_at is None:
        expires_at = parse_datetime_to_unix(decode_jwt(access_token).get("exp"))
    if expires_at is not None:
        credentials["expires_at"] = expires_at
    account = _base_account(email, credentials)
    metadata = {key: copy.deepcopy(payload[key]) for key in ("disabled", "last_refresh", "expired") if key in payload}
    unknown = {key: copy.deepcopy(value) for key, value in payload.items() if key not in CPA_FIELDS}
    if unknown:
        metadata["unmapped"] = unknown
    account["extra"][CPA_META_KEY] = metadata
    return account


def is_cpa_payload(data: Any) -> bool:
    return isinstance(data, dict) and data.get("type") == "codex" and "accounts" not in data and "credentials" not in data


def is_sub2_wrapper(data: Any) -> bool:
    return isinstance(data, dict) and isinstance(data.get("accounts"), list) and data.get("type", "") in ("", "sub2api-data", "sub2api-bundle")


def is_sub2_account_payload(data: Any) -> bool:
    return (isinstance(data, dict) and data.get("platform") == "openai" and data.get("type") == "oauth"
            and isinstance(data.get("credentials"), dict))


def is_sub2_payload(data: Any) -> bool:
    if isinstance(data, list):
        return bool(data) and all(is_sub2_wrapper(item) or is_sub2_account_payload(item) for item in data)
    return is_sub2_wrapper(data) or is_sub2_account_payload(data)


def _reject_constant(_value: str):
    raise ValueError("JSON 不允许 NaN 或 Infinity")


def _object_without_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("JSON 包含重复字段")
        result[key] = value
    return result


def load_json_file(path: str | Path) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8-sig"), parse_constant=_reject_constant, object_pairs_hook=_object_without_duplicates)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ValueError("JSON 文件编码或语法无效") from exc


def parse_json_documents(text: str) -> list[Any]:
    raw = (text or "").lstrip("\ufeff").strip()
    if not raw:
        raise ValueError("JSON 内容为空")
    decoder = json.JSONDecoder(parse_constant=_reject_constant, object_pairs_hook=_object_without_duplicates)
    docs, index = [], 0
    while index < len(raw):
        while index < len(raw) and (raw[index].isspace() or raw[index] == "\ufeff"):
            index += 1
        if index >= len(raw):
            break
        try:
            item, index = decoder.raw_decode(raw, index)
        except json.JSONDecodeError as exc:
            raise ValueError(f"JSON 解析失败：第 {exc.lineno} 行，第 {exc.colno} 列") from exc
        docs.append(item)
    return docs


def accounts_from_sub2_data(data: Any) -> Accounts:
    if isinstance(data, list):
        accounts = Accounts()
        for item in data:
            accounts.extend(accounts_from_sub2_data(item))
        if not accounts:
            raise ValueError("sub2 JSON 里没有账号")
        return accounts
    if is_sub2_wrapper(data):
        if isinstance(data.get("version", 1), bool) or data.get("version", 1) not in (0, 1):
            raise ValueError("不支持此 sub2 数据版本")
        if not isinstance(data.get("proxies", []), list):
            raise ValueError("sub2 proxies 必须是数组")
        values = data["accounts"]
        wrappers = [{key: copy.deepcopy(value) for key, value in data.items() if key != "accounts"}]
    elif is_sub2_account_payload(data):
        values, wrappers = [data], []
    else:
        raise ValueError("不是 OpenAI OAuth sub2 JSON")
    if not values:
        raise ValueError("sub2 JSON 里没有账号")
    accounts = Accounts(wrappers=wrappers)
    for index, value in enumerate(values, 1):
        try:
            _validate_account(value)
        except ValueError as exc:
            raise ValueError(f"第 {index} 条账号：{exc}") from exc
        if not _string(value.get("name")):
            raise ValueError(f"第 {index} 条账号缺少 name")
        accounts.append(copy.deepcopy(value))
    return accounts


def accounts_from_cpa_data(data: Any) -> Accounts:
    values = data if isinstance(data, list) else [data]
    if not values:
        raise ValueError("没有可用的 CPA 账号")
    accounts = Accounts()
    for index, item in enumerate(values, 1):
        try:
            account = cpa_to_sub2_account(item)
        except ValueError as exc:
            raise ValueError(f"第 {index} 条账号：{exc}") from exc
        info = _conversion_user_info(_string(item.get("id_token")), _string(item.get("access_token")),
                                    marked=item.get("id_token_synthetic") is True)
        if info["email"] and _string(item.get("email")) and info["email"].casefold() != item["email"].strip().casefold():
            accounts.warnings.append(f"第 {index} 条 CPA 邮箱与 token 声明不一致；保留显式邮箱，请核对来源。")
        if info["chatgpt_account_id"] and _string(item.get("account_id")) and info["chatgpt_account_id"] != item["account_id"].strip():
            accounts.warnings.append(f"第 {index} 条 CPA account_id 与 token 声明不一致；保留显式 account_id。")
        for field in ("expired", "last_refresh"):
            if item.get(field) and _parse_datetime(item[field]) is None:
                accounts.warnings.append(f"第 {index} 条 CPA {field} 无法解析或缺少时区；保留原始元数据，不猜测时间。")
        accounts.append(account)
    return accounts


def detect_payload_kind(data: Any) -> str | None:
    if is_sub2_payload(data):
        return "sub2"
    if is_cpa_payload(data) or (isinstance(data, list) and data and all(is_cpa_payload(item) for item in data)):
        return "cpa"
    return None


def parse_accounts_from_text(text: str, expected: str | None = None) -> tuple[str, Accounts]:
    docs = parse_json_documents(text)
    kinds = {detect_payload_kind(item) for item in docs}
    if None in kinds:
        raise ValueError("无法识别 JSON 格式；仅支持 OpenAI OAuth sub2 和 type=codex 的 CPA")
    if len(kinds) != 1:
        raise ValueError("多段 JSON 混合了 sub2 和 CPA，请分开转换")
    kind = kinds.pop()
    if expected and kind != expected:
        raise ValueError(f"当前内容是 {kind} 格式，请改选 {kind} 转换方向")
    accounts = Accounts()
    for item in docs:
        accounts.extend(accounts_from_sub2_data(item) if kind == "sub2" else accounts_from_cpa_data(item))
    return kind, accounts


def _load_accounts(path: str | Path, kind: str) -> Accounts:
    target = Path(path)
    if target.is_dir():
        files = sorted((p for p in target.iterdir() if p.is_file() and p.suffix.lower() == ".json"), key=lambda p: p.name.casefold())
    elif target.is_file():
        files = [target]
    else:
        raise ValueError("找不到输入文件或目录")
    if not files:
        raise ValueError("目录里没有 JSON 文件")
    accounts = Accounts()
    for index, file_path in enumerate(files, 1):
        try:
            data = load_json_file(file_path)
            accounts.extend(accounts_from_sub2_data(data) if kind == "sub2" else accounts_from_cpa_data(data))
        except (ValueError, OSError) as exc:
            if not target.is_dir():
                raise
            # File names may contain account identifiers: use sorted position only.
            reason = str(exc) if isinstance(exc, ValueError) else "无法读取文件"
            accounts.warnings.append(f"目录第 {index} 个 JSON 文件已跳过：{reason}")
    if not accounts:
        raise ValueError("目录内没有可用账号；" + "；".join(accounts.warnings))
    return accounts


def load_sub2_accounts(path: str | Path) -> Accounts:
    return _load_accounts(path, "sub2")


def load_cpa_accounts(path: str | Path) -> Accounts:
    return _load_accounts(path, "cpa")


def _merged_wrapper(accounts: list[dict[str, Any]]) -> dict[str, Any]:
    wrapper: dict[str, Any] = {}
    proxies: list[Any] = []
    proxy_keys: dict[str, Any] = {}
    for source in getattr(accounts, "wrappers", []):
        for key, value in source.items():
            if key == "proxies":
                for proxy in value:
                    if not isinstance(proxy, dict):
                        raise ValueError("sub2 proxies 只能包含对象")
                    proxy_key = _string(proxy.get("proxy_key"))
                    if proxy_key and proxy_key in proxy_keys and proxy_keys[proxy_key] != proxy:
                        raise ValueError("多个 sub2 文件的同名 proxy_key 配置冲突，无法安全合并")
                    if proxy not in proxies:
                        proxies.append(copy.deepcopy(proxy))
                    if proxy_key:
                        proxy_keys[proxy_key] = proxy
            elif key not in wrapper:
                wrapper[key] = copy.deepcopy(value)
            elif wrapper[key] != value and key not in ("exported_at", "type", "version"):
                raise ValueError("多个 sub2 wrapper 的扩展字段冲突，请分别转换")
    wrapper.setdefault("type", "sub2api-data")
    wrapper.setdefault("version", 1)
    wrapper.setdefault("exported_at", datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"))
    wrapper["proxies"] = proxies
    return wrapper


def build_export_payload(accounts: list[dict[str, Any]]) -> dict[str, Any]:
    wrapper = _merged_wrapper(accounts)
    for account in accounts:
        _validate_account(account)
    wrapper["accounts"] = copy.deepcopy(list(accounts))
    return wrapper


def account_conversion_status(account: dict[str, Any]) -> dict[str, str]:
    """A local summary, never a claim that a credential works online."""
    creds = account["credentials"]
    identity = _conversion_identity(account)
    recorded = parse_datetime_to_unix(creds.get("expires_at"))
    token_expiry = parse_datetime_to_unix(decode_jwt(_string(creds.get("access_token"))).get("exp"))
    expiry = recorded if recorded is not None else token_expiry
    candidates = [value for value in (recorded, token_expiry) if value is not None]
    state = "有效期未知"
    if candidates:
        state = "声明已过期" if min(candidates) <= time.time() else "声明未到期"
    conflict = recorded is not None and token_expiry is not None and recorded != token_expiry
    if conflict:
        state += " / 时间冲突"
    source = (account.get("extra") or {}).get(CONVERSION_META_KEY)
    source = source.get("source", "sub2 / CPA") if isinstance(source, dict) else "sub2 / CPA"
    return {"email": identity["email"] or "缺少邮箱", "account_id": identity["chatgpt_account_id"] or "缺少空间 ID",
            "expires": datetime.fromtimestamp(expiry, CST).strftime("%Y-%m-%d %H:%M:%S") if expiry is not None else "未知", "state": state,
            "refresh": "有刷新令牌（未验证）" if _string(creds.get("refresh_token")) else "缺少刷新令牌",
            "source": source}


def _credential_warnings(account: dict[str, Any], index: int) -> list[str]:
    creds = account["credentials"]
    access_token, id_token = _string(creds.get("access_token")), _string(creds.get("id_token"))
    prefix = f"第 {index} 条账号 "
    messages = []
    synthetic = _is_synthetic_token(id_token, _synthetic_marker(account))
    if synthetic:
        messages.append("id_token 为合成占位或无签名内容；仅保留原文，不用于补齐身份，不代表真实授权。标准 CPA 不承载顶层合成标记，请保留来源文件。")
    if not _string(creds.get("refresh_token")):
        messages.append("缺少 refresh_token；无法使用 OAuth 刷新令牌自动续期，access_token 到期后需要重新获取。")
    if not access_token:
        messages.append("缺少 access_token；需要目标工具支持使用 refresh_token 换票后才能调用。")
    identity = _conversion_identity(account)
    if not identity["chatgpt_account_id"]:
        messages.append("缺少 account_id / chatgpt_account_id，无法确定目标空间，部分目标可能无法使用。")
    if not identity["email"]:
        messages.append("缺少邮箱，不能导出标准 CPA。")
    # Read every source independently so explicit fields cannot hide disagreements.
    id_info = extract_user_info(id_token, "")
    access_info = _conversion_user_info("", access_token)
    for key in identity:
        values = [_string(creds.get(key)), id_info.get(key, ""), access_info.get(key, "")]
        if key == "email":
            values.extend((_string((account.get("extra") or {}).get("email")),
                           _string(account.get("name")) if "@" in _string(account.get("name")) else ""))
            values = [value.casefold() for value in values]
        if len({value for value in values if value}) > 1:
            messages.append(f"{key} 在显式字段、id_token 或 access_token 声明之间存在冲突；保留显式值，请核对来源与空间。")
    record_expiry = parse_datetime_to_unix(creds.get("expires_at"))
    token_expiry = parse_datetime_to_unix(decode_jwt(access_token).get("exp"))
    if creds.get("expires_at") not in (None, "") and record_expiry is None:
        messages.append("expires_at 无法解析或缺少时区；保留原值，不猜测时区。")
    if record_expiry is not None and token_expiry is not None and record_expiry != token_expiry:
        messages.append(f"到期时间冲突：记录为 {_cpa_time(record_expiry)}，access_token 声明为 {_cpa_time(token_expiry)}；保留记录值，转换不会延长实际有效期。")
    now = time.time()
    if token_expiry is not None and token_expiry <= now:
        messages.append("access_token 声明已过期；生成 JSON 不代表在线可用。")
    elif record_expiry is not None and record_expiry <= now:
        messages.append("记录的到期时间已过期；生成 JSON 不代表在线可用。")
    meta = (account.get("extra") or {}).get(CONVERSION_META_KEY)
    if isinstance(meta, dict):
        # Do not echo arbitrary imported warning strings (they may contain secrets).
        if meta.get("source") == "web_session":
            messages.append("来源为网页 Session；sessionToken 不能代替 refresh_token，转换不会增加 API 权限。")
        if meta.get("source") in ("web_session", "9router") and _string(creds.get("refresh_token")) and not _string(creds.get("client_id")):
            messages.append("来源未提供 client_id；未强行套用 Codex 客户端，目标工具的刷新客户端兼容性需核对。")
    return [prefix + message for message in messages]


def conversion_warnings(accounts: list[dict[str, Any]], target: str) -> list[str]:
    """Return warnings without printing account identifiers or token values."""
    messages = list(getattr(accounts, "warnings", []))
    if target not in ("sub2", "cpa"):
        raise ValueError("未知输出格式")
    lost: set[str] = set()
    if target == "cpa" and getattr(accounts, "wrappers", []):
        messages.append("CPA 固定九字段不保留 sub2 wrapper 元数据和 proxies；输出不生成附加备份。")
    for index, account in enumerate(accounts, 1):
        creds = account.get("credentials") or {}
        metadata = _cpa_metadata(account)
        messages.extend(_credential_warnings(account, index))
        if target == "cpa":
            payload = build_cpa_payload(account)
            refresh_source, _ = _last_refresh_source(account)
            if refresh_source == "access_iat":
                messages.append(f"第 {index} 条账号 last_refresh 源字段缺失，按 access_token 的签发时间 iat 推算；这是签发时间近似，不能确认为实际刷新时间。")
            lost.update("account." + key for key in account if key not in ("name", "platform", "type", "credentials", "extra"))
            if account.get("name") != payload["email"]:
                lost.add("account.name")
            lost.update("credentials." + key for key in creds if key not in ("access_token", "refresh_token", "id_token", "email", "chatgpt_account_id", "expires_at", "last_refresh"))
            lost.update("extra." + key for key in (account.get("extra") or {}) if key not in ("email", "disabled", CPA_META_KEY))
            if metadata.get("unmapped"):
                lost.add("CPA 非标准扩展字段")
            for field in ("expired", "last_refresh"):
                if not payload[field]:
                    messages.append(f"第 {index} 条账号缺少可靠的 {field}，输出空字符串；不生成虚假时间，目标 CPA 可能要求补齐。")
        else:
            if metadata.get("disabled") is True or (account.get("extra") or {}).get("disabled") is True:
                messages.append(f"第 {index} 条账号 disabled=true 仅保存在 extra 元数据；本地 sub2 导入器不支持导入禁用状态，导入后必须手动停用。")
            if parse_datetime_to_unix(creds.get("expires_at")) is None:
                messages.append(f"第 {index} 条账号没有可靠的 token 到期时间；不生成虚假 expires_at。")
            if account.get("proxy_key") and not any(source.get("proxies") for source in getattr(accounts, "wrappers", [])):
                messages.append(f"第 {index} 条账号引用 proxy_key，但没有代理定义；仅当目标 sub2 已有匹配代理时才能导入。")
    if lost:
        messages.append("转换为标准 CPA 将丢失这些字段（反向转换无法恢复）：" + ", ".join(sorted(lost)))
    return list(dict.fromkeys(messages))


def safe_email_filename(email: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._@+-]+", "_", email.strip()).strip(" .") or "account"
    if cleaned.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}:
        cleaned = "_" + cleaned
    return cleaned[:140].rstrip(" .") or "account"


def _atomic_write_json(path: Path, payload: Any, *, overwrite: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    descriptor, temporary = tempfile.mkstemp(prefix=".reauth-", suffix=".tmp", dir=path.parent)
    temp_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if overwrite:
            os.replace(temp_path, path)
        else:
            if os.name == "nt":
                # Windows rename atomically publishes and never replaces a file.
                os.rename(temp_path, path)
            else:
                # Unix rename replaces; a same-volume hard link fails if occupied.
                os.link(temp_path, path)
    finally:
        temp_path.unlink(missing_ok=True)


def write_export_file(path: str | Path, accounts: list[dict[str, Any]]) -> Path:
    output = Path(path)
    _atomic_write_json(output, build_export_payload(accounts), overwrite=True)
    return output


def write_cpa_files(output_dir: str | Path, accounts: list[dict[str, Any]]) -> list[Path]:
    folder = Path(output_dir)
    folder.mkdir(parents=True, exist_ok=True)
    # Validate the entire batch before creating any output files.
    payloads = [build_cpa_payload(account) for account in accounts]
    used = {p.name.casefold() for p in folder.iterdir()}
    written: list[Path] = []
    for payload in payloads:
        stem = safe_email_filename(payload["email"])
        suffix = 1
        while True:
            filename = f"{stem}.json" if suffix == 1 else f"{stem}__{suffix}.json"
            if filename.casefold() in used:
                suffix += 1
                continue
            path = folder / filename
            try:
                _atomic_write_json(path, payload, overwrite=False)
            except FileExistsError:
                used.add(filename.casefold())
                suffix += 1
                continue
            used.add(filename.casefold())
            written.append(path)
            break
    return written
