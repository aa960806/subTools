"""Shared login input parsing. Parsing never contacts an account or mailbox."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

import pyotp

from reauth_formats import _object_without_duplicates, _reject_constant


@dataclass
class AccountInput:
    email: str
    password: str = field(repr=False)
    totp_secret: str = field(repr=False)
    source_line: int
    mailbox_url: str = field(default="", repr=False)
    oauth_account: dict | None = field(default=None, repr=False)
    refresh_state: str = ""


def _email(value):
    value = re.sub(r"\\([@_.-])", r"\1", str(value or "").strip())
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
        raise ValueError("账号缺少有效邮箱")
    return value


def _totp(value):
    value = re.sub(r"\s+", "", value or "").upper()
    if value:
        try:
            pyotp.TOTP(value).byte_secret()
        except Exception:
            raise ValueError("2FA 密钥必须为有效的 Base32 密钥") from None
    return value


def _mailbox(value, email):
    from phone_mailbox import MailboxError, validate_mailbox_url
    try:
        return validate_mailbox_url(value, email)
    except MailboxError as exc:
        raise ValueError(str(exc)) from None


def parse_account_line(line: str, source_line: int = 0) -> AccountInput:
    raw = line.strip().lstrip("\ufeff")
    if not raw or raw.startswith("#"):
        raise ValueError("empty")
    delimiter = "----" if "----" in raw else "\t"
    parts = raw.split(delimiter)
    if len(parts) < 2:
        return AccountInput(_email(raw), "", "", source_line)
    email = _email(parts[0])
    def mailbox_candidate(value):
        candidate = value.strip()
        markdown = re.fullmatch(r"\[[^\r\n]*\]\((https?://[^\s]+)\)", candidate)
        if markdown:
            candidate = markdown.group(1)
        return candidate if candidate.lower().startswith(("http://", "https://")) else ""

    mailbox_fields = [(index, mailbox_candidate(value)) for index, value in enumerate(parts[1:], 1)
                      if mailbox_candidate(value)]
    if mailbox_fields:
        if len(mailbox_fields) != 1:
            raise ValueError("每个账号只能提供一个邮箱接码地址；复杂密码请使用 JSON")
        position, url = mailbox_fields[0]
        if position not in (len(parts) - 1, len(parts) - 2):
            raise ValueError("邮箱接码地址应放在末尾或 2FA 前；复杂密码请使用 JSON")
        fields = parts[1:position]
        if position == len(parts) - 2:
            totp = _totp(parts[-1])
        else:
            totp = _totp(fields.pop()) if len(fields) > 1 else ""
        password = delimiter.join(fields)
        return AccountInput(email, password, totp, source_line, _mailbox(url, email))
    if len(parts) >= 3:
        # Keep delimiters inside passwords; the final component must be a real TOTP key.
        password, totp = delimiter.join(parts[1:-1]), _totp(parts[-1])
        if not password or not totp:
            raise ValueError("密码和 2FA 密钥不能为空；无 2FA 请使用两段格式")
        return AccountInput(email, password, totp, source_line)
    password = parts[1]
    if not password:
        raise ValueError("密码或邮箱接码地址不能为空")
    candidate = password.strip()
    markdown = re.fullmatch(r"\[[^\r\n]*\]\((https?://[^\s]+)\)", candidate)
    if markdown:
        candidate = markdown.group(1)
    if candidate.lower().startswith(("http://", "https://")):
        return AccountInput(email, "", "", source_line, _mailbox(candidate, email))
    return AccountInput(email, password, "", source_line)


def account_input_from_mapping(account: dict, source_line: int = 0, *, include_oauth=True) -> AccountInput:
    if account.get("platform") and str(account["platform"]).lower() != "openai":
        raise ValueError("仅支持 OpenAI 账号")
    def mapping(value):
        return value if isinstance(value, dict) else {}
    creds, extra = mapping(account.get("credentials")), mapping(account.get("extra"))
    meta = mapping(extra.get("openai_reauth_cpa"))
    sources = (extra, creds, account, mapping(meta.get("unmapped")), meta,
               mapping(account.get("user")), mapping(account.get("providerSpecificData")))
    def secret(*keys):
        return next((source[key] for source in sources for key in keys
                     if isinstance(source.get(key), str) and source[key].strip()), "")
    named = None
    name = account.get("name")
    if isinstance(name, str) and "----" in name:
        named = parse_account_line(name, source_line)
    oauth_account = None
    if include_oauth and secret("refresh_token", "refreshToken"):
        from reauth_conversion import parse_conversion_text
        from reauth_formats import _conversion_identity
        _, converted = parse_conversion_text(json.dumps(account, ensure_ascii=False))
        oauth_account = converted[0]
        inferred_email = _conversion_identity(oauth_account)["email"]
    else:
        inferred_email = ""
    email = _email(creds.get("email") or secret("email") or (named.email if named else inferred_email or name))
    if named and email.casefold() != named.email.casefold():
        raise ValueError("name 中的登录邮箱与账号邮箱冲突")
    password = secret("password", "login_password") or (named.password if named else "")
    totp = _totp(secret("totp_secret", "totp", "otp_secret", "2fa", "two_factor_secret")
                 or (named.totp_secret if named else ""))
    mailbox = secret("mailbox_url", "email_code_url") or (named.mailbox_url if named else "")
    return AccountInput(email, password, totp, source_line, _mailbox(mailbox, email) if mailbox else "", oauth_account)


def input_records(text: str):
    """Yield (line, account mapping or text) from mixed JSON and account lines."""
    raw = (text or "").lstrip("\ufeff")
    decoder = json.JSONDecoder(parse_constant=_reject_constant, object_pairs_hook=_object_without_duplicates)
    def flatten(value, line):
        if isinstance(value, list):
            for item in value:
                yield from flatten(item, line)
        elif isinstance(value, dict):
            if "accounts" in value:
                if not isinstance(value["accounts"], list):
                    raise ValueError("accounts 必须是账号数组")
                yield from flatten(value["accounts"], line)
            else:
                yield line, value
        else:
            raise ValueError("JSON 账号必须是对象，不能包含空值或文本")
    offset = 0
    while offset < len(raw):
        if raw[offset].isspace() or raw[offset] == "\ufeff":
            offset += 1
            continue
        line = raw.count("\n", 0, offset) + 1
        if raw[offset] in "{[":
            try:
                value, end = decoder.raw_decode(raw, offset)
            except json.JSONDecodeError as exc:
                raise ValueError(f"JSON 第 {exc.lineno} 行、第 {exc.colno} 列语法无效") from None
            yield from flatten(value, line)
        else:
            end = raw.find("\n", offset)
            if end < 0:
                end = len(raw)
            if raw[offset] != "#":
                yield line, raw[offset:end]
        offset = end


def parse_accounts_text(text: str, *, include_oauth=True):
    accounts, errors = [], []
    try:
        for line, value in input_records(text):
            try:
                accounts.append(account_input_from_mapping(value, line, include_oauth=include_oauth) if isinstance(value, dict)
                                else parse_account_line(value, line))
            except ValueError as exc:
                errors.append(f"第 {line} 行: {exc}")
    except ValueError as exc:
        errors.append(str(exc))
    return accounts, errors


def load_accounts(text: str, *, include_oauth=True) -> list[AccountInput]:
    accounts, errors = parse_accounts_text(text, include_oauth=include_oauth)
    if errors:
        raise ValueError("输入格式无效:\n  " + "\n  ".join(errors))
    if not accounts:
        raise ValueError("没有识别到账号，请粘贴或导入账号 JSON / 文本")
    return accounts


def login_mapping(account: AccountInput) -> dict:
    """For in-memory page handoff or an encrypted journal only."""
    return {"platform": "openai", "email": account.email, "password": account.password,
            "totp_secret": account.totp_secret, "mailbox_url": account.mailbox_url}


def login_description(account: AccountInput) -> str:
    method = "邮箱验证码" if account.mailbox_url and not account.password else "密码" if account.password else "浏览器手动登录"
    return f"需要 OAuth 登录 · {method}" + (" + 2FA" if account.totp_secret else "")
