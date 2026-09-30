"""Read login codes from the account owner's mailbox link.

Mailbox URLs are credentials. This module never logs URLs, message contents or codes.
Only the documented mailbox JSON endpoints are read; email HTML is treated as text.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from email.utils import parseaddr, parsedate_to_datetime
from html.parser import HTMLParser
from typing import Callable
from urllib.parse import quote, unquote, unquote_to_bytes, urlencode, urlsplit

import httpx


class MailboxError(RuntimeError):
    def __init__(self, category: str, message: str) -> None:
        super().__init__(message)
        self.category = category


@dataclass(frozen=True)
class MailboxBaseline:
    ids: frozenset[str] = field(default_factory=frozenset, repr=False)
    codes: frozenset[str] = field(default_factory=frozenset, repr=False)


def validate_mailbox_url(url: str, email: str) -> str:
    """Validate the known mailbox-link shape and the exact recipient."""
    try:
        parsed = urlsplit(str(url).strip())
        parts = parsed.path.split("/")
        valid = (
            parsed.scheme in {"http", "https"}
            and bool(parsed.hostname)
            and parsed.username is None and parsed.password is None
            and not parsed.query and not parsed.fragment
            and len(parts) == 4 and parts[1] == "messages"
            and re.fullmatch(r"[A-Za-z0-9_-]{8,256}", parts[2]) is not None
            and unquote(parts[3]).casefold() == str(email).strip().casefold()
            and re.fullmatch(r"[^\s/@]+@[^\s/@]+\.[^\s/@]+", str(email).strip()) is not None
            and not any(ch in str(url) for ch in "\r\n\t\\")
        )
        parsed.port  # Validate an explicit port before any request.
    except (ValueError, TypeError):
        valid = False
    if not valid:
        raise MailboxError("mailbox_input", "邮箱接码地址无效或与账号邮箱不一致")
    return parsed.geturl()


class _MessageText(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag.lower() in {"script", "style"}:
            self.hidden += 1

    def handle_endtag(self, tag):
        if tag.lower() in {"script", "style"} and self.hidden:
            self.hidden -= 1
        if not self.hidden:
            self.parts.append(" ")

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def _login_message(message: dict) -> bool:
    sender = parseaddr(str(message.get("from_address") or message.get("fromAddress") or message.get("from") or ""))[1].casefold()
    _, _, domain = sender.rpartition("@")
    direct = domain == "openai.com" or domain.endswith(".openai.com")
    # iCloud Hide My Email preserves the original sender in this documented form.
    forwarded = re.fullmatch(r"noreply_at_(?:tm_)?openai_com_[a-z0-9_]+@icloud\.com", sender) is not None
    subject = str(message.get("subject") or "").casefold()
    brand = "openai" in subject or "chatgpt" in subject
    code_subject = re.search(r"\bcode\b|验证码|登录代码|登入代码", subject) is not None
    unrelated = re.search(r"password.{0,15}reset|reset.{0,15}password|重置密码|密码重置|phone|手机号|短信", subject) is not None
    return (direct or forwarded) and brand and code_subject and not unrelated


def _aware_timestamp(value: object) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = parsedate_to_datetime(text)
        except (ValueError, TypeError, OverflowError):
            return None
    # The mailbox also returns local dates with no timezone; don't invent one.
    return parsed.timestamp() if parsed.tzinfo is not None else None


class MailboxClient:
    def __init__(self, url: str, email: str, proxy: str | None = None, *, client: httpx.Client | None = None) -> None:
        parsed = urlsplit(validate_mailbox_url(url, email))
        self.email = str(email).strip().casefold()
        self._origin = f"{parsed.scheme}://{parsed.netloc}"
        _, _, token, recipient = parsed.path.split("/")
        self._suffix = f"{token}/{quote(unquote(recipient), safe='@._-')}"
        # This provider documents a separate read-only JSON endpoint. Build it
        # directly; never follow the mailbox page's redirect or send its token
        # to a different origin.
        self._simple_api_path = None
        if parsed.hostname == "msg.linlanyu.com":
            self._simple_api_path = "/api/messages?" + urlencode({
                "token": token, "email": unquote(recipient), "limit": 1, "simple": 1,
            })
        self._owned_client = client is None
        self._client = client or httpx.Client(proxy=proxy or None, follow_redirects=False, timeout=10.0, trust_env=False)
        self.poll_interval = 2.0

    def close(self) -> None:
        if self._owned_client:
            self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _get(self, path: str, deadline: float | None = None, *, as_json: bool = True):
        remaining = 10.0 if deadline is None else deadline - time.monotonic()
        if remaining <= 0:
            raise MailboxError("mailbox_timeout", "等待邮箱验证码超时")
        try:
            response = self._client.get(self._origin + path, timeout=min(10.0, remaining), follow_redirects=False)
            if response.status_code in {401, 403, 404}:
                raise MailboxError("mailbox_access", "邮箱接码地址不可访问或已失效")
            if response.is_redirect:
                raise MailboxError("mailbox_access", "邮箱接码接口发生重定向，请检查地址")
            response.raise_for_status()
            if len(response.content) > 2_000_000:
                raise MailboxError("mailbox_response", "邮箱接码接口响应过大")
            return response.json() if as_json else response.text
        except MailboxError:
            raise
        except (httpx.HTTPError, ValueError, UnicodeError):
            raise MailboxError("mailbox_network", "邮箱接码接口请求失败，请检查网络或服务状态") from None

    def _items(self, deadline: float | None = None) -> list[dict]:
        if self._simple_api_path is not None:
            return self._simple_items(deadline)
        payload = self._get(f"/api/messages/{self._suffix}", deadline)
        if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
            raise MailboxError("mailbox_response", "邮箱接码接口返回格式无法识别")
        return [item for item in payload["items"][:100] if isinstance(item, dict)]

    def _simple_items(self, deadline: float | None) -> list[dict]:
        payload = self._get(self._simple_api_path, deadline)
        data = payload.get("data") if isinstance(payload, dict) else None
        if (not isinstance(payload, dict) or payload.get("success") is not True
                or not isinstance(data, dict)
                or not isinstance(data.get("email"), str)
                or data["email"].strip().casefold() != self.email
                or type(data.get("hasMail")) is not bool):
            raise MailboxError("mailbox_response", "邮箱接码接口返回格式或收件人不匹配")
        if not data["hasMail"]:
            return []
        if not all(isinstance(data.get(key), str) for key in ("code", "from", "subject", "receivedAt")):
            raise MailboxError("mailbox_response", "邮箱接码接口返回邮件格式无法识别")
        message = {
            "recipient": data["email"], "from_address": data["from"],
            "subject": data["subject"], "received_at": data["receivedAt"],
        }
        if not _login_message(message):
            return []
        if (re.fullmatch(r"[0-9]{6}", data["code"]) is None
                or _aware_timestamp(data["receivedAt"]) is None):
            raise MailboxError("mailbox_response", "邮箱接码接口返回验证码或邮件时间无效")
        subject_codes = set(re.findall(r"(?<!\d)\d{6}(?!\d)", data["subject"]))
        if subject_codes and subject_codes != {data["code"]}:
            raise MailboxError("mailbox_response", "邮箱接码接口返回验证码不一致")
        identity = json.dumps([self.email, data["from"], data["subject"],
                               data["receivedAt"], data["code"]], ensure_ascii=False)
        message["id"] = hashlib.sha256(identity.encode("utf-8")).hexdigest()
        message["_provided_code"] = data["code"]
        return [message]

    def _belongs_to_account(self, message: dict) -> bool:
        # This service uses "mailbox" for the folder (INBOX/JUNK), not the
        # recipient. The URL already scopes all requests to this account.
        # Only an explicit recipient address may further restrict a message.
        for key in ("recipient", "email", "address", "to_address", "toAddress"):
            value = message.get(key)
            if value:
                address = parseaddr(str(value))[1].strip().casefold()
                if address != self.email:
                    return False
        return True

    @staticmethod
    def _id(message: dict) -> str:
        value = str(message.get("id", ""))
        return value if re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value) else ""

    def _body_text(self, body: str, is_html: bool, deadline: float | None) -> str:
        if body.startswith("data:"):
            try:
                header, data = body.split(",", 1)
                if not re.fullmatch(r"data:text/(?:html|plain)(?:;charset=[A-Za-z0-9_-]+)?(?:;base64)?", header, re.I):
                    return ""
                raw = base64.b64decode(data, validate=True) if header.lower().endswith(";base64") else unquote_to_bytes(data)
                if len(raw) > 2_000_000:
                    return ""
                body = raw.decode("utf-8", errors="replace")
                is_html = "text/html" in header.lower()
            except (ValueError, binascii.Error):
                return ""
        elif is_html and (body.startswith(("http://", "https://", "/"))):
            parsed = urlsplit(body)
            if (parsed.scheme or parsed.netloc) and f"{parsed.scheme}://{parsed.netloc}" != self._origin:
                return ""
            if parsed.fragment or parsed.query or not parsed.path.startswith("/") or parsed.path.startswith("//"):
                return ""
            body = self._get(parsed.path, deadline, as_json=False)
        if not is_html:
            return body
        parser = _MessageText()
        parser.feed(body)
        return " ".join(parser.parts)

    def _codes(self, item: dict, deadline: float | None = None) -> set[str]:
        if not self._belongs_to_account(item) or not _login_message(item):
            return set()
        if self._simple_api_path is not None:
            code = item.get("_provided_code")
            return {code} if isinstance(code, str) and re.fullmatch(r"[0-9]{6}", code) else set()
        subject_codes = set(re.findall(r"(?<!\d)\d{6}(?!\d)", str(item.get("subject") or "")))
        if subject_codes:
            return subject_codes
        message_id = self._id(item)
        if not message_id:
            return set()
        detail = self._get(f"/message/{message_id}/{self._suffix}", deadline)
        if not isinstance(detail, dict) or not self._belongs_to_account(detail) or not _login_message(detail):
            return set()
        body = self._body_text(str(detail.get("body") or ""), bool(detail.get("html", detail.get("is_html", False))), deadline)
        return set(re.findall(r"(?<!\d)\d{6}(?!\d)", body))

    def snapshot(self, deadline: float | None = None,
                 should_stop: Callable[[], bool] | None = None) -> MailboxBaseline:
        deadline = deadline if deadline is not None else time.monotonic() + 30.0
        stop = should_stop or (lambda: False)
        if stop():
            raise MailboxError("cancelled", "邮箱验证码读取已停止")
        items = self._items(deadline)
        ids = frozenset(self._id(item) for item in items if self._id(item))
        codes: set[str] = set()
        detail_count = 0
        for item in items:
            if stop():
                raise MailboxError("cancelled", "邮箱验证码读取已停止")
            if not self._belongs_to_account(item) or not _login_message(item):
                continue
            # IDs cover every listed message. Limit old body requests because a
            # large inbox must not postpone the actual login for many minutes.
            if not re.search(r"(?<!\d)\d{6}(?!\d)", str(item.get("subject") or "")):
                detail_count += 1
                if detail_count > 10:
                    continue
            codes.update(self._codes(item, deadline))
        return MailboxBaseline(ids=ids, codes=frozenset(codes))

    def wait_for_code(self, baseline: MailboxBaseline, issued_after: float, deadline: float,
                      should_stop: Callable[[], bool] | None = None) -> str | None:
        """Poll until a new login code arrives. deadline uses time.monotonic().

        issued_after is Unix time. A missing timezone is not guessed: new IDs and
        baseline codes establish freshness when the server's date is ambiguous.
        """
        stop = should_stop or (lambda: False)
        old_max = max((int(value) for value in baseline.ids if value.isdigit()), default=-1)
        network_failures = 0
        while time.monotonic() < deadline and not stop():
            try:
                for item in self._items(deadline):
                    if stop() or time.monotonic() >= deadline:
                        return None
                    message_id = self._id(item)
                    if not message_id or message_id in baseline.ids:
                        continue
                    if message_id.isdigit() and int(message_id) <= old_max:
                        continue
                    timestamp = _aware_timestamp(item.get("received_at", item.get("receivedAt")))
                    # The latest-message provider has no server message id.
                    # Require its timezone-aware receipt time to be at least
                    # the current login's start, in addition to the baseline.
                    slack = 0 if self._simple_api_path is not None else 5
                    if timestamp is not None and timestamp < issued_after - slack:
                        continue
                    codes = self._codes(item, deadline) - baseline.codes
                    # Multiple distinct six-digit values are ambiguous; never guess.
                    if len(codes) == 1:
                        return next(iter(codes))
                network_failures = 0
            except MailboxError as exc:
                if exc.category == "mailbox_timeout":
                    return None
                network_failures += 1
                if exc.category != "mailbox_network" or network_failures >= 3:
                    raise
            pause_until = min(deadline, time.monotonic() + self.poll_interval)
            while time.monotonic() < pause_until and not stop():
                time.sleep(min(0.1, max(0.0, pause_until - time.monotonic())))
        return None
