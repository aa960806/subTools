"""Isolated registration orchestration boundary.

The web application can manage registration jobs without importing the old
desktop projects.  The default adapter is deliberately non-networked; a
deployment may provide an explicitly reviewed adapter through
``run_batch_registration(..., adapter=...)``.  This keeps the task lifecycle,
mailbox freshness and recovery rules testable without embedding a challenge
solver or silently replaying an uncertain signup request.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import string
import time
import uuid
from datetime import date
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol
from urllib.parse import urlsplit

import httpx

from account_inputs import input_records
from phone_mailbox import MailboxClient, MailboxError, validate_mailbox_url
from flow_control import check_running
from registration_policy import graph_message_codes, session_candidate


EMAIL_RE = re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]+")


def validate_registration_url(value: str) -> str:
    """Never send registration credentials to a configurable third-party page."""
    try:
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or parsed.netloc not in {"chatgpt.com", "auth.openai.com"}
                or parsed.username or parsed.password or parsed.fragment
                or "\\" in value or any(c.isspace() for c in value)):
            raise ValueError
    except (ValueError, TypeError):
        raise ValueError("注册页面仅支持 https://chatgpt.com 或 https://auth.openai.com") from None
    return value


class RegistrationPersistenceError(RuntimeError):
    """No further side effects are allowed after a checkpoint write fails."""


def registration_needs_review(checkpoint):
    return bool(checkpoint and (checkpoint.get("create_confirmed")
        or any((checkpoint.get("side_effects") or {}).values())
        or checkpoint.get("stage", "created") not in {"created", "mailbox_ready", "sentinel", "identity_ready"}))
REGISTRATION_STAGES = (
    "mailbox_ready",
    "sentinel",
    "identity_ready",
    "auth_flow",
    "user_register",
    "email_otp_send",
    "email_otp_wait",
    "email_otp_validate",
    "create_account",
    "auth_session",
    "totp_enroll",
    "access_token_probe",
    "finalize",
)


@dataclass
class RegistrationInput:
    email: str
    password: str = field(default="", repr=False)
    totp_secret: str = field(default="", repr=False)
    mailbox_url: str = field(default="", repr=False)
    mailbox_client_id: str = field(default="", repr=False)
    mailbox_refresh_token: str = field(default="", repr=False)
    name: str = ""
    birthdate: str = ""
    source_line: int = 0
    checkpoint: dict[str, Any] = field(default_factory=dict, repr=False)


@dataclass
class RegistrationResult:
    email: str
    ok: bool = False
    category: str = "failed"
    error: str = ""
    account: dict[str, Any] | None = field(default=None, repr=False)
    registration_state: str = "failed"
    checkpoint: dict[str, Any] = field(default_factory=dict, repr=False)


class RegistrationAdapter(Protocol):
    def register(
        self,
        item: RegistrationInput,
        *,
        config: dict[str, Any],
        should_stop: Callable[[], bool],
        on_stage: Callable[[str], None],
        checkpoint: dict[str, Any],
        on_checkpoint: Callable[[dict[str, Any]], None] | None = None,
    ) -> RegistrationResult: ...


def _email(value: Any) -> str:
    candidate = str(value or "").strip()
    if not EMAIL_RE.fullmatch(candidate):
        raise ValueError("注册记录缺少有效邮箱")
    return candidate


def _mailbox(value: Any, email: str) -> str:
    try:
        return validate_mailbox_url(str(value or ""), email)
    except MailboxError as exc:
        raise ValueError(str(exc)) from None


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _registration_entry_failure(
    status: int,
    body: str,
    *,
    title: str = "",
    url: str = "",
) -> tuple[str, str] | None:
    """Classify a registration entry page before any email is submitted.

    A blocked page often has an empty body (or only a browser title), so the
    response status, title, URL and body are considered together.  The
    diagnostic deliberately returns a stable, non-secret message and never
    includes the page content.
    """
    text = " ".join((str(body or ""), str(title or ""), str(url or ""))).casefold()
    if status == 429:
        return "rate_limited", "注册入口返回 HTTP 429，站点暂时限流；未提交邮箱"
    hard_block_markers = (
        "unable to load site",
        "if you are using a vpn",
        "try turning it off",
        "access denied",
        "sorry, you have been blocked",
        "this website is using a security service",
    )
    challenge_markers = (
        "just a moment",
        "attention required",
        "checking your browser",
        "verify you are human",
        "enable javascript and cookies to continue",
        "performing security verification",
        "cloudflare ray id",
        "__cf_chl",
        "challenges.cloudflare.com",
    )
    if any(marker in text for marker in challenge_markers):
        return "needs_interaction", "注册入口要求完成浏览器安全验证；未提交邮箱"
    if status in (403, 407) or any(marker in text for marker in hard_block_markers):
        return "uncertain", f"注册入口拒绝当前网络请求 (HTTP {status or 'unknown'})；未提交邮箱，请检查网络或代理"
    if status >= 500:
        return "uncertain", f"注册入口暂时不可用 (HTTP {status})；未提交邮箱"
    return None


def _parse_value(value: Any, line: int) -> RegistrationInput:
    if isinstance(value, dict):
        sources = (_mapping(value.get("registration")), _mapping(value))

        def pick(*keys: str) -> str:
            for source in sources:
                candidate = source.get(keys[0]) if len(keys) == 1 else next(
                    (source.get(key) for key in keys if source.get(key)), None
                )
                if isinstance(candidate, str) and candidate.strip():
                    return candidate.strip()
            return ""

        email = _email(pick("email"))
        mailbox = pick("mailbox_url", "email_code_url", "mailbox")
        client_id = pick("mailbox_client_id", "client_id")
        refresh_token = pick("mailbox_refresh_token", "refresh_token")
        if client_id and refresh_token:
            return RegistrationInput(email=email, password=pick("registration_password", "openai_password"),
                                    mailbox_client_id=client_id, mailbox_refresh_token=refresh_token,
                                    name=pick("name", "full_name"), birthdate=pick("birthdate", "date_of_birth"),
                                    source_line=line)
        if not mailbox:
            raise ValueError("注册记录必须提供邮箱接码地址")
        return RegistrationInput(
            email=email,
            password=pick("password", "login_password"),
            mailbox_url=_mailbox(mailbox, email),
            name=pick("name", "full_name"),
            birthdate=pick("birthdate", "date_of_birth"),
            source_line=line,
        )

    raw = str(value or "").strip()
    if not raw or raw.startswith("#"):
        raise ValueError("empty")
    delimiter = "----" if "----" in raw else "\t"
    parts = [part.strip() for part in raw.split(delimiter)]
    email = _email(parts[0])
    if len(parts) == 4 and re.fullmatch(r"[0-9a-fA-F-]{36}", parts[2] or "") and parts[3]:
        return RegistrationInput(email=email, mailbox_client_id=parts[2],
                                 mailbox_refresh_token=parts[3], source_line=line)
    urls = [part for part in parts[1:] if part.lower().startswith(("http://", "https://"))]
    if len(urls) != 1:
        raise ValueError("注册记录必须包含一个邮箱接码地址")
    mailbox = urls[0]
    password_parts = [part for part in parts[1:] if part != mailbox]
    password = delimiter.join(password_parts).strip()
    return RegistrationInput(email=email, password=password, mailbox_url=_mailbox(mailbox, email), source_line=line)


def load_registration_inputs(text: str | dict[str, Any], max_accounts: int = 200) -> list[RegistrationInput]:
    """Parse registration text or one registration mapping.

    The web endpoint supplies text, while callers importing a JSON record may
    already have a decoded mapping.  Supporting both keeps the parser's
    validation rules identical and avoids treating mailbox credentials as the
    OpenAI registration password.
    """
    items: list[RegistrationInput] = []
    errors: list[str] = []
    if isinstance(text, dict):
        try:
            items.append(_parse_value(text, 1))
        except ValueError as exc:
            errors.append(f"第 1 行: {exc}")
    elif isinstance(text, str):
        try:
            for index, (line, value) in enumerate(input_records(text), 1):
                if len(items) >= max_accounts:
                    raise ValueError(f"单批最多 {max_accounts} 条注册记录")
                try:
                    items.append(_parse_value(value, line))
                except ValueError as exc:
                    errors.append(f"第 {line} 行: {exc}")
        except ValueError as exc:
            errors.append(str(exc))
    else:
        errors.append("注册输入必须是文本或对象")
    if errors:
        raise ValueError("输入格式无效:\n  " + "\n  ".join(errors))
    if not items:
        raise ValueError("没有识别到注册记录")
    emails = [item.email.casefold() for item in items]
    if len(emails) != len(set(emails)):
        raise ValueError("注册输入包含重复邮箱")
    return items


def registration_fingerprint(text: str) -> str:
    return hashlib.sha256(str(text).encode("utf-8")).hexdigest()


def _checkpoint(
    item: RegistrationInput,
    stage: str,
    *,
    state: str,
    error: str = "",
    **extra: Any,
) -> dict[str, Any]:
    payload = {
        "version": 1,
        "email": item.email,
        "stage": stage,
        "state": state,
        "registration_state": state,
        "error": str(error or "")[:300],
        "updated_at": int(time.time()),
    }
    for key, value in extra.items():
        if value is not None:
            payload[key] = value
    return payload


class SafeRegistrationAdapter:
    """Fixture adapter used by tests and local UI verification only."""

    def register(self, item, *, config, should_stop, on_stage, checkpoint, on_checkpoint=None):
        if str(config.get("driver", "disabled")) != "fixture" or os.environ.get("SUBTOOLS_REGISTRATION_FIXTURE") != "1":
            return RegistrationResult(
                item.email,
                category="registration_disabled",
                error="真实注册适配器未启用；当前任务只完成输入与状态编排",
                registration_state="disabled",
                checkpoint=_checkpoint(item, checkpoint.get("stage", "created"), state="disabled"),
            )
        for stage in REGISTRATION_STAGES:
            if should_stop():
                return RegistrationResult(
                    item.email,
                    category="cancelled",
                    error="注册任务已停止",
                    registration_state="cancelled",
                    checkpoint=_checkpoint(item, stage, state="cancelled"),
                )
            on_stage(stage)
        # This account is synthetic and is only emitted under the explicit
        # fixture flag; it never represents a live platform credential.
        account = {
            "platform": "fixture",
            "email": item.email,
            "credentials": {
                "access_token": "fixture-access-token",
                "refresh_token": "fixture-refresh-token",
            },
            "extra": {"registration_state": "fixture_completed"},
        }
        return RegistrationResult(
            item.email,
            ok=True,
            category="success",
            error="fixture 注册完成（未连接外部服务）",
            account=account,
            registration_state="completed",
            checkpoint={},
        )


class RegistrationFlowError(RuntimeError):
    def __init__(self, category: str, message: str, stage: str):
        super().__init__(message)
        self.category, self.stage = category, stage


def _run_registered_oauth(
    page: Any,
    item: RegistrationInput,
    registration_password: str,
    *,
    oauth: Any,
    callback: Any,
    timeout: float,
    should_stop: Callable[[], bool],
    headless: bool,
    login_with_browser_fn: Callable[..., Any],
    exchange_code_fn: Callable[..., dict[str, Any]],
    proxy: str | None,
) -> dict[str, Any]:
    """Complete OAuth from the browser session created by registration.

    The account is already signed in when this is called. The shared OAuth
    state machine still owns the authorization page because it handles
    workspace/consent screens and validates the one-time callback state.
    """
    from account_inputs import AccountInput
    from openai_reauth import AuthFlowError

    oauth_account = AccountInput(item.email, registration_password, item.totp_secret, item.source_line)
    result = login_with_browser_fn(
        page,
        oauth_account,
        oauth,
        callback,
        timeout,
        should_stop,
        headless,
    )
    if result is None:
        raise RegistrationFlowError("uncertain", "OAuth 回调未确认；未保存账号", "access_token_probe")
    if not result.state or not result.state.isascii() or not secrets.compare_digest(result.state, oauth.state):
        raise AuthFlowError("oauth_error", "OAuth state mismatch")
    if result.error:
        raise AuthFlowError("oauth_error", "OAuth 授权被拒绝或未完成")
    if not result.code:
        raise RegistrationFlowError("uncertain", "OAuth 回调未返回授权码；未保存账号", "access_token_probe")
    check_running(should_stop)
    return exchange_code_fn(result.code, oauth.code_verifier, oauth.redirect_uri, proxy, trust_env=False)


class MicrosoftGraphMailboxClient:
    """Read-only Outlook mailbox OTP client for four-column account lines."""

    token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    messages_url = "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages"

    def __init__(self, email: str, client_id: str, refresh_token: str, proxy: str | None = None, on_refresh=None):
        self.email = email.casefold()
        self.client_id = client_id
        self.refresh_token = refresh_token
        self.client = httpx.Client(proxy=proxy, timeout=15.0, follow_redirects=False, trust_env=False)
        self.access_token = ""
        self.on_refresh = on_refresh

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.client.close()

    def _refresh(self, deadline=None, should_stop=None):
        check_running(should_stop, deadline)
        try:
            response = self.client.post(self.token_url, data={
                "grant_type": "refresh_token", "client_id": self.client_id,
                "refresh_token": self.refresh_token,
                "scope": "https://graph.microsoft.com/.default offline_access",
            }, timeout=self._timeout(deadline))
            response.raise_for_status()
            body = response.json()
            token = body.get("access_token") if isinstance(body, dict) else None
            if not isinstance(token, str) or not token:
                raise ValueError("missing access token")
            rotated = body.get("refresh_token")
            if isinstance(rotated, str) and rotated and rotated != self.refresh_token:
                self.refresh_token = rotated
                if self.on_refresh:
                    self.on_refresh(rotated)
            self.access_token = token
        except RegistrationPersistenceError:
            raise
        except Exception as exc:
            raise MailboxError("mailbox_access", "Microsoft 邮箱凭据无法换取读取令牌") from exc

    @staticmethod
    def _timeout(deadline):
        check_running(deadline=deadline)
        return min(10, max(.05, deadline-time.monotonic())) if deadline else 10

    def _messages(self, deadline=None, should_stop=None):
        check_running(should_stop, deadline)
        try:
            if not self.access_token:
                self._refresh(deadline, should_stop)
            check_running(should_stop, deadline)
            response = self.client.get(self.messages_url, headers={"Authorization": f"Bearer {self.access_token}"},
                                       timeout=self._timeout(deadline),
                                       params={"$top": "50", "$orderby": "receivedDateTime desc",
                                               "$select": "id,subject,from,toRecipients,receivedDateTime,body"})
            if response.status_code == 401:
                self._refresh(deadline, should_stop)
                check_running(should_stop, deadline)
                response = self.client.get(self.messages_url, headers={"Authorization": f"Bearer {self.access_token}"},
                                           timeout=self._timeout(deadline),
                                           params={"$top": "50", "$orderby": "receivedDateTime desc",
                                                   "$select": "id,subject,from,toRecipients,receivedDateTime,body"})
            response.raise_for_status()
            value = response.json().get("value")
            if not isinstance(value, list):
                raise ValueError("invalid messages response")
            return [item for item in value if isinstance(item, dict)]
        except (MailboxError, RegistrationPersistenceError):
            raise
        except Exception as exc:
            check_running(should_stop, deadline)
            raise MailboxError("mailbox_network", "Microsoft 邮箱消息读取失败") from exc

    @staticmethod
    def _code(message):
        return graph_message_codes(message)

    def snapshot(self, deadline=None, should_stop=None):
        from phone_mailbox import MailboxBaseline
        messages = self._messages(deadline, should_stop)
        check_running(should_stop, deadline)
        ids = frozenset(str(item.get("id")) for item in messages if item.get("id"))
        codes = frozenset(code for item in messages for code in self._code(item))
        return MailboxBaseline(ids=ids, codes=codes)

    def wait_for_code(self, baseline, issued_after, deadline, should_stop=None):
        stop = should_stop or (lambda: False)
        while time.monotonic() < deadline and not stop():
            messages = self._messages(deadline, stop)
            check_running(stop, deadline)
            candidates = []
            for item in messages:
                if str(item.get("id")) in baseline.ids:
                    continue
                received = str(item.get("receivedDateTime") or "")
                try:
                    from datetime import datetime
                    timestamp = datetime.fromisoformat(received.replace("Z", "+00:00")).timestamp()
                except (ValueError, TypeError, OverflowError):
                    continue
                recipients = {str((r.get("emailAddress") or {}).get("address") or "").casefold()
                              for r in item.get("toRecipients", []) if isinstance(r, dict)}
                if self.email not in recipients:
                    continue
                if timestamp < issued_after - 5:
                    continue
                candidates.extend(self._code(item) - baseline.codes)
            if len(set(candidates)) == 1:
                return candidates[0]
            pause = min(deadline, time.monotonic() + 2)
            while time.monotonic() < pause and not stop():
                time.sleep(min(0.1, pause - time.monotonic()))
        return None


class PlaywrightRegistrationAdapter:
    """Controlled browser registration adapter.

    The adapter intentionally stops at human challenges and never retries a
    submission whose result is unknown.  It uses only the public, existing
    browser/OAuth and mailbox boundaries in this project.
    """

    def _checkpoint(self, item, stage, state="running", error="", **extra):
        return _checkpoint(item, stage, state=state, error=error, **extra)

    @staticmethod
    def _visible(page, selectors):
        for selector in selectors:
            try:
                locator = page.locator(selector)
                for index in range(min(locator.count(), 8)):
                    target = locator.nth(index)
                    if target.is_visible(timeout=300):
                        return target
            except Exception:
                continue
        return None

    @staticmethod
    def _body(page):
        try:
            return page.inner_text("body")[:12000].casefold()
        except Exception:
            return ""

    @staticmethod
    def _page_metadata(page) -> tuple[str, str, str]:
        """Return URL, title and body for non-secret entry-page diagnostics."""
        try:
            url = str(getattr(page, "url", "") or "")
        except Exception:
            url = ""
        try:
            title = str(page.title() or "")
        except Exception:
            title = ""
        return url, title, PlaywrightRegistrationAdapter._body(page)

    def _fail(self, item, stage, category, message, *, checkpoint=None, **extra):
        preserved = dict(checkpoint or {})
        if preserved.get("create_confirmed") and category == "uncertain":
            category = "auth_session_pending"
        payload = self._checkpoint(item, stage, category, message)
        # Keep only state needed to explain or safely resume a request.  The
        # browser is always closed after a result, so page objects and response
        # bodies must never leak into a checkpoint.
        for key in (
            "side_effects",
            "create_confirmed",
        ):
            if key in preserved:
                payload[key] = preserved[key]
        payload.update({key: value for key, value in extra.items() if value is not None})
        return RegistrationResult(item.email, category=category, error=message,
                                  registration_state=category, checkpoint=payload)

    @staticmethod
    def _existing_account_marker(body, title="", url=""):
        text = " ".join((str(body or ""), str(title or ""), str(url or ""))).casefold()
        markers = (
            "user_already_exists",
            "user already exists",
            "account already exists",
            "email already exists",
            "email is already registered",
            "email already in use",
            "identity_provider_mismatch",
        )
        return any(marker in text for marker in markers)

    @staticmethod
    def _create_account_response(response):
        """Keep only the outcome of the account-creation request, never its body."""
        url = str(getattr(response, "url", "") or "")
        parsed = urlsplit(url)
        if (parsed.scheme != "https" or parsed.netloc != "auth.openai.com"
                or parsed.path != "/api/accounts/create_account"
                or getattr(getattr(response, "request", None), "method", "POST") != "POST"):
            return None
        try:
            payload = response.json()
            body = json.dumps(payload, ensure_ascii=True).casefold()
        except Exception:
            return "failed"
        if PlaywrightRegistrationAdapter._existing_account_marker(body):
            return "existing"
        valid = isinstance(payload, dict) and not payload.get("error") and payload.get("success") is not False
        return "confirmed" if valid and int(getattr(response, "status", 0) or 0) == 200 else "failed"

    @staticmethod
    def _click(page, selectors, timeout=5):
        for selector in selectors:
            try:
                target = page.locator(selector).first
                visible = target.is_visible(timeout=min(800, timeout * 1000))
            except Exception:
                continue
            if visible:
                # A click may have reached the service before navigation times
                # out. Trying another selector would replay the same submission.
                try:
                    target.click(timeout=timeout * 1000)
                except Exception as exc:
                    raise RegistrationFlowError("uncertain", "提交结果未确认；未重复点击或按回车", "auth_flow") from exc
                return selector
        return None

    @staticmethod
    def _fill_like_user(page, selector, value):
        target = page.locator(selector).first
        target.wait_for(state="visible", timeout=8000)
        try:
            target.click()
            target.fill("")
            target.type(str(value), delay=35)
        except Exception:
            target.fill(str(value))
        return True

    @staticmethod
    def _submit_email_form(page, email):
        """Submit only the form owning the exact email input.

        The login page also renders social-provider buttons.  A generic first
        submit click can enter an IdP flow and make the registration state
        impossible to classify, so the structural form check is preferred.
        """
        try:
            result = page.evaluate("""({email}) => {
              const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
                && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
                && !el.disabled && el.getAttribute('aria-disabled') !== 'true';
              const input = [...document.querySelectorAll(
                'input[type=email],input[name=email],input[name=username],input#login-email,input[autocomplete=email],input[autocomplete=username]'
              )].find(el => visible(el) && String(el.value || '').trim().toLowerCase() === String(email).trim().toLowerCase());
              if (!input) return {ok:false, reason:'email_value_mismatch'};
              const form = input.closest('form');
              if (!form) return {ok:false, reason:'email_form_missing'};
              const bad = /google|apple|microsoft|github|facebook|oauth|sso|oidc|authorize|consent|social|provider|idp/i;
              const attrs = el => [el.id, el.name, el.type, el.value, el.className,
                el.getAttribute('aria-label'), el.getAttribute('title'), el.getAttribute('data-testid'),
                el.getAttribute('data-provider'), el.getAttribute('data-idp')].filter(Boolean).join(' ');
              if (bad.test(attrs(form))) return {ok:false, reason:'unsafe_email_form'};
              const buttons = [...form.querySelectorAll('button,input[type=submit]')];
              const safe = buttons.filter(visible).filter(el => !bad.test(attrs(el) + ' ' + (el.innerText || '')));
              const target = safe.find(el => String(el.type || '').toLowerCase() === 'submit');
              if (!target) return {ok:false, reason:'submit_missing'};
              return {ok:true, form_index:[...document.querySelectorAll('form')].indexOf(form),
                target_index:buttons.indexOf(target)};
            }""", {"email": str(email)})
            if not isinstance(result, dict) or not result.get("ok"):
                return False
        except Exception:
            return False
        try:
            page.locator("form").nth(result["form_index"]).locator(
                "button,input[type=submit]"
            ).nth(result["target_index"]).click(timeout=8000)
        except Exception as exc:
            raise RegistrationFlowError("uncertain", "邮箱提交状态无法确认；未重试", "auth_flow") from exc
        return True

    @staticmethod
    def _visible_selector(page, selectors):
        target = PlaywrightRegistrationAdapter._visible(page, selectors)
        return target, next((selector for selector in selectors if target is not None and
                             PlaywrightRegistrationAdapter._selector_matches(page, selector, target)), None)

    @staticmethod
    def _selector_matches(page, selector, target):
        try:
            for index in range(min(page.locator(selector).count(), 8)):
                if page.locator(selector).nth(index).equals(target):
                    return True
        except Exception:
            return False
        return False

    @staticmethod
    def _stage(page):
        """Derive the registration stage from URL first, then visible controls."""
        try:
            url = str(page.url or "")
        except Exception:
            url = ""
        try:
            validate_registration_url(url)
        except ValueError:
            return "external"
        parsed = urlsplit(url)
        lower = parsed.path.casefold()
        if parsed.hostname == "chatgpt.com" and lower in {"/auth/login", "/auth/signup"}:
            return "entry"
        if parsed.hostname == "chatgpt.com" and not lower.startswith(("/auth/", "/api/", "/backend-api/")):
            try:
                cookies = page.context.cookies()
                names = {str(c.get("name")) for c in cookies if c.get("value")
                         and c.get("domain", "chatgpt.com").lstrip(".") == "chatgpt.com"}
                prefix = "__Secure-next-auth.session-token"
                chunks = {int(n[len(prefix)+1:]) for n in names if re.fullmatch(re.escape(prefix)+r"\.[0-9]{1,2}", n)}
                if prefix in names or (chunks and chunks == set(range(max(chunks)+1))):
                    return "complete"
            except Exception:
                pass
        if parsed.hostname == "auth.openai.com":
            if lower.rstrip("/") in {"/add-phone", "/phone-verification"}:
                return "phone"
            if lower.rstrip("/") in {"/log-in/password", "/login/password"}:
                return "login_password"
            if PlaywrightRegistrationAdapter._visible(page, ['input[autocomplete="current-password"]']):
                return "login_password"
            if "about-you" in lower:
                return "about_you"
            if any(part in lower for part in ("email-verification", "/verify")):
                if PlaywrightRegistrationAdapter._visible(page, [
                    'input[type="password"]', 'input[name="password"]', 'input[autocomplete="new-password"]']):
                    return "password"
                if PlaywrightRegistrationAdapter._visible(page, [
                    'input[autocomplete="one-time-code"]', 'input[inputmode="numeric"]',
                    'input[type="tel"]', 'input[name*="code" i]', 'input[id*="code" i]',
                    'input[aria-label*="code" i]']):
                    return "otp"
                return "email_verification"
        if PlaywrightRegistrationAdapter._visible(page, [
            'input[type="password"]', 'input[name="password"]', 'input[autocomplete="new-password"]']):
            return "password"
        if PlaywrightRegistrationAdapter._visible(page, [
            'input[name="name"]', 'input[autocomplete="name"]', 'input[type="date"]',
            'input[name*="birth" i]', 'input[name="age"]', 'input[id$="-age"]',
            '[role="spinbutton"][data-type]']):
            return "about_you"
        if PlaywrightRegistrationAdapter._visible(page, [
            'input[autocomplete="one-time-code"]', 'input[name*="code" i]', 'input[id*="code" i]',
            'input[aria-label*="code" i]']):
            return "otp"
        try:
            slots = page.locator('input[maxlength="1"][inputmode="numeric"], input[maxlength="1"][type="tel"]')
            if slots.count() == 6 and all(slots.nth(i).is_visible(timeout=100) for i in range(6)):
                return "otp"
        except Exception:
            pass
        if PlaywrightRegistrationAdapter._visible(page, [
            'input[type="email"]', 'input[name="email"]', 'input[autocomplete="email"]',
            'input[name="username"]', 'input[autocomplete="username"]']):
            return "entry"
        return "unknown"

    @staticmethod
    def _fetch_session(page, timeout=45, should_stop=None):
        """Read the ChatGPT session in-page so browser cookies and origin are reused."""
        deadline = time.monotonic() + timeout
        last_status, last_error, attempts = 0, "", 0
        while time.monotonic() < deadline:
            check_running(should_stop, deadline)
            attempts += 1
            try:
                payload = page.evaluate("""async (budgetMs) => {
                    if (location.origin !== 'https://chatgpt.com') return {status:0};
                    const controller = new AbortController();
                    const timer = setTimeout(() => controller.abort(), budgetMs);
                    try {
                    const response = await fetch('/api/auth/session', {
                      credentials: 'include', headers: {accept: 'application/json'}, signal:controller.signal
                    });
                    return {status: response.status, text: await response.text()};
                    } finally { clearTimeout(timer); }
                }""", max(1, int(min(5, deadline-time.monotonic())*1000)))
                check_running(should_stop, deadline)
                last_status = int(payload.get("status") or 0) if isinstance(payload, dict) else 0
                if last_status == 429:
                    raise RegistrationFlowError("rate_limited", "读取 ChatGPT 会话返回 HTTP 429；已停止本批次", "auth_session")
                if last_status in {401, 403}:
                    raise RegistrationFlowError("session_http_error", f"读取 ChatGPT 会话返回 HTTP {last_status}；请核对登录状态和网络", "auth_session")
                if last_status == 200:
                    data = json.loads(str(payload.get("text") or "{}"))
                    if session_candidate(data):
                        return data
                    last_error = "会话中缺少有效 accessToken"
                else:
                    last_error = "会话服务暂时不可用" if last_status >= 500 else "会话请求未成功"
            except RegistrationFlowError:
                raise
            except Exception:
                check_running(should_stop, deadline)
                last_error = "网络、页面上下文或响应格式异常"
            wait = min(1.5, max(0, deadline - time.monotonic()))
            try:
                page.wait_for_timeout(wait * 1000)
            except Exception:
                time.sleep(wait)
        raise RegistrationFlowError("session_unavailable", f"ChatGPT 会话未确认（HTTP {last_status}，读取 {attempts} 次；{last_error}）", "auth_session")

    @staticmethod
    def _bind_totp_in_browser(
        page,
        access_token,
        *,
        device_id,
        chat_base="https://chatgpt.com",
        budget_ms=20_000,
        on_secret=None,
        should_stop=None,
    ):
        """Enroll TOTP through the authenticated browser origin.

        The registration reference performs both MFA calls in the same browser
        context as signup. Keeping that property avoids losing cookies or edge
        clearance when the account is created behind a proxy.
        """
        if not str(access_token or "").strip():
            return None, "ChatGPT session 缺少 accessToken，无法绑定 TOTP"
        check_running(should_stop)
        try:
            import pyotp
            base = str(chat_base or "https://chatgpt.com").rstrip("/")
            try:
                budget = max(1_000, int(budget_ms))
            except (TypeError, ValueError):
                budget = 20_000
            enroll = page.evaluate(
                """async ([url, token, device, budgetMs]) => {
                  const controller = new AbortController();
                  const timer = setTimeout(() => controller.abort(), budgetMs);
                  try {
                    const response = await fetch(url, {
                      method: 'POST', credentials: 'include',
                      headers: {'Authorization': 'Bearer ' + token,
                                'oai-device-id': device,
                                'oai-language': 'en-US',
                                'Content-Type': 'application/json'},
                      body: JSON.stringify({factor_type: 'totp'}),
                      signal: controller.signal
                    });
                    return {status: response.status, body: await response.json().catch(() => ({}))};
                  } catch (_) { return {status: 0, body: {}}; }
                  finally { clearTimeout(timer); }
                }""",
                [f"{base}/backend-api/accounts/mfa/enroll", access_token, device_id, budget],
            )
            if not isinstance(enroll, dict) or int(enroll.get("status") or 0) != 200:
                return None, "TOTP 初始化失败"
            body = enroll.get("body") if isinstance(enroll.get("body"), dict) else {}
            secret = str(body.get("secret") or "").strip()
            session_id = str(body.get("session_id") or "").strip()
            if not secret or not session_id:
                return None, "TOTP 初始化返回内容不完整"
            if on_secret:
                on_secret(secret)
            check_running(should_stop)
            code = pyotp.TOTP(secret).now()
            activate = page.evaluate(
                """async ([url, token, device, code, sessionId, budgetMs]) => {
                  const controller = new AbortController();
                  const timer = setTimeout(() => controller.abort(), budgetMs);
                  try {
                    const response = await fetch(url, {
                      method: 'POST', credentials: 'include',
                      headers: {'Authorization': 'Bearer ' + token,
                                'oai-device-id': device,
                                'oai-language': 'en-US',
                                'Content-Type': 'application/json'},
                      body: JSON.stringify({code, factor_type: 'totp', session_id: sessionId}),
                      signal: controller.signal
                    });
                    return {status: response.status, body: await response.json().catch(() => ({}))};
                  } catch (_) { return {status: 0, body: {}}; }
                  finally { clearTimeout(timer); }
                }""",
                [f"{base}/backend-api/accounts/mfa/user/activate_enrollment", access_token,
                 device_id, code, session_id, budget],
            )
            activated = isinstance(activate, dict) and int(activate.get("status") or 0) == 200
            activated_body = activate.get("body") if isinstance(activate, dict) else {}
            if not activated or not isinstance(activated_body, dict) or not activated_body.get("success"):
                return None, "TOTP 激活失败"
            return secret, ""
        except RegistrationPersistenceError:
            raise
        except Exception:
            check_running(should_stop)
            return None, "TOTP 绑定结果未确认"

    @staticmethod
    def _signin_fallback(page, email, budget_ms=10000):
        """Return the issue window start when NextAuth begins the fallback flow."""
        issued_after = time.time()
        try:
            result = page.evaluate("""async ([email, budgetMs]) => {
              if (location.origin !== 'https://chatgpt.com') return false;
              const controller = new AbortController();
              const timer = setTimeout(() => controller.abort(), budgetMs);
              try {
              const csrf = await fetch('/api/auth/csrf', {credentials:'include', headers:{accept:'application/json'}, signal:controller.signal});
              const csrfBody = await csrf.json().catch(() => ({}));
              if (!csrf.ok || !csrfBody.csrfToken) return false;
              const query = new URLSearchParams({
                prompt:'login', 'screen_hint':'login_or_signup', login_hint:email,
                'ext-oai-did': crypto.randomUUID(),
                'auth_session_logging_id': crypto.randomUUID(),
                'ext-passkey-client-capabilities': '11111'
              });
              const form = new URLSearchParams({callbackUrl:'https://chatgpt.com/', csrfToken:csrfBody.csrfToken, json:'true'});
              const response = await fetch('/api/auth/signin/openai?' + query.toString(), {
                method:'POST', credentials:'include',
                headers:{accept:'application/json', 'content-type':'application/x-www-form-urlencoded'},
                body:form.toString(), signal:controller.signal
              });
              const body = await response.json().catch(() => ({}));
              if (!response.ok || !body.url) return false;
              const target = new URL(body.url, location.href);
              if (!['https://chatgpt.com', 'https://auth.openai.com'].includes(target.origin)
                  || target.username || target.password) return false;
              for (const [key, value] of query.entries()) {
                if (!target.searchParams.get(key)) target.searchParams.set(key, value);
              }
              location.assign(target.toString());
              return true;
              } finally { clearTimeout(timer); }
            }""", [str(email), max(1, int(budget_ms))])
            return issued_after if result else None
        except Exception:
            return None

    @staticmethod
    def _registration_password(item: RegistrationInput) -> str:
        """Use an explicit registration password or generate one.

        Microsoft Graph records use their second column for mailbox access, so
        the parser intentionally leaves ``item.password`` empty.  The mature
        browser flows generate a separate password in that case; keeping it
        it in the encrypted task before submission avoids losing the credential
        when an uncertain registration needs manual recovery.
        """
        if item.password:
            return item.password
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        required = [secrets.choice(string.ascii_uppercase),
                    secrets.choice(string.ascii_lowercase),
                    secrets.choice(string.digits),
                    secrets.choice("!@#$%^&*")]
        required.extend(secrets.choice(alphabet) for _ in range(20))
        secrets.SystemRandom().shuffle(required)
        return "".join(required)

    @staticmethod
    def _complete_profile(page, name, birthdate):
        """Fill native and React-style profile controls, including hidden birthday fields."""
        value = str(birthdate or "")
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            today = date.today()
            value = f"{today.year - 25:04d}-{today.month:02d}-{today.day:02d}"
        year, month, day = value.split("-")
        result = page.evaluate("""({name, birthday, year, month, day}) => {
          const visible = el => el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length)
            && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
            && !el.disabled && !el.readOnly;
          const attrs = el => [el.name, el.id, el.placeholder, el.getAttribute('aria-label'), el.type]
            .filter(Boolean).join(' ').toLowerCase();
          const set = (el, val) => { if (!el) return false; const proto = el.tagName.toLowerCase() === 'select' ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
            const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set; if (setter) setter.call(el, String(val)); else el.value = String(val);
            el.dispatchEvent(new Event('input', {bubbles:true})); el.dispatchEvent(new Event('change', {bubbles:true})); el.blur?.(); return true; };
          const fields = [...document.querySelectorAll('input,select,textarea')].filter(visible);
          const nameField = fields.find(el => String(el.autocomplete || '').toLowerCase() === 'name' || /(^|\\s)(name|full.?name)(\\s|$)/.test(attrs(el)));
          const first = fields.find(el => /(^|\\s)(first.?name)(\\s|$)/.test(attrs(el)));
          const last = fields.find(el => /(^|\\s)(last.?name)(\\s|$)/.test(attrs(el)));
          const birth = fields.find(el => el.type === 'date' || /birth(day|date)?/.test(attrs(el)));
          const age = fields.find(el => /(^|\\s)age(\\s|$)/.test(attrs(el)) || String(el.id || '').toLowerCase().endsWith('-age'));
          let named = false, born = false;
          if (nameField) { set(nameField, name); named = true; } else { if (first) { set(first, String(name).split(/\\s+/, 1)[0]); named = true; } if (last) { set(last, String(name).split(/\\s+/).slice(1).join(' ') || 'User'); named = true; } }
          if (age) { const now = new Date(); const a = now.getFullYear() - Number(year) - ((now.getMonth() + 1 < Number(month)) || (now.getMonth() + 1 === Number(month) && now.getDate() < Number(day)) ? 1 : 0); set(age, a); born = true; } else if (birth) { set(birth, birthday); born = true; }
          if (!born) { const y = fields.find(el => /(^|\\s)year(\\s|$)/.test(attrs(el))); const m = fields.find(el => /(^|\\s)month(\\s|$)/.test(attrs(el))); const d = fields.find(el => /(^|\\s)day(\\s|$)/.test(attrs(el))); if (y && m && d) { set(y, year); set(m, month); set(d, day); born = true; } }
          if (!born) {
            const selects = [...document.querySelectorAll('[data-testid="hidden-select-container"] select,.react-aria-Select select,select')].filter(el => !el.disabled);
            const values = el => [...el.options].map(option => String(option.value));
            const has = (el, val) => values(el).includes(String(val));
            const numbers = el => values(el).map(Number).filter(Number.isFinite);
            const years = selects.find(el => has(el, year) && Math.max(...numbers(el), -Infinity) > 1900);
            const months = selects.find(el => el !== years && (has(el, month) || has(el, Number(month))) && Math.max(...numbers(el), -Infinity) <= 12);
            const days = selects.find(el => el !== years && el !== months && (has(el, day) || has(el, Number(day))) && Math.max(...numbers(el), -Infinity) >= 28);
            if (years && months && days) { set(years, year); set(months, has(months, Number(month)) ? Number(month) : month); set(days, has(days, Number(day)) ? Number(day) : day); born = true; }
          }
          const spins = [...document.querySelectorAll('[role=spinbutton][data-type]')].filter(visible);
          for (const [kind, val] of [['year',year],['month',month.padStart(2,'0')],['day',day.padStart(2,'0')]]) { const el = spins.find(item => String(item.getAttribute('data-type')).toLowerCase() === kind); if (el) { if ('value' in el) el.value = val; else el.textContent = val; el.dispatchEvent(new Event('input',{bubbles:true})); el.dispatchEvent(new Event('change',{bubbles:true})); el.blur?.(); born = true; } }
          if (spins.length >= 3) born = true;
          const consent = [...document.querySelectorAll('input[type=checkbox],[role=checkbox]')]
            .some(el => visible(el) && (el.required || el.getAttribute('aria-required') === 'true')
              && (el.checked === false || el.getAttribute('aria-checked') === 'false'));
          return {named, born, consent};
        }""", {"name": str(name or "User"), "birthday": value, "year": year, "month": month, "day": day})
        if isinstance(result, dict) and result.get("consent"):
            raise RegistrationFlowError("needs_interaction", "注册资料页需要人工确认必选条款", "create_account")
        if not isinstance(result, dict) or not result.get("born"):
            raise RegistrationFlowError("uncertain", "about-you 生日控件未通过校验", "create_account")
        if not result.get("named"):
            raise RegistrationFlowError("uncertain", "about-you 姓名控件未通过校验", "create_account")
        button = PlaywrightRegistrationAdapter._visible(page, [
            'button[type="submit"]', 'button[data-testid="continue-button"]',
            'button:has-text("Continue")', 'button:has-text("Create account")'])
        if button is None:
            raise RegistrationFlowError("uncertain", "未找到 about-you 提交按钮", "create_account")
        button.click()

    def register(self, item, *, config, should_stop, on_stage, checkpoint, on_checkpoint=None):
        stage = str(checkpoint.get("stage") or "created")
        if should_stop():
            return self._fail(item, stage, "cancelled", "注册任务已停止", checkpoint=checkpoint)
        if registration_needs_review(checkpoint):
            state = str(checkpoint.get("state") or checkpoint.get("registration_state") or "")
            category = "auth_session_pending" if state == "auth_session_pending" else "uncertain"
            message = ("已有已建号但会话未确认的检查点，请先恢复会话或人工核对邮箱状态；未自动重放请求"
                       if category == "auth_session_pending" else
                       "已有未确认的注册提交，请先人工核对邮箱状态；未自动重放请求")
            return self._fail(item, stage, category, message, checkpoint=checkpoint)
        try:
            from openai_reauth import (AuthFlowError, CallbackServer, exchange_code,
                                       generate_oauth_session, launch_browser,
                                       login_with_browser)
            from reauth_formats import build_account_payload
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            return self._fail(item, stage, "uncertain", "浏览器注册依赖不可用", checkpoint=checkpoint)
        proxy = str(config.get("proxy") or "").strip() or None
        timeout = max(30, int(config.get("timeout", 900)))
        otp_timeout = max(30, int(config.get("otp_timeout", 300)))
        page_timeout = max(5, int(config.get("page_timeout", 60)))
        session_timeout = max(5, int(config.get("session_timeout", 60)))
        oauth_timeout = max(5, int(config.get("oauth_timeout", 120)))
        signup_url = validate_registration_url(str(config.get("signup_url") or "https://chatgpt.com/auth/login").strip())
        registration_password = self._registration_password(item)
        headless = not bool(config.get("show_browser", False))
        browser = page = callback = None
        mailbox = None
        side_effects = dict(checkpoint.get("side_effects") or {})
        create_confirmed = bool(checkpoint.get("create_confirmed"))
        create_response = {"state": ""}
        pending_create_responses = []
        create_outcomes = []
        auth_responses = []
        deadline = time.monotonic() + timeout

        def remaining():
            check_running(should_stop, deadline)
            return max(.001, deadline - time.monotonic())

        def save_checkpoint(name, state="running", error=""):
            nonlocal stage
            stage = name
            extra = {"side_effects": dict(side_effects)}
            if create_confirmed:
                extra.update(create_confirmed=True)
            checkpoint.clear()
            checkpoint.update(self._checkpoint(item, name, state=state, error=error, **extra))
            if on_checkpoint:
                on_checkpoint(dict(checkpoint))
            return checkpoint

        def mark(name, state="running", error=""):
            remaining()
            save_checkpoint(name, state=state, error=error)
            on_stage(name)
        try:
            def persist_mailbox_token(token):
                item.mailbox_refresh_token = token
                save_checkpoint(stage)
            mailbox_factory = (MicrosoftGraphMailboxClient(item.email, item.mailbox_client_id,
                             item.mailbox_refresh_token, proxy=proxy, on_refresh=persist_mailbox_token)
                              if item.mailbox_client_id and item.mailbox_refresh_token
                              else MailboxClient(item.mailbox_url, item.email, proxy=proxy))
            with mailbox_factory as mailbox:
                mark("mailbox_ready")
                baseline = mailbox.snapshot(min(deadline, time.monotonic() + 30), should_stop=should_stop)
                if should_stop():
                    return self._fail(item, "mailbox_ready", "cancelled", "注册任务已停止", checkpoint=checkpoint)
                with sync_playwright() as playwright:
                    browser = launch_browser(playwright, headless=headless, proxy=proxy)
                    context = browser.new_context()
                    page = context.new_page()
                    def observe_create(response):
                        parsed = urlsplit(str(getattr(response, "url", "") or ""))
                        # Reading a response body from a sync Playwright event
                        # callback races navigation/body delivery. Consume it on
                        # the main flow before classifying the resulting page.
                        if parsed.netloc == "auth.openai.com" and parsed.path == "/api/accounts/create_account":
                            pending_create_responses.append(response)
                        if parsed.hostname in {"chatgpt.com", "auth.openai.com"} and (
                            parsed.path.startswith("/api/auth/") or
                            parsed.path.startswith("/api/accounts/")
                        ):
                            auth_responses.append((parsed.path, int(getattr(response, "status", 0) or 0)))
                    page.on("response", observe_create)
                    def observe_finished(request):
                        for response in list(pending_create_responses):
                            if getattr(response, "request", None) == request:
                                # requestfinished guarantees body delivery;
                                # capture the outcome before navigation discards it.
                                create_outcomes.append(self._create_account_response(response))
                                pending_create_responses.remove(response)
                    page.on("requestfinished", observe_finished)
                    page.set_default_timeout(min(15000, timeout * 1000))
                    mark("sentinel")
                    try:
                        response = page.goto(signup_url, wait_until="domcontentloaded", timeout=min(30, remaining()) * 1000)
                    except Exception:
                        return self._fail(item, "sentinel", "uncertain",
                                          "注册入口页面无法加载；未提交邮箱，请检查网络或代理", checkpoint=checkpoint)
                    current_url, title, body = self._page_metadata(page)
                    validate_registration_url(current_url)
                    status = int(getattr(response, "status", 0) or 0)
                    entry_failure = _registration_entry_failure(
                        status, body, title=title, url=current_url
                    )
                    if entry_failure:
                        category, message = entry_failure
                        return self._fail(item, "sentinel", category, message, checkpoint=checkpoint)
                    if any(word in body for word in ("captcha", "recaptcha", "security challenge", "verify you are human")):
                        return self._fail(item, "sentinel", "needs_interaction", "页面要求人工完成安全验证", checkpoint=checkpoint)
                    mark("identity_ready")
                    email = None
                    entry_deadline = min(deadline, time.monotonic() + page_timeout)
                    while time.monotonic() < entry_deadline and not should_stop():
                        remaining()
                        current_url, title, body = self._page_metadata(page)
                        validate_registration_url(current_url)
                        entry_failure = _registration_entry_failure(status, body, title=title, url=current_url)
                        if entry_failure:
                            category, message = entry_failure
                            return self._fail(item, "identity_ready", category, message, checkpoint=checkpoint)
                        if any(word in body for word in ("captcha", "recaptcha", "security challenge", "verify you are human")):
                            return self._fail(item, "identity_ready", "needs_interaction", "页面要求人工完成安全验证", checkpoint=checkpoint)
                        email = self._visible(page, [
                            'input#login-email', 'input[type="email"]', 'input[name="email"]',
                            'input[name="username"]', 'input[autocomplete="username"]',
                            'input[autocomplete="email"]', 'input[inputmode="email"]',
                        ])
                        if email is not None:
                            break
                        try:
                            page.wait_for_timeout(400)
                        except Exception:
                            time.sleep(0.4)
                    if should_stop():
                        return self._fail(item, "identity_ready", "cancelled", "注册任务已停止", checkpoint=checkpoint)
                    entry_via_fallback = False
                    if email is None:
                        side_effects["email_submit_attempted"] = True
                        save_checkpoint("auth_flow", state="email_submit_pending")
                        fallback_issued_after = self._signin_fallback(page, item.email, min(10000, remaining() * 1000))
                        if fallback_issued_after is not None:
                            issued_after = fallback_issued_after
                            side_effects["email_submitted"] = True
                            save_checkpoint("auth_flow", state="submitted_email")
                            entry_deadline = min(deadline, time.monotonic() + page_timeout)
                            while time.monotonic() < entry_deadline and not should_stop():
                                if self._stage(page) != "entry":
                                    break
                                try:
                                    page.wait_for_timeout(500)
                                except Exception:
                                    time.sleep(0.5)
                            if self._stage(page) != "entry":
                                entry_via_fallback = True
                        else:
                            current_url, title, body = self._page_metadata(page)
                            entry_failure = _registration_entry_failure(status, body, title=title, url=current_url)
                            if entry_failure:
                                category, message = entry_failure
                                return self._fail(item, "identity_ready", category, message, checkpoint=checkpoint)
                            return self._fail(item, "identity_ready", "uncertain",
                                              "备用邮箱提交结果未确认；未重复发起请求", checkpoint=checkpoint)
                    if not entry_via_fallback:
                        self._fill_like_user(page, 'input#login-email' if self._visible(page, ['input#login-email']) else
                                             'input[type="email"], input[name="email"], input[name="username"], input[autocomplete="username"]', item.email)
                    mark("auth_flow")
                    save_checkpoint("auth_flow", state="email_submit_pending")
                    if not entry_via_fallback:
                        side_effects["email_submit_attempted"] = True
                        save_checkpoint("auth_flow", state="email_submit_pending")
                        issued_after = time.time()
                        if not self._submit_email_form(page, item.email):
                            raise RegistrationFlowError("uncertain", "未找到安全的邮箱提交按钮；未重试", "auth_flow")
                        side_effects["email_submitted"] = True
                        save_checkpoint("auth_flow", state="submitted_email")
                    password_submitted = False
                    otp_submitted = False
                    otp_submitted_at = None
                    fallback_at = None
                    session_navigation_attempted = False
                    phase, phase_started = None, time.monotonic()
                    while True:
                        for pending_response in list(pending_create_responses):
                            request = getattr(pending_response, "request", None)
                            if request is not None:
                                continue
                            pending_create_responses.remove(pending_response)
                            create_outcomes.append(self._create_account_response(pending_response))
                        while create_outcomes:
                            outcome = create_outcomes.pop(0)
                            if outcome:
                                create_response["state"] = outcome
                            if outcome == "confirmed":
                                create_confirmed = True
                                save_checkpoint("create_account", state="auth_session_pending")
                        if should_stop():
                            return self._fail(item, stage, "cancelled", "注册任务已停止", checkpoint=checkpoint)
                        remaining()
                        current_stage = self._stage(page)
                        if current_stage == "external":
                            return self._fail(item, stage, "needs_interaction", "注册跳转到了外部页面；未填写密码或验证码", checkpoint=checkpoint)
                        if any(status == 429 for _, status in auth_responses):
                            return self._fail(item, stage, "rate_limited", "注册服务限流；本批次停止", checkpoint=checkpoint)
                        if current_stage == "phone":
                            return self._fail(item, stage, "phone_required", "账号需要补手机；注册流程未调用付费接码", checkpoint=checkpoint)
                        if current_stage == "login_password":
                            side_effects["existing_account_detected"] = True
                            save_checkpoint("auth_flow", state="existing_account")
                            return self._fail(item, "auth_flow", "existing_account",
                                              "注册已转到已有账号登录页；未填写新密码，可转授权处理", checkpoint=checkpoint)
                        current_url, title, body = self._page_metadata(page)
                        location = urlsplit(current_url)
                        if (create_confirmed and location.hostname == "chatgpt.com"
                                and not location.path.startswith(("/auth/", "/api/", "/backend-api/"))):
                            # Cookie names can change. An authenticated, matching
                            # session response remains mandatory before proceeding.
                            current_stage = "complete"
                        if phase != current_stage:
                            phase, phase_started = current_stage, time.monotonic()
                        elapsed = time.monotonic() - phase_started
                        phase_limit = session_timeout if create_confirmed and current_stage in {"unknown", "entry"} else page_timeout
                        if elapsed >= phase_limit:
                            failed = next(((path, status) for path, status in reversed(auth_responses) if status >= 400), None)
                            detail = f"；认证接口 {failed[0]} 返回 HTTP {failed[1]}" if failed else ""
                            return self._fail(item, current_stage, "uncertain",
                                              f"页面阶段 {current_stage} 在 {phase_limit} 秒内未推进{detail}；未重放已提交请求",
                                              checkpoint=checkpoint)
                        entry_failure = _registration_entry_failure(0, body, title=title, url=current_url)
                        if entry_failure:
                            category, message = entry_failure
                            return self._fail(item, current_stage, category, message, checkpoint=checkpoint)
                        if create_response["state"] == "confirmed" and not create_confirmed:
                            create_confirmed = True
                            save_checkpoint("create_account", state="auth_session_pending")
                        if create_response["state"] == "existing" or self._existing_account_marker(body, title, current_url):
                            # Before the email submit boundary this is a login
                            # page hint.  After it, the server has explicitly
                            # told us that signup cannot proceed and the row is
                            # permanently half-registered for this workflow.
                            category = ("partial_registered"
                                        if side_effects.get("email_submitted") or
                                           side_effects.get("password_submitted") or
                                           side_effects.get("otp_submitted")
                                        else "existing_account")
                            message = ("服务端报告邮箱已存在，已标记为半注册；未重试注册请求"
                                       if category == "partial_registered" else
                                       "邮箱可能已经注册")
                            return self._fail(item, current_stage, category, message, checkpoint=checkpoint)
                        if create_confirmed and current_stage in {"unknown", "entry"}:
                            if not session_navigation_attempted and elapsed >= min(10, session_timeout / 2):
                                session_navigation_attempted = True
                                save_checkpoint("auth_session", state="auth_session_pending")
                                page.goto("https://chatgpt.com/", wait_until="domcontentloaded",
                                          timeout=min(30, remaining()) * 1000)
                            page.wait_for_timeout(1200)
                            continue
                        if current_stage == "complete":
                            if not password_submitted or not create_confirmed:
                                return self._fail(item, "auth_session", "uncertain", "会话已建立但建号响应未确认", checkpoint=checkpoint)
                            mark("auth_session", state="running")
                            try:
                                session = self._fetch_session(page, timeout=min(session_timeout, remaining()), should_stop=should_stop)
                            except RegistrationFlowError:
                                raise
                            except Exception:
                                remaining()
                                return self._fail(
                                    item,
                                    "auth_session",
                                     "uncertain",
                                     "注册后会话未确认；请人工核对邮箱状态，未自动重放注册请求",
                                    checkpoint=checkpoint,
                                )
                            candidate = session_candidate(session)
                            session_email = candidate.get("email", "")
                            if not session_email or session_email.casefold() != item.email.casefold():
                                return self._fail(
                                    item,
                                    "auth_session",
                                     "uncertain",
                                     "会话邮箱与注册邮箱不一致；未保存账号或重放注册请求",
                                    checkpoint=checkpoint,
                                )
                            session_access_token = candidate.get("access_token", "")
                            if not session_access_token:
                                return self._fail(item, "auth_session", "uncertain",
                                                  "注册后会话缺少凭据；未自动重放注册请求", checkpoint=checkpoint)
                            side_effects["session_confirmed"] = True
                            save_checkpoint("auth_session", state="auth_session_pending")
                            totp_secret = ""
                            totp_error = ""
                            if bool(config.get("require_totp", True)):
                                mark("totp_enroll")
                                def persist_totp(secret):
                                    item.totp_secret = secret
                                    side_effects["totp_activation_attempted"] = True
                                    save_checkpoint("totp_enroll", state="totp_activation_pending")
                                totp_secret, totp_error = self._bind_totp_in_browser(
                                    page, session_access_token, device_id=str(uuid.uuid4()),
                                    budget_ms=min(10_000, max(1, int(remaining() * 500))),
                                    on_secret=persist_totp, should_stop=should_stop,
                                )
                                if not totp_secret:
                                    return self._fail(
                                        item,
                                        "totp_enroll",
                                        "auth_session_pending",
                                        f"账号已创建但 TOTP 绑定未确认：{totp_error or '未知错误'}；未换取 OAuth 或保存账号",
                                        checkpoint=checkpoint,
                                    )
                                item.totp_secret = totp_secret
                                side_effects["totp_confirmed"] = True
                                save_checkpoint("totp_enroll", state="auth_session_pending")
                            mark("access_token_probe")
                            # The web session is only the registration proof.  The
                            # current tool stores Codex-compatible OAuth tokens,
                            # so exchange a fresh one-time callback code while
                            # reusing the authenticated browser context.
                            oauth = generate_oauth_session()
                            callback = CallbackServer()
                            callback.start()
                            # Registration leaves the browser authenticated, but the
                            # OAuth page still has its own workspace, consent and
                            # callback states. Reuse the production login state
                            # machine so those states are handled consistently with
                            # normal re-authentication.
                            tokens = _run_registered_oauth(
                                page,
                                item,
                                registration_password,
                                oauth=oauth,
                                callback=callback,
                                timeout=min(oauth_timeout, remaining()),
                                should_stop=should_stop,
                                headless=headless,
                                login_with_browser_fn=login_with_browser,
                                exchange_code_fn=exchange_code,
                                proxy=proxy,
                            )
                            # Once token exchange returns, preserve the credential
                            # even if stop/deadline was reached during the request.
                            on_stage("finalize")
                            account = build_account_payload(tokens, item.email)
                            # Keep the password with the successful encrypted
                            # account payload as well as the encrypted task item.
                            account.setdefault("credentials", {})["password"] = registration_password
                            if item.totp_secret:
                                credentials = account.setdefault("credentials", {})
                                credentials["totp_secret"] = item.totp_secret
                            account.setdefault("extra", {})["registration_totp"] = {
                                "enrolled": bool(totp_secret),
                                "error": totp_error,
                            }
                            return RegistrationResult(item.email, ok=True, category="success", error="注册完成",
                                                      account=account, registration_state="completed", checkpoint={})
                        if current_stage == "password":
                            selector = 'input[type="password"], input[name="password"], input[autocomplete="new-password"]'
                            if not password_submitted:
                                item.password = registration_password
                                side_effects["password_submit_attempted"] = True
                                save_checkpoint("user_register", state="password_submit_pending")
                                self._fill_like_user(page, selector, registration_password)
                                if not self._click(page, ['button[type="submit"]', 'button[data-testid="continue-button"]', 'button:has-text("Continue")', 'button:has-text("Create account")'], timeout=6):
                                    page.locator(selector).first.press("Enter")
                                password_submitted = True
                                side_effects["password_submitted"] = True
                                mark("user_register")
                            page.wait_for_timeout(1500)
                            continue
                        if current_stage == "otp":
                            if not password_submitted:
                                if fallback_at is None:
                                    clicked = self._click(page, ['a[href="/create-account/password"]', 'a[href*="/create-account/password"]'], timeout=5)
                                    if clicked:
                                        fallback_at = time.monotonic()
                                    else:
                                        page.wait_for_timeout(1500)
                                        continue
                                elif time.monotonic() - fallback_at >= page_timeout:
                                    return self._fail(item, "user_register", "uncertain", "密码注册入口未推进", checkpoint=checkpoint)
                                page.wait_for_timeout(1500)
                                continue
                            if otp_submitted:
                                if time.monotonic() - (otp_submitted_at or time.monotonic()) >= page_timeout:
                                    return self._fail(item, "email_otp_validate", "uncertain", "验证码提交后页面未推进；未重放验证码", checkpoint=checkpoint)
                                page.wait_for_timeout(1500)
                                continue
                            mark("email_otp_send")
                            mark("email_otp_wait")
                            code = mailbox.wait_for_code(baseline, issued_after, min(deadline, time.monotonic() + otp_timeout), should_stop=should_stop)
                            remaining()
                            if not code:
                                return self._fail(item, "email_otp_wait", "uncertain", "邮箱验证码未在时限内确认", checkpoint=checkpoint)
                            mark("email_otp_validate")
                            side_effects["otp_submit_attempted"] = True
                            save_checkpoint("email_otp_validate", state="otp_submit_pending")
                            fields = page.locator('input[autocomplete="one-time-code"], input[inputmode="numeric"], input[type="tel"], input[name*="code" i], input[id*="code" i], input[aria-label*="code" i]')
                            visible_fields = []
                            for index in range(min(fields.count(), 8)):
                                try:
                                    if fields.nth(index).is_visible(timeout=300):
                                        visible_fields.append(fields.nth(index))
                                except Exception:
                                    continue
                            if not visible_fields:
                                raise RegistrationFlowError("uncertain", "未找到邮箱验证码输入框", "email_otp_validate")
                            if len(visible_fields) == 1:
                                visible_fields[0].fill(code)
                            else:
                                for field, digit in zip(visible_fields, str(code)):
                                    field.fill(digit)
                            if not self._click(page, ['button[type="submit"]', 'button:has-text("Continue")', 'button:has-text("Verify")'], timeout=6):
                                visible_fields[0].press("Enter")
                            otp_submitted = True
                            side_effects["otp_submitted"] = True
                            otp_submitted_at = time.monotonic()
                            phase_started = otp_submitted_at
                            save_checkpoint("email_otp_validate", state="otp_submitted")
                            page.wait_for_timeout(2000)
                            continue
                        if current_stage == "about_you":
                            if side_effects.get("profile_submit_attempted"):
                                page.wait_for_timeout(1200)
                                continue
                            mark("create_account")
                            name = item.name or "OpenAI User"
                            birthdate = item.birthdate or f"{date.today().year - 25:04d}-{date.today().month:02d}-{date.today().day:02d}"
                            side_effects["profile_submit_attempted"] = True
                            save_checkpoint("create_account", state="profile_submit_pending")
                            self._complete_profile(page, name, birthdate)
                            side_effects["profile_submitted"] = True
                            save_checkpoint("create_account", state="submitted_create")
                            page.wait_for_timeout(2000)
                            continue
                        if current_stage == "email_verification":
                            if not otp_submitted:
                                if not side_effects.get("verification_entry_attempted"):
                                    parsed = urlsplit(current_url)
                                    if (parsed.hostname or "").casefold() == "auth.openai.com" and parsed.path.rstrip("/").casefold() == "/email-verification":
                                        button = self._visible(page, [
                                            'button:has-text("Continue to ChatGPT")',
                                            'button:has-text("Continue")',
                                            'button:has-text("Verify")',
                                            'button:has-text("继续")',
                                        ])
                                        if button is not None:
                                            side_effects["verification_entry_attempted"] = True
                                            save_checkpoint("email_verification", state="verification_entry_pending")
                                            button.click(timeout=3000)
                                            page.wait_for_timeout(1500)
                                            continue
                                page.wait_for_timeout(1200)
                                continue
                            if side_effects.get("email_verification_attempted"):
                                page.wait_for_timeout(1200)
                                continue
                            button = self._visible(page, [
                                'button:has-text("Continue to ChatGPT")',
                                'button:has-text("Continue")',
                                'button:has-text("Verify")',
                                'button:has-text("Done")',
                            ])
                            if button is None:
                                page.wait_for_timeout(1200)
                                continue
                            side_effects["email_verification_attempted"] = True
                            save_checkpoint("email_verification", state="verification_submit_pending")
                            button.click(timeout=3000)
                            page.wait_for_timeout(1500)
                            continue
                        page.wait_for_timeout(1200)
        except MailboxError as exc:
            category = "cancelled" if exc.category == "cancelled" else "uncertain"
            return self._fail(item, stage, category, str(exc), checkpoint=checkpoint)
        except RegistrationPersistenceError:
            raise
        except RegistrationFlowError as exc:
            category = "auth_session_pending" if create_confirmed and exc.category != "rate_limited" else exc.category
            message = (("账号已创建；" if create_confirmed else "") + str(exc))
            return self._fail(item, exc.stage, category, message, checkpoint=checkpoint)
        except AuthFlowError as exc:
            category = getattr(exc, "category", "uncertain")
            if category in {"cancelled", "rate_limited"}:
                message = str(exc)
            elif create_confirmed:
                category = "auth_session_pending"
                message = "账号已创建但 OAuth 会话未确认；请恢复会话或人工核对，未自动重放注册请求"
            else:
                if category not in {"cancelled", "rate_limited", "needs_interaction", "existing_account", "partial_registered", "uncertain"}:
                    category = "uncertain"
                message = str(exc)
            return self._fail(item, checkpoint.get("stage", stage), category, message, checkpoint=checkpoint)
        except Exception as exc:
            category = "auth_session_pending" if create_confirmed else "uncertain"
            message = ("账号已创建但注册后续步骤未确认；请恢复会话或人工核对，未自动重放注册请求"
                       if create_confirmed else "注册结果未确认，未自动重放请求")
            last = exc.__traceback__
            while last and last.tb_next:
                last = last.tb_next
            site = f"{Path(last.tb_frame.f_code.co_filename).name}:{last.tb_lineno}" if last else "unknown"
            return self._fail(item, checkpoint.get("stage", stage), category, message,
                              checkpoint=checkpoint, exception_type=type(exc).__name__, exception_site=site)
        finally:
            if callback is not None:
                callback.stop()
            if browser is not None:
                try:
                    browser.close()
                except Exception:
                    pass


def run_batch_registration(
    items: list[RegistrationInput],
    config: dict[str, Any],
    *,
    should_stop: Callable[[], bool] | None = None,
    on_stage: Callable[[str, str], None] | None = None,
    on_progress: Callable[[int, int, RegistrationResult], None] | None = None,
    on_checkpoint: Callable[[int, RegistrationInput, dict[str, Any]], None] | None = None,
    checkpoint_dir: str | Path | None = None,
    adapter: RegistrationAdapter | None = None,
) -> list[RegistrationResult]:
    stop = should_stop or (lambda: False)
    selected = adapter or SafeRegistrationAdapter()
    results: list[RegistrationResult] = []
    root = Path(checkpoint_dir) if checkpoint_dir else None
    if root:
        root.mkdir(parents=True, exist_ok=True)

    def write_checkpoint(path: Path, payload: dict[str, Any]) -> None:
        temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
        try:
            temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

    for index, item in enumerate(items, 1):
        path = root / (hashlib.sha256(item.email.casefold().encode()).hexdigest() + ".json") if root else None

        def persist_checkpoint(payload):
            item.checkpoint = dict(payload or {})
            try:
                if on_checkpoint:
                    on_checkpoint(index, item, dict(item.checkpoint))
                if path:
                    write_checkpoint(path, item.checkpoint)
            except Exception as exc:
                raise RegistrationPersistenceError("注册检查点保存失败，已停止；未继续提交请求") from exc

        if stop():
            result = RegistrationResult(
                item.email,
                category="cancelled",
                error="注册任务已停止",
                registration_state="cancelled",
                checkpoint=_checkpoint(
                    item,
                    item.checkpoint.get("stage", "created"),
                    state="cancelled",
                    side_effects=item.checkpoint.get("side_effects") or {},
                    create_confirmed=item.checkpoint.get("create_confirmed"),
                ),
            )
        elif registration_needs_review(item.checkpoint):
            # Changing drivers must not erase an uncertain live submission.
            category = "auth_session_pending" if item.checkpoint.get("create_confirmed") else "uncertain"
            result = PlaywrightRegistrationAdapter()._fail(item, item.checkpoint.get("stage", "created"),
                category, "已有注册提交待核对；保留恢复记录，未调用注册适配器", checkpoint=item.checkpoint)
        else:
            checkpoint = dict(item.checkpoint or {})
            try:
                result = selected.register(
                    item,
                    config=config,
                    should_stop=stop,
                    on_stage=lambda stage, email=item.email: on_stage(email, stage) if on_stage else None,
                    checkpoint=checkpoint,
                    on_checkpoint=persist_checkpoint,
                )
            except RegistrationPersistenceError:
                raise
            except Exception as exc:  # An uncertain adapter result must be resumable.
                category = "auth_session_pending" if checkpoint.get("create_confirmed") else "uncertain"
                result = RegistrationResult(
                    item.email,
                    category=category,
                    error=("账号已创建但后续步骤未确认，未自动重放请求"
                           if category == "auth_session_pending" else
                           "注册适配器未确认结果，未自动重放请求"),
                    registration_state=category,
                    checkpoint=_checkpoint(
                        item,
                        checkpoint.get("stage", "created"),
                        state=category,
                        error="注册适配器异常；详情未写入公开检查点",
                        side_effects=checkpoint.get("side_effects") or {},
                        create_confirmed=checkpoint.get("create_confirmed"),
                    ),
                )
        if not result.ok:
            persist_checkpoint(result.checkpoint)
        results.append(result)
        if on_progress:
            on_progress(index, len(items), result)
        if result.ok:
            # The encrypted task must contain the successful account before
            # its anti-replay checkpoint is removed.
            persist_checkpoint({})
            if path:
                path.unlink(missing_ok=True)
        if result.category in {"rate_limited", "phone_fraud"}:
            for next_index, pending in enumerate(items[index:], index + 1):
                deferred = RegistrationResult(pending.email, category="not_processed",
                    error="本批次因限流或风控停止；此账号未尝试", checkpoint=dict(pending.checkpoint))
                results.append(deferred)
                if on_progress:
                    on_progress(next_index, len(items), deferred)
            break
        if result.category == "cancelled":
            for pending in items[index:]:
                cancelled = RegistrationResult(
                    pending.email,
                    category="cancelled",
                    error="注册任务已停止",
                    registration_state="cancelled",
                    checkpoint=_checkpoint(
                        pending,
                        pending.checkpoint.get("stage", "created"),
                        state="cancelled",
                        side_effects=pending.checkpoint.get("side_effects") or {},
                        create_confirmed=pending.checkpoint.get("create_confirmed"),
                    ),
                )
                pending.checkpoint = dict(cancelled.checkpoint)
                if on_checkpoint:
                    on_checkpoint(len(results) + 1, pending, dict(pending.checkpoint))
                if root:
                    path = root / (hashlib.sha256(pending.email.casefold().encode()).hexdigest() + ".json")
                    write_checkpoint(path, pending.checkpoint)
                results.append(cancelled)
                if on_progress:
                    on_progress(len(results), len(items), cancelled)
            break
    return results


__all__ = [
    "REGISTRATION_STAGES",
    "RegistrationAdapter",
    "RegistrationInput",
    "RegistrationResult",
    "PlaywrightRegistrationAdapter",
    "SafeRegistrationAdapter",
    "load_registration_inputs",
    "registration_fingerprint",
    "run_batch_registration",
]
