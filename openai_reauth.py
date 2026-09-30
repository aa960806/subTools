#!/usr/bin/env python3
"""Standalone OpenAI Codex OAuth re-auth tool for sub2api account JSON export."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import sys
import threading
import time
from contextlib import ExitStack
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, unquote

import httpx
import pyotp

from reauth_proxy import normalize_proxy, playwright_proxy

from reauth_formats import (
    Accounts, CST, _format_cst, build_account_payload, build_export_payload,
    build_cpa_payload, cpa_to_sub2_account, decode_jwt, extract_user_info,
    parse_datetime_to_unix, is_cpa_payload, is_sub2_wrapper,
    is_sub2_account_payload, is_sub2_payload, load_json_file,
    parse_json_documents, accounts_from_sub2_data, accounts_from_cpa_data,
    detect_payload_kind, parse_accounts_from_text, load_sub2_accounts,
    load_cpa_accounts, safe_email_filename, write_cpa_files, write_export_file,
    conversion_warnings,
)
from human_pacing import (
    HumanSettings,
    human_delay,
    human_settings_from_options,
    type_like_human,
)

CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
AUTHORIZE_URL = "https://auth.openai.com/oauth/authorize"
TOKEN_URL = "https://auth.openai.com/oauth/token"
DEFAULT_REDIRECT_URI = "http://localhost:1455/auth/callback"
DEFAULT_SCOPES = "openid profile email offline_access"
CODEX_UA = "codex-tui/0.146.0 (Ubuntu 22.4.0; x86_64) xterm-256color"
CODEX_ORIGINATOR = "codex-tui"
CALLBACK_PORT = 1455
TOOL_DIR = Path(__file__).resolve().parent
DEBUG_DIR = TOOL_DIR / "debug"

CONTINUE_BUTTON_NAMES = re.compile(
    r"^(Continue|Log in|Sign in|Next|Verify|Submit|Allow|Authorize|"
    r"Accept|Agree|Confirm|Continue to Codex|Continue to ChatGPT)$",
    re.I,
)
OTP_OPTION_NAMES = re.compile(
    r"authenticator|authentication app|one-time password|otp|totp|use a code",
    re.I,
)
PASSKEY_ESCAPE_NAMES = re.compile(
    r"use password|try another way|other options|use a different method|not now|skip",
    re.I,
)
WORKSPACE_PROMPT = re.compile(
    r"(?:select|choose).{0,30}(?:workspace|organization|account)|"
    r"(?:选择|選擇).{0,12}(?:工作空间|工作空間|工作区|工作區|组织|組織)",
    re.I,
)
WORKSPACE_PERSONAL = re.compile(
    # Workspace avatars may contribute one or two letters to a label's text.
    r"^(?:[a-z]{1,3}\s*)?(?:Personal(?: account| workspace)?|"
    r"个人(?:账户|帐户|账号|工作空间|工作区)|個人(?:帳戶|賬戶|帳號|工作空間|工作區))$",
    re.I,
)
WORKSPACE_CONTINUE = re.compile(
    r"^(?:Continue|Next|Confirm|Continue to Codex|Continue to ChatGPT|继续|繼續|下一步|确认|確認)$",
    re.I,
)


from account_inputs import AccountInput, parse_account_line, parse_accounts_text, load_accounts


@dataclass
class OAuthSession:
    state: str
    code_verifier: str = field(repr=False)
    redirect_uri: str
    auth_url: str


@dataclass
class CallbackResult:
    code: str | None = None
    state: str | None = None
    error: str | None = None
    error_description: str | None = None


@dataclass
class ReauthResult:
    email: str
    ok: bool
    account: dict[str, Any] | None = field(default=None, repr=False)
    error: str | None = None
    category: str = "failed"
    # OAuth success and phone binding are deliberately tracked separately.
    # ``ok`` keeps its historical meaning (the OAuth token exchange succeeded),
    # while phone_status tells the phone workflow whether a binding was actually
    # attempted and accepted by the page/API.
    phone_status: str = "not_requested"
    phone_info: dict[str, Any] | None = field(default=None, repr=False)
    phone_error: str | None = None


from flow_control import AuthFlowError, check_running


def check_cancelled(should_stop: Callable[[], bool] | None) -> None:
    if should_stop and should_stop():
        raise AuthFlowError("cancelled", "已取消当前账号")


def redact_diagnostic(message: str, secrets_to_hide: tuple[str, ...] = ()) -> str:
    text = str(message)
    for secret in sorted(filter(None, secrets_to_hide), key=len, reverse=True):
        text = text.replace(secret, "[redacted]")
    text = re.sub(r"https?://[^\s<>\"']+", "[url]", text)
    text = re.sub(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[token]", text)
    return text[:1200]


_log_callback: Callable[[str], None] | None = None


def set_log_callback(callback: Callable[[str], None] | None) -> None:
    global _log_callback
    _log_callback = callback


def log(message: str) -> None:
    stamp = datetime.now().strftime("%H:%M:%S")
    line = f"[{stamp}] {message}"
    if _log_callback is not None:
        _log_callback(line)
    else:
        print(line, flush=True)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def generate_oauth_session(redirect_uri: str = DEFAULT_REDIRECT_URI) -> OAuthSession:
    state = secrets.token_bytes(32).hex()
    code_verifier = secrets.token_bytes(64).hex()
    code_challenge = b64url(hashlib.sha256(code_verifier.encode("ascii")).digest())
    params = {
        "client_id": CLIENT_ID,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "codex_cli_simplified_flow": "true",
        "id_token_add_organizations": "true",
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": DEFAULT_SCOPES,
        "state": state,
    }
    auth_url = f"{AUTHORIZE_URL}?{urlencode(sorted(params.items()))}"
    return OAuthSession(
        state=state,
        code_verifier=code_verifier,
        redirect_uri=redirect_uri,
        auth_url=auth_url,
    )


def exchange_code(
    code: str,
    code_verifier: str,
    redirect_uri: str,
    proxy: str | None,
    *,
    trust_env: bool = False,
) -> dict[str, Any]:
    proxy = normalize_proxy(proxy)
    form = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }
    headers = {
        "User-Agent": CODEX_UA,
        "originator": CODEX_ORIGINATOR,
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    # Do not redirect a request containing a code/verifier or blindly retry a
    # single-use authorization code after an ambiguous network timeout.
    try:
        with httpx.Client(proxy=proxy, timeout=httpx.Timeout(25.0, connect=10.0), follow_redirects=False, trust_env=trust_env) as client:
            response = client.post(TOKEN_URL, data=form, headers=headers)
    except httpx.TimeoutException as exc:
        raise AuthFlowError("network", "换票超时，兑换结果未知；请重新授权，不重用授权码") from exc
    except httpx.HTTPError as exc:
        raise AuthFlowError("network", "无法连接 token 接口，请检查网络或代理") from exc
    if response.status_code == 429:
        raise AuthFlowError("rate_limited", "token 接口限流（HTTP 429）")
    if response.status_code != 200:
        raise AuthFlowError("oauth_error", f"token exchange failed: HTTP {response.status_code}")
    try:
        data = response.json()
    except ValueError as exc:
        raise AuthFlowError("oauth_error", "token 接口返回的内容不是有效 JSON") from exc
    if not isinstance(data, dict):
        raise AuthFlowError("oauth_error", "token 接口返回的数据结构无效")
    for key in ("access_token", "refresh_token", "id_token"):
        if not isinstance(data.get(key), str) or not data[key].strip():
            raise AuthFlowError("oauth_error", f"token 接口缺少 {key}，本次授权未完成")
    return data


class CallbackServer:
    def __init__(self, port: int = CALLBACK_PORT) -> None:
        self.port = port
        self._lock = threading.Lock()
        self._event = threading.Event()
        self._result = CallbackResult()
        self._expected_state: str | None = None
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                parsed = urlparse(self.path)
                query = parse_qs(parsed.query)
                if parsed.path != "/auth/callback":
                    self.send_response(404)
                    self.end_headers()
                    return
                result = CallbackResult(
                    code=(query.get("code") or [None])[0],
                    state=(query.get("state") or [None])[0],
                    error=(query.get("error") or [None])[0],
                    error_description=(query.get("error_description") or [None])[0],
                )
                valid_shape = all(len(query.get(key, [])) <= 1 for key in ("code", "state", "error"))
                accepted = valid_shape and outer.set_result(result)
                body = (b"<html><body>Authorization received. You can close this window.</body></html>"
                        if accepted else b"Invalid or expired authorization callback.")
                self.send_response(200 if accepted else 400)
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
                return

        self._handler = Handler

    def set_result(self, result: CallbackResult) -> bool:
        with self._lock:
            if (not self._expected_state or not isinstance(result.state, str) or not result.state.isascii()
                    or not secrets.compare_digest(result.state, self._expected_state)
                    or bool(result.code) == bool(result.error)):
                return False
            if self._result.code or self._result.error:
                return False
            self._result = result
            self._event.set()
            return True

    def reset(self, expected_state: str | None = None) -> None:
        with self._lock:
            self._expected_state = expected_state
            self._result = CallbackResult()
            self._event.clear()

    def wait(self, timeout: float) -> CallbackResult | None:
        if not self._event.wait(timeout):
            return None
        with self._lock:
            return self._result

    def start(self) -> None:
        # On Windows SO_REUSEADDR can allow a second listener on an active port.
        class ExclusiveServer(ThreadingHTTPServer):
            allow_reuse_address = False
            daemon_threads = True

        httpd = ExclusiveServer(("127.0.0.1", self.port), self._handler)
        self.port = httpd.server_port
        self._httpd = httpd
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        self._thread = thread

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
        self.reset()


def parse_playwright_proxy(proxy: str) -> dict[str, str]:
    return playwright_proxy(proxy)


def _system_chrome_executables() -> list[str]:
    """Prefer installed Windows Chrome over a stale per-user channel entry."""
    if sys.platform != "win32":
        return []
    candidates = []
    seen = set()
    for variable in ("ProgramFiles", "ProgramFiles(x86)"):
        root = os.environ.get(variable)
        if not root:
            continue
        executable = Path(root) / "Google" / "Chrome" / "Application" / "chrome.exe"
        key = str(executable).casefold()
        if key not in seen and executable.is_file():
            candidates.append(str(executable))
            seen.add(key)
    return candidates


def launch_browser(
    playwright: Any, headless: bool, proxy: str | None, *, phone_workflow: bool = False,
) -> Any:
    from reauth_proxy_bridge import browser_proxy_context

    # Phone verification extends the existing authorization login flow; it
    # shares that flow's launch configuration and browser preference.
    kwargs: dict[str, Any] = {
        "headless": headless,
        "args": ["--disable-blink-features=AutomationControlled"],
        "ignore_default_args": ["--enable-automation"],
    }
    if headless:
        kwargs["args"] = list(kwargs["args"]) + ["--headless=new"]
    last_error: Exception | None = None
    channels = ("msedge", None, "chrome") if headless else ("chrome", "msedge", None)
    targets = [("chrome（系统安装）", {"executable_path": path}) for path in _system_chrome_executables()] if phone_workflow and not headless else []
    targets.extend((channel or "bundled chromium", {"channel": channel} if channel else {}) for channel in channels)
    resources = ExitStack()
    try:
        config = resources.enter_context(browser_proxy_context(proxy))
        if config:
            kwargs["proxy"] = config
        else:
            # All workflows resolve one explicit network path before launch.
            kwargs["args"] = list(kwargs["args"]) + ["--no-proxy-server"]
        for label, target in targets:
            try:
                browser = playwright.chromium.launch(**target, **kwargs)
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                log(f"浏览器启动失败（{label}）：{type(exc).__name__}")
                continue
            try:
                browser.on("disconnected", lambda *_: resources.close())
            except Exception:
                browser.close()
                raise
            log(f"浏览器已启动（{'静默' if headless else '可见'} / {label}）")
            if phone_workflow:
                log(f"接码浏览器：{label} / Chromium {browser.version} / {'静默' if headless else '可见'} / 复用授权登录配置")
            return browser
    except BaseException:
        resources.close()
        raise
    resources.close()
    raise RuntimeError("无法启动浏览器；请安装 Edge/Chrome 或运行 python -m playwright install chromium") from last_error


def first_visible(page: Any, selectors: list[str], timeout_ms: int = 400) -> Any | None:
    for selector in selectors:
        locator = page.locator(selector)
        try:
            if locator.count() == 0:
                continue
            for index in range(min(locator.count(), 12)):
                target = locator.nth(index)
                if target.is_visible(timeout=timeout_ms):
                    return target
        except Exception:
            continue
    return None


def click_named_button(page: Any, pattern: re.Pattern[str]) -> bool:
    try:
        buttons = page.get_by_role("button")
        count = buttons.count()
    except Exception:
        return False
    for index in range(count):
        button = buttons.nth(index)
        try:
            if not button.is_visible():
                continue
            name = (button.inner_text() or "").strip()
            if pattern.search(name):
                button.click()
                return True
        except Exception:
            continue
    return False


def page_text(page: Any) -> str:
    try:
        return page.inner_text("body")
    except Exception:
        return ""


def visible_error_text(page: Any) -> str:
    selectors = [
        '[role="alert"]',
        '[aria-live="assertive"]',
        '[class*="error" i]',
        '[class*="Error" i]',
        '[data-type="error"]',
    ]
    chunks: list[str] = []
    for selector in selectors:
        locator = page.locator(selector)
        try:
            count = min(locator.count(), 12)
        except Exception:
            continue
        for index in range(count):
            node = locator.nth(index)
            try:
                if not node.is_visible():
                    continue
                text = (node.inner_text() or "").strip()
            except Exception:
                continue
            if text and text not in chunks:
                chunks.append(text)
    return "\n".join(chunks)


def form_is_busy(page: Any) -> bool:
    busy = page.locator('button[aria-busy="true"], button[class*="loading" i], fieldset[disabled]')
    try:
        count = min(busy.count(), 8)
    except Exception:
        return False
    for index in range(count):
        try:
            if busy.nth(index).is_visible():
                return True
        except Exception:
            continue
    return False


def save_debug(page: Any, email: str, reason: str) -> None:
    """Write only a coarse diagnostic; never persist login DOM or screenshots."""
    DEBUG_DIR.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9._@-]+", "_", email)[:80]
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    diagnostic = DEBUG_DIR / f"{safe}-{stamp}.txt"
    try:
        diagnostic.write_text(f"reason={redact_diagnostic(reason)}\n", encoding="utf-8")
    except OSError:
        log("无法保存诊断信息")


def current_totp(secret: str) -> str:
    return pyotp.TOTP(secret).now()


def fill_otp(page: Any, secret: str) -> bool:
    if not str(secret or "").strip():
        return False
    # A code with less than three seconds left often expires while submitting.
    if time.time() % 30 > 27:
        return False
    code = current_totp(secret)
    boxes = page.locator('input[maxlength="1"]')
    try:
        if boxes.count() >= 6:
            for index, digit in enumerate(code):
                boxes.nth(index).fill(digit)
            return True
    except Exception:
        pass
    otp = first_visible(
        page,
        [
            'input[autocomplete="one-time-code"]',
            'input[name="code"]',
            'input[name="otp"]',
            'input[name="totp"]',
            'input[inputmode="numeric"]',
            'input[aria-label*="code" i]',
        ],
    )
    if otp is None:
        return False
    otp.fill(code)
    return True


def maybe_handle_passkey_or_method_picker(page: Any) -> None:
    text = page_text(page)
    if re.search(r"passkey|security key", text, re.I):
        click_named_button(page, PASSKEY_ESCAPE_NAMES)
    if re.search(r"choose how to sign in|verification method|authenticate", text, re.I):
        try:
            option = page.get_by_text(OTP_OPTION_NAMES)
            if option.count() and option.first.is_visible():
                option.first.click()
                return
        except Exception:
            pass
        click_named_button(page, OTP_OPTION_NAMES)


def maybe_select_workspace(page: Any) -> bool:
    text = page_text(page)
    if not WORKSPACE_PROMPT.search(text):
        return False
    try:
        radios = page.locator('input[type="radio"], [role="radio"]')
        candidates = []
        for index in range(radios.count()):
            radio = radios.nth(index)
            details = radio.evaluate("""element => {
                const labels = Array.from(element.labels || []);
                const allLabels = Array.from(document.querySelectorAll('label'));
                const labelledBy = (element.getAttribute('aria-labelledby') || '')
                    .split(/\\s+/).filter(Boolean)
                    .map(id => document.getElementById(id)?.innerText || '').join(' ');
                return {
                    native: element.tagName === 'INPUT',
                    nested: element.tagName === 'INPUT' &&
                        !!element.parentElement?.closest('[role="radio"]'),
                    texts: [element.getAttribute('aria-label') || '', labelledBy,
                        ...labels.map(label => label.innerText), element.innerText || ''],
                    labels: labels.map(label => allLabels.indexOf(label))
                };
            }""")
            if details["nested"]:
                continue
            label = None
            for label_index in details["labels"]:
                associated_label = page.locator("label").nth(label_index)
                if associated_label.is_visible():
                    label = associated_label
                    break
            if not radio.is_visible() and label is None:
                continue
            names = [re.sub(r"\s+", " ", name.replace("\u200b", "")).strip()
                     for name in details["texts"] if name.strip()]
            kind = "personal" if any(WORKSPACE_PERSONAL.fullmatch(name) for name in names) else (
                "organization" if names else "unknown"
            )
            candidates.append({
                "radio": radio, "label": label, "native": details["native"],
                "kind": kind, "checked": radio.is_checked(), "enabled": radio.is_enabled(),
            })

        organizations = [item for item in candidates if item["kind"] == "organization"]
        # A checked, disabled *only* option is how OpenAI represents a fixed
        # workspace. With multiple options, disabled organizations are not a
        # reason to silently authorize the personal account instead.
        eligible = [item for item in organizations if item["enabled"] or (
            item["checked"] and len(candidates) == 1
        )]
        if not organizations:
            if any(item["kind"] == "unknown" for item in candidates):
                return False
            eligible = [item for item in candidates if item["kind"] == "personal" and (
                item["enabled"] or (item["checked"] and len(candidates) == 1)
            )]
        if not eligible:
            return False
        selected = next((item for item in eligible if item["checked"]), eligible[0])
        radio = selected["radio"]
        if not radio.is_checked():
            if selected["label"] is not None:
                selected["label"].click(timeout=1500)
            elif selected["native"]:
                radio.check(timeout=1500)
            else:
                radio.click(timeout=1500)
        # Never submit on a click alone: custom controls may ignore the click,
        # and submitting then could grant the still-selected personal account.
        if not radio.is_checked():
            return False
        buttons = page.get_by_role("button", name=WORKSPACE_CONTINUE)
        for index in range(buttons.count()):
            button = buttons.nth(index)
            if button.is_visible() and button.is_enabled():
                button.click(timeout=1500)
                log("已选择非个人工作空间" if selected["kind"] == "organization" else "已选择个人工作空间")
                return True
    except Exception:
        pass
    return False


LEGAL_FOOTER_NOISE = re.compile(
    r"your chatgpt rate limits apply|"
    r"codex can make mistakes|"
    r"privacy policy apply",
    re.I | re.S,
)


def sanitize_login_text(text: str) -> str:
    cleaned = LEGAL_FOOTER_NOISE.sub(" ", text or "")
    return re.sub(r"\s+", " ", cleaned).strip()


SKIPPABLE_AUTH_ERRORS = (
    "account deactivated",
    "account deleted",
    "account not found",
    "incorrect email or password",
    "too many login attempts",
)


def fatal_login_error(text: str) -> str | None:
    cleaned = sanitize_login_text(text)
    if not cleaned:
        return None
    patterns = [
        (r"incorrect (email|password)|wrong password|invalid password|email or password is incorrect", "incorrect email or password"),
        (r"too many (login )?attempts|too many tries|too many requests|rate limit exceeded", "too many login attempts"),
        (r"couldn't find your account|account not found|no account found", "account not found"),
        (
            r"account_deactivated|"
            r"account[_ ]deleted|"
            r"has been deleted or deactivated|"
            r"deleted or deactivated|"
            r"account (has been )?(suspended|disabled|deactivated)",
            "account deactivated",
        ),
        (r"unusual activity|verify you.?re human|suspicious activity", "blocked by additional verification"),
    ]
    for pattern, message in patterns:
        if re.search(pattern, cleaned, re.I):
            return message
    return None


def is_terminal_auth_error(text: str) -> str | None:
    """Errors that should skip immediately, even before password is submitted."""
    fatal = fatal_login_error(text)
    if fatal in {
        "account deactivated",
        "account deleted",
        "account not found",
        "incorrect email or password",
        "too many login attempts",
        "blocked by additional verification",
    }:
        return fatal
    return None


PHONE_PAGE_HEADING = re.compile(
    r"(?:(?:verify|add|enter|confirm) (?:your |a )?(?:mobile|phone)(?: number)?|"
    r"(?:mobile|phone)(?: number)? verification(?: required)?|verify (?:your )?(?:SMS|text message) code|"
    r"(?:添加|绑定|验证|输入)(?:您的|你的)?(?:手机|手机号|手机号码)|"
    r"手机验证|短信验证|短信验证码)[.!！。:：?？]?", re.I,
)
PHONE_MENTION = re.compile(r"(verify|add|enter) (your )?phone number|phone verification", re.I)


def phone_page_evidence(page: Any, path: str) -> str:
    """Return a fixed, non-sensitive reason; body copy alone is not a challenge."""
    route = re.search(r"/(add-phone|phone-verification|phone-otp)/?$", path, re.I)
    if route:
        return "路由=/" + route.group(1).lower()
    try:
        # A secondary heading can describe an unused method alongside TOTP.
        # Require a page title or a legend scoped to the form being inspected.
        headings = page.locator('h1, [role="heading"][aria-level="1"], form legend')
        for index in range(min(headings.count(), 12)):
            node = headings.nth(index)
            if not node.is_visible() or not PHONE_PAGE_HEADING.fullmatch(sanitize_login_text(node.inner_text())):
                continue
            scope = node.locator('xpath=ancestor::form[1]')
            if scope.count() == 0:
                scope = page
            phone = first_visible(scope, [
                'input[type="tel"]:not([autocomplete="one-time-code"]):not([maxlength="1"])',
                'input[autocomplete="tel"]', 'input[name="phone_number"]', 'input[name="phoneNumber"]',
            ])
            if phone is not None:
                return "页面=手机验证；可见表单=手机号"
            code = first_visible(scope, [
                'input[autocomplete="one-time-code"]', 'input[name="code"]',
                'input[name="otp"]', 'input[maxlength="1"]',
            ])
            if code is not None:
                return "页面=手机验证；可见表单=验证码"
    except Exception:
        # A disappearing heading during navigation is not a confirmed phone page.
        pass
    return ""


def login_with_browser(
    page: Any,
    account: AccountInput,
    session: OAuthSession,
    callback: CallbackServer,
    timeout: float,
    should_stop: Callable[[], bool] | None = None,
    headless: bool = True,
    phone_handler: Callable[..., Any] | None = None,
    phone_state: dict[str, Any] | None = None,
    email_login: Any = None,
    skip_phone_verification: bool = False,
    human: HumanSettings | None = None,
) -> CallbackResult:
    check_cancelled(should_stop)
    callback.reset(session.state)
    deadline = time.monotonic() + timeout
    if email_login is not None:
        email_login.prime(deadline, should_stop)
    log(f"{account.email}: 正在打开授权页")
    human_delay(human, "open_page", should_stop=should_stop, deadline=deadline, log_fn=log)
    navigation = page.goto(session.auth_url, wait_until="domcontentloaded", timeout=min(30_000, int(timeout * 1000)))
    human_delay(human, "page_settle", should_stop=should_stop, deadline=deadline, log_fn=log)
    if phone_handler is not None and navigation is not None:
        status = navigation.status
        if isinstance(status, int) and not isinstance(status, bool) and status >= 400:
            # A blocked document can lack both login fields and the usual
            # challenge wording. Do not spend the entire phone budget waiting
            # for a form that this HTTP error page never supplied.
            cloudflare = status == 403 and "cloudflare" in page_text(page).lower()
            detail = "，Cloudflare 拒绝/验证页面" if cloudflare else ""
            reason = f"授权登录页返回 HTTP {status}{detail}；尚未进入手机号页，未调用接码"
            if status == 403 and not headless:
                # Visible mode still allows the user to inspect the page and
                # manually continue; never try to bypass a browser challenge.
                log(f"{account.email}: {reason}；等待浏览器中人工检查")
            else:
                category = "rate_limited" if status == 429 else "needs_interaction" if status == 403 else "network"
                action = "请开启显示浏览器检查登录页，并核对网络模式" if status == 403 else "请检查登录服务与网络后重试"
                raise AuthFlowError(category, f"{reason}；{action}")

    filled_email = False
    filled_password = False
    filled_otp = False
    otp_retry_at = 0.0
    last_action = 0.0
    remaining = timeout
    manual_reason = ""
    pending_interaction = ""
    interaction_since = 0.0
    phone_handled = False
    pending_phone = ""
    phone_since = 0.0
    phone_notice_logged = False

    while time.monotonic() < deadline:
        check_cancelled(should_stop)
        remaining = deadline - time.monotonic()
        result = callback.wait(0.15)
        if result is not None:
            return result
        try:
            current_url = page.url
        except Exception:
            current_url = ""
        parsed = urlparse(current_url)
        redirect = urlparse(session.redirect_uri)
        if (parsed.scheme, parsed.hostname, parsed.port, parsed.path) == (redirect.scheme, redirect.hostname, redirect.port, redirect.path):
            query = parse_qs(parsed.query)
            candidate = CallbackResult(
                code=(query.get("code") or [None])[0],
                state=(query.get("state") or [None])[0],
                error=(query.get("error") or [None])[0],
                error_description=(query.get("error_description") or [None])[0],
            )
            if all(len(query.get(key, [])) <= 1 for key in ("code", "state", "error")) and callback.set_result(candidate):
                return candidate

        text = page_text(page)
        error_text = visible_error_text(page)
        combined = f"{error_text}\n{text}"
        terminal = is_terminal_auth_error(combined)
        # Account failures and rate limits take precedence over phone-page
        # detection; a stale add-phone URL must never trigger a paid purchase.
        if terminal and terminal != "blocked by additional verification":
            category = "rate_limited" if terminal == "too many login attempts" else "failed"
            raise AuthFlowError(category, terminal)
        if form_is_busy(page):
            pending_phone = ""
            time.sleep(0.2)
            continue

        phone_evidence = phone_page_evidence(page, parsed.path)
        if phone_evidence:
            # Give redirects and stale page contents a bounded settling window.
            # No SMS purchase or TOTP submission occurs during this observation.
            if pending_phone != phone_evidence:
                pending_phone, phone_since = phone_evidence, time.monotonic()
            if time.monotonic() - phone_since < 1.0:
                time.sleep(0.15)
                continue
            if skip_phone_verification or phone_handler is None:
                raise AuthFlowError("phone_required", f"待补手机：已确认手机验证页面（{phone_evidence}），已跳过，未调用自动接码")
            if phone_handled:
                time.sleep(0.2)
                continue
            log(f"{account.email}: 已确认手机验证（{phone_evidence}），开始自动接码")
            if phone_state is not None:
                phone_state["attempted"] = True
                phone_state["status"] = "attempted"
            try:
                phone_result = phone_handler(page, account, should_stop, deadline=deadline)
            except Exception as exc:
                # Order bookkeeping happens after OpenAI accepts the code. The
                # phone flow may wrap a persistence/cleanup error, so preserve
                # confirmed binding details across its exception chain.
                pending_errors = [exc]
                visited_errors: set[int] = set()
                confirmed_info = None
                while pending_errors:
                    error = pending_errors.pop()
                    if id(error) in visited_errors:
                        continue
                    visited_errors.add(id(error))
                    info = getattr(error, "phone_info", None)
                    if isinstance(info, dict) and info.get("status") == "verified":
                        confirmed_info = dict(info)
                        break
                    pending_errors.extend(item for item in (error.__cause__, error.__context__) if item is not None)
                if confirmed_info is not None:
                    if phone_state is not None:
                        phone_state["status"] = "verified"
                        phone_state["info"] = confirmed_info
                    raise AuthFlowError("sms_cleanup_required", "手机号已绑定，但短信订单记录或收尾失败，已停止后续账号") from exc
                raise
            phone_handled = True
            if phone_state is not None:
                phone_state["result"] = phone_result
                if isinstance(phone_result, dict):
                    phone_state["info"] = phone_result
                    status = str(phone_result.get("status") or "unconfirmed").lower()
                    phone_state["status"] = "verified" if status in {
                        "ok", "success", "verified", "bound", "completed",
                    } else status
                elif phone_result is True:
                    phone_state["status"] = "verified"
            last_action = time.time()
            continue
        pending_phone = ""
        if not phone_notice_logged and PHONE_MENTION.search(combined):
            log(f"{account.email}: 页面含手机验证相关说明，但未确认手机号验证路由或表单，继续授权")
            phone_notice_logged = True

        if email_login is not None and email_login.handle_page(page, text, deadline, should_stop):
            continue
        maybe_handle_passkey_or_method_picker(page)
        if maybe_select_workspace(page):
            continue

        interaction = ""
        if terminal == "blocked by additional verification" or first_visible(page, ["iframe[src*='challenges.cloudflare.com']", "iframe[src*='recaptcha']"], 200):
            interaction = "需要手动完成人机验证"
        elif re.search(r"check your (email|inbox)|(?:we(?:'ve| have)?\s+)?sent (?:you )?(?:a |an |the )?(?:verification |security )?code|code (?:has been |was )?sent to", text, re.I):
            interaction = "需要邮箱验证码"
        elif WORKSPACE_PROMPT.search(text):
            interaction = "需要选择工作区或组织"
        if interaction:
            if headless:
                # Text can render before the workspace controls. Give the page
                # a short, bounded settling period before requiring a person.
                if pending_interaction != interaction:
                    pending_interaction, interaction_since = interaction, time.monotonic()
                if time.monotonic() - interaction_since < 2:
                    time.sleep(0.15)
                    continue
                raise AuthFlowError("needs_interaction", interaction + "；请使用显示浏览器重试")
            if manual_reason != interaction:
                log(f"{account.email}: {interaction}，等待操作")
                manual_reason = interaction
            time.sleep(0.3)
            continue
        pending_interaction = ""

        now = time.time()
        if now - last_action < 0.7:
            continue

        email_input = first_visible(
            page,
            [
                'input[type="email"]',
                'input[name="email"]',
                'input[name="username"]',
                "input#email-input",
                "input#username",
                'input[autocomplete="username"]',
                'input[autocomplete="email"]',
            ],
        )
        password_input = first_visible(
            page,
            [
                'input[type="password"]',
                'input[name="password"]',
                "input#password",
                'input[autocomplete="current-password"]',
            ],
        )

        if email_input is not None and password_input is None and not filled_email:
            human_delay(human, "type_email", should_stop=should_stop, deadline=deadline, log_fn=log)
            if not type_like_human(email_input, account.email, human, should_stop=should_stop, deadline=deadline, log_fn=log):
                email_input.fill(account.email)
            filled_email = True
            last_action = now
            human_delay(human, "click", should_stop=should_stop, deadline=deadline, log_fn=log)
            if not click_named_button(page, CONTINUE_BUTTON_NAMES):
                email_input.press("Enter")
            human_delay(human, "after_email", should_stop=should_stop, deadline=deadline, log_fn=log)
            log(f"{account.email}: 已提交邮箱")
            continue

        if password_input is not None and not filled_password:
            if not str(account.password or "").strip():
                if not headless:
                    if manual_reason != "password":
                        log(f"{account.email}: 缺少登录密码，请在浏览器中完成登录")
                        manual_reason = "password"
                    time.sleep(0.2)
                    continue
                raise AuthFlowError("failed", "该账号没有登录密码，请补充密码、邮箱接码地址或显示浏览器手动登录")
            if email_input is not None and not (email_input.input_value() or "").strip():
                email_input.fill(account.email)
            human_delay(human, "type_password", should_stop=should_stop, deadline=deadline, log_fn=log)
            if not type_like_human(password_input, account.password, human, should_stop=should_stop, deadline=deadline, log_fn=log):
                password_input.fill(account.password)
            filled_password = True
            last_action = now
            human_delay(human, "click", should_stop=should_stop, deadline=deadline, log_fn=log)
            if not click_named_button(page, CONTINUE_BUTTON_NAMES):
                password_input.press("Enter")
            human_delay(human, "after_password", should_stop=should_stop, deadline=deadline, log_fn=log)
            log(f"{account.email}: 已提交密码")
            continue

        otp_needed = bool(
            first_visible(
                page,
                [
                    'input[autocomplete="one-time-code"]',
                    'input[name="code"]',
                    'input[name="otp"]',
                    'input[maxlength="1"]',
                    'input[inputmode="numeric"]',
                ],
            )
            or re.search(r"authenticator|one-time code|enter code|verification code", text, re.I)
        )
        if otp_needed and (not filled_otp or now >= otp_retry_at):
            if not account.totp_secret:
                if headless:
                    raise AuthFlowError("needs_interaction", "账号要求二次验证码但未提供 2FA 密钥；请显示浏览器手动完成")
                if manual_reason != "totp":
                    log(f"{account.email}: 缺少 2FA 密钥，请在浏览器中输入验证码")
                    manual_reason = "totp"
                time.sleep(0.2)
                continue
            # Wait before generating a short-lived TOTP, never after filling it.
            human_delay(human, "click", should_stop=should_stop, deadline=deadline, log_fn=log)
            if fill_otp(page, account.totp_secret):
                filled_otp = True
                otp_retry_at = time.time() + 30
                last_action = now
                check_running(should_stop, deadline)
                if not click_named_button(page, CONTINUE_BUTTON_NAMES):
                    page.keyboard.press("Enter")
                human_delay(human, "after_otp", should_stop=should_stop, deadline=deadline, log_fn=log)
                log(f"{account.email}: 已提交验证码")
                continue
        if otp_needed:
            # Do not let the generic Continue action submit an empty/old code
            # while waiting for the next TOTP window or for server validation.
            time.sleep(0.15)
            continue

        if not (filled_password and password_input is not None and not otp_needed):
            if click_named_button(page, CONTINUE_BUTTON_NAMES):
                last_action = now
                continue

        time.sleep(0.12)

    raise AuthFlowError("needs_interaction", f"登录流程在 {int(timeout)} 秒内未完成；请显示浏览器检查或重试")


def reauth_account(
    browser: Any,
    callback: CallbackServer,
    account: AccountInput,
    timeout: float,
    proxy: str | None,
    headless: bool,
    should_stop: Callable[[], bool] | None = None,
    phone_handler: Callable[..., Any] | None = None,
    skip_phone_verification: bool = False,
    human: HumanSettings | None = None,
) -> ReauthResult:
    session = generate_oauth_session()
    context_options: dict[str, Any] = {
        "locale": "en-US",
        "viewport": {"width": 1280, "height": 900},
    }
    # Keep the browser's native UA consistent with its version and client hints.
    if phone_handler is not None:
        # PhoneSendGuard validates paid requests via page.route; service-worker
        # fetches can bypass page routing, so this flow excludes them explicitly.
        context_options["service_workers"] = "block"
    context = browser.new_context(**context_options)
    page = context.new_page()
    from browser_bridge import attach, detach
    attach(page)
    page.set_default_timeout(3_000)
    phone_state: dict[str, Any] = {"attempted": False, "status": "not_triggered"}
    email_login = None
    try:
        # An explicit mailbox input enables email OTP in every login workflow.
        # Phone verification remains controlled independently by phone_handler.
        if account.mailbox_url:
            from phone_email_login import EmailLogin
            email_login = EmailLogin(account, proxy)
        result = login_with_browser(
            page,
            account,
            session,
            callback,
            timeout,
            should_stop,
            headless,
            phone_handler=phone_handler,
            phone_state=phone_state,
            email_login=email_login,
            human=human,
            **({"skip_phone_verification": True} if skip_phone_verification else {}),
        )
        check_cancelled(should_stop)
        if not result.state or not result.state.isascii() or not secrets.compare_digest(result.state, session.state):
            raise AuthFlowError("oauth_error", "OAuth state mismatch")
        if result.error:
            # Arbitrary callback error_description may echo credentials or URLs.
            raise AuthFlowError("oauth_error", "OAuth 授权被拒绝或未完成")
        if not result.code:
            raise RuntimeError("OAuth callback missing authorization code")
        log(f"{account.email}: 正在换取 token")
        exchange_options = {"trust_env": False}
        token = exchange_code(result.code, session.code_verifier, session.redirect_uri, proxy, **exchange_options)
        payload = build_account_payload(token, account.email)
        log(f"{account.email}: 授权成功（{payload['credentials'].get('plan_type') or '未知套餐'}）")
        phone_status = str(phone_state.get("status") or "not_triggered") if phone_handler else "not_requested"
        # A handler supplied by the phone page is an explicit request to bind a
        # number.  Returning OAuth success without a verified binding must stay
        # visible to the caller rather than being counted as phone success.
        return ReauthResult(
            email=account.email,
            ok=True,
            account=payload,
            category="success",
            phone_status=phone_status,
            phone_info=phone_state.get("info"),
        )
    except Exception as exc:  # noqa: BLE001
        # Playwright exception text can include fill() values. Keep only known
        # application errors; browser call logs are deliberately excluded.
        reason = (str(exc) if isinstance(exc, (AuthFlowError, ValueError))
                  else f"浏览器或网络操作失败（{type(exc).__name__}），请检查连接并重试")
        reason = redact_diagnostic(reason, (account.password, account.totp_secret, account.mailbox_url, session.code_verifier))
        category = getattr(exc, "category", "failed")
        phone_status = str(phone_state.get("status") or "not_triggered") if phone_handler else "not_requested"
        phone_error = None
        if phone_state.get("attempted"):
            if phone_status not in {"verified", "bound", "completed"}:
                phone_error = reason
                phone_status = "failed" if category != "cancelled" else "cancelled"
        log(f"{account.email}: 失败，跳过：{reason}")
        return ReauthResult(
            email=account.email,
            ok=False,
            error=reason,
            category=category,
            phone_status=phone_status,
            phone_info=phone_state.get("info"),
            phone_error=phone_error,
        )
    finally:
        if email_login is not None:
            email_login.close()
        detach()
        callback.reset()
        try:
            context.close()
        except Exception:
            pass


def read_input_text(path: str | None) -> str:
    if path:
        return Path(path).read_text(encoding="utf-8-sig")
    if sys.stdin.isatty():
        log("Paste account lines (email----password----totp), then Ctrl+Z Enter (Windows) or Ctrl+D")
    return sys.stdin.read()


def self_test() -> int:
    account = parse_account_line("a@b.com----p----w----JBSWY3DPEHPK3PXP", 1)
    assert account.email == "a@b.com"
    assert account.password == "p----w"
    session = generate_oauth_session()
    parsed = urlparse(session.auth_url)
    query = parse_qs(parsed.query)
    assert parsed.scheme == "https"
    assert parsed.netloc == "auth.openai.com"
    assert query["client_id"] == [CLIENT_ID]
    assert query["code_challenge_method"] == ["S256"]
    assert query["codex_cli_simplified_flow"] == ["true"]
    assert query["id_token_add_organizations"] == ["true"]
    assert query["redirect_uri"] == [DEFAULT_REDIRECT_URI]
    assert query["scope"] == [DEFAULT_SCOPES]
    assert len(session.code_verifier) == 128
    assert len(session.state) == 64
    header = b64url(json.dumps({"alg": "none"}).encode())
    payload = b64url(json.dumps({"email": "x@y.com", "https://api.openai.com/auth": {"chatgpt_account_id": "acc"}}).encode())
    info = extract_user_info(f"{header}.{payload}.sig", "")
    assert info["email"] == "x@y.com"
    assert info["chatgpt_account_id"] == "acc"
    export = build_export_payload([])
    assert export["type"] == "sub2api-data"
    cpa = build_cpa_payload(
        {
            "name": "a@b.com",
            "credentials": {
                "email": "a@b.com",
                "access_token": "at",
                "refresh_token": "rt",
                "id_token": "id",
                "expires_at": 1789600000,
            },
        }
    )
    assert list(cpa.keys()) == [
        "type",
        "email",
        "expired",
        "id_token",
        "account_id",
        "disabled",
        "access_token",
        "last_refresh",
        "refresh_token",
    ]
    assert cpa["type"] == "codex"
    assert cpa["email"] == "a@b.com"
    assert cpa["disabled"] is False
    assert cpa["expired"].endswith("+08:00")
    converted = cpa_to_sub2_account(cpa)
    assert converted["platform"] == "openai"
    assert converted["type"] == "oauth"
    assert converted["credentials"]["email"] == "a@b.com"
    assert converted["credentials"]["access_token"] == "at"
    assert converted["credentials"]["refresh_token"] == "rt"
    roundtrip = build_cpa_payload(converted)
    assert roundtrip["email"] == "a@b.com"
    assert roundtrip["access_token"] == "at"
    assert parse_datetime_to_unix("2026-09-25T10:02:18.000+08:00") is not None
    kind, parsed_accounts = parse_accounts_from_text(json.dumps(build_export_payload([converted])))
    assert kind == "sub2"
    assert parsed_accounts[0]["credentials"]["email"] == "a@b.com"
    kind, parsed_accounts = parse_accounts_from_text(json.dumps(cpa))
    assert kind == "cpa"
    assert parsed_accounts[0]["credentials"]["access_token"] == "at"
    bare = {
        "name": "a@b.com",
        "platform": "openai",
        "type": "oauth",
        "credentials": {
            "access_token": "at",
            "refresh_token": "rt",
            "email": "a@b.com",
            "expires_at": 1789600000,
        },
        "concurrency": 100,
    }
    kind, parsed_accounts = parse_accounts_from_text(json.dumps(bare))
    assert kind == "sub2"
    assert parsed_accounts[0]["concurrency"] == 100
    assert parsed_accounts[0]["credentials"]["refresh_token"] == "rt"
    footer = (
        "Enter your password\nForgot password?\nContinue\n"
        "ChatGPT Terms of Use and Privacy Policy apply. Your ChatGPT training "
        "controls apply to Codex. Codex can make mistakes, and your ChatGPT rate limits apply."
    )
    assert fatal_login_error(footer) is None
    assert fatal_login_error("Too many login attempts. Try again later.") == "too many login attempts"
    deactivated = (
        "Authentication Error\n"
        "You do not have an account because it has been deleted or deactivated.\n"
        "error_code: account_deactivated"
    )
    assert fatal_login_error(deactivated) == "account deactivated"
    assert is_terminal_auth_error(deactivated) == "account deactivated"
    code = pyotp.TOTP("JBSWY3DPEHPK3PXP").now()
    assert len(code) == 6
    log("self-test passed")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Batch-reauth OpenAI accounts into sub2api JSON")
    parser.add_argument("-i", "--input", help="Account file. Omit to read stdin.")
    parser.add_argument("-o", "--output", default="sub2api-account.json", help="Output JSON path or CPA directory")
    parser.add_argument("--format", choices=("sub2", "cpa"), default="sub2", help="Export format: sub2 one file, cpa one file per email")
    parser.add_argument("--proxy", help="Proxy URL or host:port:username:password; used by browser and token exchange")
    parser.add_argument("--timeout", type=int, default=180, help="Per-account login timeout in seconds")
    parser.add_argument("--headless", action="store_true", default=True, help="Silent browser (default)")
    parser.add_argument("--show-browser", action="store_true", help="Show the browser window for debugging")
    parser.add_argument("--self-test", action="store_true", help="Run local logic checks and exit")
    parser.add_argument("--recovery-dir", default=str(TOOL_DIR / "recovery"), help="Successful accounts are saved here immediately")
    return parser.parse_args(argv)


def run_batch_reauth(
    accounts: list[AccountInput],
    timeout: float = 180,
    proxy: str | None = None,
    headless: bool = True,
    should_stop: Callable[[], bool] | None = None,
    on_progress: Callable[[int, int, ReauthResult], None] | None = None,
    recovery_dir: str | Path | None = TOOL_DIR / "recovery",
    phone_handler: Callable[..., Any] | None = None,
    skip_phone_verification: bool = False,
    human: HumanSettings | None = None,
    result_transform: Callable[[AccountInput, ReauthResult], ReauthResult] | None = None,
) -> list[ReauthResult]:
    if not accounts:
        raise ValueError("没有账号")
    if timeout <= 0:
        raise ValueError("超时时间必须大于零")
    proxy = normalize_proxy(proxy)
    recovery_file: Path | None = None
    if recovery_dir is not None:
        run_dir = Path(recovery_dir) / (datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(4))
        run_dir.mkdir(parents=True, exist_ok=False)
        recovery_file = run_dir / "accounts.json"
        # Verify persistence before starting any authorization.
        write_export_file(recovery_file, [])
        log(f"成功结果自动保存到：{recovery_file}")

    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError("未安装 playwright。请先运行：pip install -r requirements.txt") from exc

    callback = CallbackServer(CALLBACK_PORT)
    try:
        callback.start()
    except OSError as exc:
        raise RuntimeError(
            f"端口 {CALLBACK_PORT} 已被占用，请关闭 Codex 或本地回调服务后重试（{exc}）"
        ) from exc
    log(f"回调服务已启动：{DEFAULT_REDIRECT_URI}")
    if headless:
        log("静默授权中，不弹出网页，进度只显示在日志里")

    results: list[ReauthResult] = []
    try:
        with sync_playwright() as playwright:
            launch_options = {"phone_workflow": True} if phone_handler is not None else {}
            browser = launch_browser(playwright, headless=headless, proxy=proxy, **launch_options)
            try:
                for index, account in enumerate(accounts, start=1):
                    if should_stop is not None and should_stop():
                        log("已停止后续账号")
                        break
                    if index > 1:
                        try:
                            human_delay(human, "between_accounts", should_stop=should_stop,
                                        log_fn=log, reason="上一个账号已结束")
                        except AuthFlowError as exc:
                            if exc.category != "cancelled":
                                raise
                            break
                    log(f"[{index}/{len(accounts)}] 开始 {account.email}")
                    result = reauth_account(
                        browser=browser,
                        callback=callback,
                        account=account,
                        timeout=timeout,
                        proxy=proxy,
                        headless=headless,
                        should_stop=should_stop,
                        human=human,
                        phone_handler=phone_handler,
                        **({"skip_phone_verification": True} if skip_phone_verification else {}),
                    )
                    if result_transform is not None:
                        result = result_transform(account, result)
                    results.append(result)
                    if result.ok and recovery_file is not None:
                        try:
                            write_export_file(recovery_file, [r.account for r in results if r.ok and r.account])
                        except OSError as exc:
                            log("自动保存失败，已暂停后续账号；请立即手动保存现有结果")
                            if on_progress is not None:
                                on_progress(index, len(accounts), result)
                            break
                    if phone_handler is None:
                        state = "成功" if result.ok else f"失败（{result.error}）"
                    elif result.phone_status == "verified":
                        state = "手机号绑定成功" + ("，OAuth 已完成" if result.ok else f"，OAuth 未完成（{result.error}）")
                    elif result.ok:
                        state = "OAuth 已完成，本次未确认手机号绑定"
                    else:
                        state = f"接码未完成（{result.error}）"
                    log(f"[{index}/{len(accounts)}] {state}  {account.email}")
                    if on_progress is not None:
                        on_progress(index, len(accounts), result)
                    if result.category == "rate_limited":
                        log("检测到限流，已暂停本批次，剩余账号未尝试；稍后可重试")
                        break
                    if result.category == "cancelled":
                        break
                    if phone_handler is not None and result.category in {"sms_fatal", "sms_cleanup_required", "sms_cancelled", "sms_network", "circuit_open", "phone_fraud"}:
                        log(f"短信服务无法继续，本批次已停止；剩余账号未尝试：{result.error or result.category}")
                        break
            finally:
                browser.close()
    finally:
        callback.stop()
    return results


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if args.self_test:
        return self_test()

    try:
        accounts = load_accounts(read_input_text(args.input))
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    log(f"已加载 {len(accounts)} 个账号")

    try:
        from oauth_refresh import run_refresh_first
        results = run_refresh_first(
            accounts,
            authorize=run_batch_reauth,
            timeout=float(args.timeout),
            proxy=args.proxy,
            headless=not args.show_browser,
            recovery_dir=args.recovery_dir,
        )
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc

    ok_accounts = [item.account for item in results if item.ok and item.account]
    failed = [item for item in results if not item.ok]
    for warning in conversion_warnings(ok_accounts, args.format):
        log(f"转换提示：{warning}")
    if args.format == "cpa":
        written = write_cpa_files(args.output, ok_accounts)
        log(f"已按 CPA 格式写入 {len(written)} 个文件到 {args.output}")
    else:
        output_path = write_export_file(args.output, ok_accounts)
        log(f"已按 sub2 格式写入 {len(ok_accounts)} 个账号到 {output_path}")
    if failed or len(results) < len(accounts):
        for item in failed:
            log(f"FAILED {item.email}: {item.error}")
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        log("interrupted")
        raise SystemExit(130)
