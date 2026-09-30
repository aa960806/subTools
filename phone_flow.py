"""Existing-account phone verification using SMSBower and Playwright."""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from contextlib import nullcontext
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4
from urllib.parse import urlparse

import pyotp

from openai_reauth import (
    AccountInput,
    AuthFlowError,
    click_named_button,
    first_visible,
    form_is_busy,
    log,
    page_text,
    visible_error_text,
    parse_account_line,
    run_batch_reauth,
)
from phone_pool import PhonePool, PhonePoolError, SmsbowerSettings, phone_retry_plan
from phone_form import PHONE_INPUTS, fill_phone_number, ensure_sms_channel
from phone_request import PhoneSendGuard, masked_phone, response_diagnostic
from phone_smsbower import SmsBowerError, country_label, normalize_phone
from human_pacing import HumanSettings, human_delay, human_settings_from_options, type_like_human
from phone_lock import PhoneBatchLease
from reauth_formats import Accounts, parse_accounts_from_text, parse_json_documents
from reauth_proxy import normalize_proxy

CONTINUE_BUTTON_NAMES = re.compile(
    r"^(Continue|Verify|Submit|Next|Send code|Confirm|继续|驗證|验证|提交|下一步|发送验证码|發送驗證碼|确认|確認)$",
    re.I,
)


def needs_phone_page(url: str, text: str = "") -> bool:
    value = f"{url} {text}".lower()
    return "/add-phone" in value or "phone-verification" in value or "verify your phone" in value or "add a phone" in value


def accounts_from_any_text(text: str) -> Accounts:
    kind, accounts = parse_accounts_from_text(text)
    if not accounts:
        raise ValueError("没有识别到账号")
    return accounts


# Phone verification always uses browser login, independent of refresh-first authorization.
from account_inputs import account_input_from_mapping as _account_input, load_accounts as _load_accounts


def account_input_from_mapping(account, source_line=0):
    return _account_input(account, source_line, include_oauth=False)


def parse_phone_jobs(text):
    return _load_accounts(text, include_oauth=False)


def _fill_phone_number(page: Any, phone: str) -> bool:
    return fill_phone_number(page, phone)


def _submit_continue(page: Any) -> None:
    if not click_named_button(page, CONTINUE_BUTTON_NAMES):
        page.keyboard.press("Enter")


def _response_summary(response: Any) -> tuple[int | None, str]:
    """Parse the full response before retaining only phone-flow result fields."""
    status = getattr(response, "status", None)
    try:
        status = int(status) if status is not None else None
    except (TypeError, ValueError):
        status = None
    data = None
    try:
        data = response.json()
    except Exception:
        pass
    if not isinstance(data, dict):
        body = "invalid response"
        try:
            body = response.text()
            if not isinstance(body, str):
                return status, "invalid response"
            data = json.loads(body)
        except Exception:
            # A non-JSON error still supplies useful classification markers;
            # it never qualifies as a successful validation response.
            return status, body[:600]
    if not isinstance(data, dict):
        return status, "invalid response"
    summary = {key: data[key] for key in ("success", "ok", "verified", "continue_url") if key in data}
    error = data.get("error")
    if isinstance(error, dict):
        # Preserve the structure so exact provider codes outrank generic prose.
        # Only these fields are needed for classification; none are logged raw.
        summary["error"] = {
            key: str(error[key])[:600 if key == "message" else 96]
            for key in ("code", "type", "message") if error.get(key) is not None
        } or ({"present": True} if error else {})
    elif "error" in data:
        summary["error"] = str(error)[:600] if error else error
    for key in ("code", "type", "message"):
        if key in data:
            value = data[key]
            summary[key] = str(value)[:600 if key == "message" else 96] if value else value
    return status, json.dumps(summary, ensure_ascii=False)


def _submit_and_capture(page: Any, path_fragment: str, timeout_ms: int = 8_000, before_submit=None, expected_phone: str | None = None, should_stop=None, deadline=None) -> tuple[int | None, str]:
    guard = PhoneSendGuard(page, expected_phone, log) if expected_phone is not None else nullcontext()
    with guard:
        status, body = _capture_submission(page, path_fragment, timeout_ms, before_submit, should_stop, deadline)
        if status is not None:
            stage = "发送短信" if path_fragment.endswith("/add-phone/send") else "提交验证码"
            log(f"接码{stage}结果：HTTP {status} · code={phone_response_code(body)}")
        else:
            log("接码：未捕获接口响应，正在核对页面状态")
        return status, body


def _capture_submission(page: Any, path_fragment: str, timeout_ms: int = 8_000, before_submit=None, should_stop=None, deadline=None) -> tuple[int | None, str]:
    """Click once and capture the relevant API response when the page exposes it.

    The browser flow remains usable with older/newer frontends that do not expose
    the endpoint (or with the small fake pages used by tests): in that case the
    returned status is ``None`` and the caller verifies the resulting page state.
    """
    _check_phone_stop(should_stop, deadline)
    expect_response = getattr(page, "expect_response", None)
    if callable(expect_response):
        submitted = False

        def request_matches(request):
            parsed = urlparse(str(getattr(request, "url", "")))
            return parsed.hostname == "auth.openai.com" and parsed.path == path_fragment and request.method == "POST"

        def observed_request(request):
            nonlocal submitted
            if request_matches(request):
                submitted = True

        listening = False
        try:
            def matches(response):
                return request_matches(response.request)
            page.on("request", observed_request)
            listening = True
            with expect_response(matches, timeout=timeout_ms) as waiter:
                if before_submit is not None:
                    before_submit()
                    # Filling the final digit can submit automatically, often
                    # after a short frontend debounce. Pump Playwright events
                    # before deciding whether an explicit click is needed.
                    auto_deadline = time.monotonic() + min(0.5, max(0, timeout_ms / 1000 - 0.1))
                    while not submitted and time.monotonic() < auto_deadline:
                        page.wait_for_timeout(min(25, max(1, (auto_deadline - time.monotonic()) * 1000)))
                if not submitted:
                    _check_phone_stop(should_stop, deadline)
                    _submit_continue(page)
            response = waiter.value
            log(response_diagnostic(response))
            return _response_summary(response)
        except AuthFlowError:
            raise
        except Exception:
            # A timeout means the click itself may still have completed. Do not
            # click a second time: duplicate send requests can consume a paid SMS.
            return None, ""
        finally:
            if listening:
                try:
                    page.remove_listener("request", observed_request)
                except Exception:
                    pass
    if before_submit is not None:
        before_submit()
    _check_phone_stop(should_stop, deadline)
    _submit_continue(page)
    return None, ""


PHONE_ERROR_CODES = {
    "fraud_guard": ("phone_fraud", "触发风控，已熔断本批次，需要人工检查"),
    "unsupported_phone_number": ("phone_rejected", "不支持该手机号"),
    "invalid_phone_number": ("phone_rejected", "手机号无效"),
    "phone_number_already_in_use": ("phone_rejected", "手机号已被占用"),
    "phone_already_in_use": ("phone_rejected", "手机号已被占用"),
    "phone_recently_used": ("phone_rejected", "手机号近期已被使用"),
    "rate_limit_exceeded": ("rate_limited", "请求频率受限"),
    "too_many_requests": ("rate_limited", "请求频率受限"),
    "rate_limit_error": ("rate_limited", "请求频率受限"),
    "invalid_code": ("failed", "短信验证码无效"),
    "incorrect_code": ("failed", "短信验证码不正确"),
    "invalid_otp": ("failed", "短信验证码无效"),
    "otp_expired": ("failed", "短信验证码已过期"),
    "code_expired": ("failed", "短信验证码已过期"),
    "phone_verification_failed": ("failed", "手机号验证未通过"),
}


def phone_response_code(body: str) -> str:
    """Return a known error code only; never reflect arbitrary response data."""
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return "unknown"
    if not isinstance(data, dict):
        return "unknown"
    error = data.get("error")
    candidates = []
    if isinstance(error, dict):
        candidates.extend((error.get("code"), error.get("type")))
    elif isinstance(error, str):
        candidates.append(error)
    candidates.extend((data.get("code"), data.get("type")))
    for value in candidates:
        if not isinstance(value, str):
            continue
        code = value.strip().lower()
        if re.fullmatch(r"[a-z0-9_-]{1,64}", code) and code in PHONE_ERROR_CODES:
            return code
    return "unknown"


def _phone_error_category(status: int | None, body: str) -> str:
    code = phone_response_code(body)
    if code in PHONE_ERROR_CODES:
        return PHONE_ERROR_CODES[code][0]
    if status == 429:
        return "rate_limited"
    text = body.lower()
    if "fraud" in text:
        return "phone_fraud"
    if any(marker in text for marker in ("already in use", "already_used", "already_in_use", "invalid phone", "invalid_phone", "unsupported", "recently used", "recently_used")):
        return "phone_rejected"
    if any(marker in text for marker in ("rate limit", "rate_limit", "too many requests", "too many attempts", "too_many_requests")):
        return "rate_limited"
    return "failed"


def phone_error_diagnostic(stage: str, status: int | None, body: str) -> str:
    """Describe an API rejection using fixed text and an allowlisted code."""
    code = phone_response_code(body)
    descriptions = {
        "rate_limited": "请求频率受限",
        "phone_fraud": "触发风控，已熔断本批次，需要人工检查",
        "needs_interaction": "需要人工检查，已停止自动换号",
        "phone_rejected": "OpenAI 拒绝该手机号",
        "failed": "服务端未接受请求，具体原因未确认",
    }
    detail = PHONE_ERROR_CODES[code][1] if code in PHONE_ERROR_CODES else descriptions[_phone_error_category(status, body)]
    label = {"send": "发送短信失败", "validate": "验证短信码失败"}.get(stage, "手机验证失败")
    http_status = str(status) if isinstance(status, int) and 100 <= status <= 599 else "未捕获"
    hint = "；失败发生在发送阶段，尚未进入短信轮询" if stage == "send" and _phone_error_category(status, body) == "phone_fraud" else ""
    return f"{label}（HTTP {http_status}，code={code}）：{detail}{hint}"


def _response_succeeded(status: int | None, body: str) -> bool:
    if status is None or not 200 <= status < 300:
        return False
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return not body.strip() and status == 204
    if not isinstance(data, dict):
        return False
    return (not data.get("error") and data.get("success") is not False
            and data.get("ok") is not False and data.get("verified") is not False)


def _validation_confirmed(body: str) -> bool:
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return False
    if not isinstance(data, dict):
        return False
    if data.get("verified") is True or data.get("success") is True:
        return True
    continuation = data.get("continue_url")
    if not isinstance(continuation, str) or not continuation.strip():
        return False
    parsed = urlparse(continuation)
    return (parsed.hostname in {None, "auth.openai.com", "localhost", "127.0.0.1"}
            and bool(parsed.path)
            and not any(part in parsed.path for part in ("phone", "error", "login", "log-in")))


def _check_phone_stop(should_stop, deadline: float | None) -> None:
    if should_stop and should_stop():
        raise AuthFlowError("cancelled", "已取消当前账号")
    if deadline is not None and time.monotonic() >= deadline:
        raise AuthFlowError("timeout", "当前账号已超过接码时间限制")


def _fill_otp_code(page: Any, code: str, human: HumanSettings | None = None, should_stop=None, deadline=None) -> bool:
    if not re.fullmatch(r"\d{4,8}", str(code or "").strip()):
        return False
    boxes = page.locator('input[maxlength="1"]')
    try:
        visible_boxes = [boxes.nth(index) for index in range(boxes.count()) if boxes.nth(index).is_visible()]
        if len(visible_boxes) == len(code):
            for index, digit in enumerate(code):
                # Each box is a separate field: pause between digits the way a
                # person moves across the code inputs.
                human_delay(human, "click", should_stop=should_stop, deadline=deadline, log_fn=None)
                if not type_like_human(visible_boxes[index], digit, human, should_stop=should_stop, deadline=deadline):
                    visible_boxes[index].fill(digit)
            return True
    except AuthFlowError:
        raise
    except Exception:
        pass
    otp = first_visible(
        page,
        ['input[autocomplete="one-time-code"]', 'input[name="code"]', 'input[name="otp"]', 'input[inputmode="numeric"]'],
        timeout_ms=800,
    )
    if otp is None:
        return False
    try:
        if not type_like_human(otp, code, human, should_stop=should_stop, deadline=deadline):
            otp.fill(code)
        return True
    except AuthFlowError:
        raise
    except Exception:
        return False


def _phone_page_finished(page: Any) -> bool:
    try:
        url = str(page.url or "").lower()
    except Exception:
        url = ""
    text = page_text(page)
    if re.search(r"phone (?:number )?(?:added|verified)|verification complete|successfully added", text, re.I):
        return True
    parsed = urlparse(url)
    if parsed.hostname == "auth.openai.com" and parsed.path in {"/consent", "/sign-in-with-chatgpt/codex/consent"}:
        return True
    # Remaining on the verification route with a hidden/removed input is not
    # enough evidence: React can remove the form while a failed request is still
    # being rendered. The API response (when available) is the authoritative
    # signal; otherwise require a route change or explicit success text.
    return False


def _complete_phone_attempt(
    page: Any,
    pool: PhonePool,
    should_stop: Callable[[], bool] | None = None,
    deadline: float | None = None,
    human: HumanSettings | None = None,
) -> dict:
    _check_phone_stop(should_stop, deadline)
    phone_input = first_visible(page, PHONE_INPUTS, 400)
    if phone_input is None:
        raise AuthFlowError("needs_interaction", "当前页面没有手机号输入框，请返回添加手机号页面后重试")
    ensure_sms_channel(page)
    human_delay(human, "phone_form", should_stop=should_stop, deadline=deadline, log_fn=log)
    phone = pool.prepare_for_send(should_stop=should_stop, deadline=deadline)
    _check_phone_stop(should_stop, deadline)
    display = normalize_phone(phone)
    log(f"接码：准备向号码 {masked_phone(display)} 发送短信")
    # Retain the route throughout polling and OTP validation: a frontend timer
    # must not send another paid SMS after the first response has arrived.
    info = None
    try:
        with PhoneSendGuard(page, display, log) as guard:
            info = _send_and_validate_phone(page, pool, display, guard, should_stop, deadline, human)
        return info
    except AuthFlowError as exc:
        if info and info.get("status") == "verified":
            exc.phone_info = info
        raise


def _send_and_validate_phone(
    page: Any, pool: PhonePool, display: str, guard, should_stop=None, deadline=None,
    human: HumanSettings | None = None,
) -> dict:

    def fill_phone():
        human_delay(human, "phone_send", should_stop=should_stop, deadline=deadline, log_fn=log)
        if not _fill_phone_number(page, display):
            raise AuthFlowError("needs_interaction", "未找到手机号输入框")
        channel = ensure_sms_channel(page)
        log(f"接码表单通道：{'短信已选中' if channel == 'sms' else '页面未提供通道选项'}")

    send_timeout = 8_000 if deadline is None else max(1, min(8_000, int((deadline - time.monotonic()) * 1000)))
    send_status, send_body = _submit_and_capture(page, "/api/accounts/add-phone/send", timeout_ms=send_timeout, before_submit=fill_phone, should_stop=should_stop, deadline=deadline)
    guard.check_sent()
    if send_status is not None and not _response_succeeded(send_status, send_body):
        pool.cancel_current()
        category = _phone_error_category(send_status, send_body)
        raise AuthFlowError(category, phone_error_diagnostic("send", send_status, send_body))

    send_deadline = min(time.monotonic() + 20, deadline) if deadline is not None else time.monotonic() + 20
    otp_visible = False
    while time.monotonic() < send_deadline:
        if should_stop and should_stop():
            pool.cancel_current()
            raise AuthFlowError("cancelled", "已取消当前账号")
        if form_is_busy(page):
            time.sleep(0.2)
            continue
        text = visible_error_text(page)
        category = _phone_error_category(None, text)
        if text and category != "failed":
            pool.cancel_current()
            raise AuthFlowError(category, phone_error_diagnostic("send", None, text))
        otp_visible = first_visible(page, ['input[autocomplete="one-time-code"]', 'input[maxlength="1"]', 'input[name="code"]'], 400) is not None
        if otp_visible:
            break
        time.sleep(0.2)
    if not otp_visible:
        pool.cancel_current()
        raise AuthFlowError("failed", "手机号发送后未出现验证码页面")

    log("接码：等待 SMSBower 短信")
    human_delay(human, "phone_wait_code", should_stop=should_stop, deadline=deadline, log_fn=log)
    try:
        _check_phone_stop(should_stop, deadline)
        remaining = None if deadline is None else max(1, int(deadline - time.monotonic()))
        code = pool.wait_code(should_stop=should_stop, timeout=remaining)
    except Exception as exc:
        if should_stop and should_stop():
            raise AuthFlowError("cancelled", "已取消当前账号") from exc
        category = getattr(exc, "category", "")
        if category:
            raise AuthFlowError(category, str(exc)) from exc
        raise AuthFlowError("sms_timeout" if str(exc) == "phone_sms_timeout" else "failed", "短信等待超时或失败") from exc
    _check_phone_stop(should_stop, deadline)
    def fill_code():
        human_delay(human, "phone_type_code", should_stop=should_stop, deadline=deadline, log_fn=log)
        if not _fill_otp_code(page, code, human=human, should_stop=should_stop, deadline=deadline):
            raise AuthFlowError("failed", "验证码格式或输入框无效")
    validate_timeout = 12_000 if deadline is None else max(1, min(12_000, int((deadline - time.monotonic()) * 1000)))
    validate_status, validate_body = _submit_and_capture(page, "/api/accounts/phone-otp/validate", timeout_ms=validate_timeout, before_submit=fill_code, should_stop=should_stop, deadline=deadline)
    if validate_status is not None and not _response_succeeded(validate_status, validate_body):
        pool.cancel_current()
        category = _phone_error_category(validate_status, validate_body)
        raise AuthFlowError(category, phone_error_diagnostic("validate", validate_status, validate_body))
    # A successful response is authoritative. Without a response (for example,
    # a frontend route change), require the OTP form to disappear or the URL to
    # leave the verification route before consuming the number.
    if not _validation_confirmed(validate_body):
        settle_deadline = min(time.monotonic() + 5, deadline) if deadline is not None else time.monotonic() + 5
        while time.monotonic() < settle_deadline and not _phone_page_finished(page):
            if should_stop and should_stop():
                pool.cancel_current()
                raise AuthFlowError("cancelled", "已取消当前账号")
            time.sleep(0.2)
        if not _phone_page_finished(page):
            pool.cancel_current()
            raise AuthFlowError("failed", "验证码提交结果未确认")

    guard.keep_until_page_close()
    info = pool.mark_used()
    info["status"] = "verified"
    log(f"接码成功：号码 {masked_phone(info['phone'])}（{info['reuse_count']}/{info['max_reuse']}）")
    return info


def complete_phone_on_page(
    page: Any,
    pool: PhonePool,
    should_stop: Callable[[], bool] | None = None,
    deadline: float | None = None,
    human: HumanSettings | None = None,
) -> dict:
    """Bind a phone and consume reuse only after OpenAI accepts the OTP.

    Each configured country shares one small retry budget for availability,
    rejection and SMS timeout. Only these failures can advance to a fallback
    country; fraud, rate limits and ambiguous purchases stop immediately.
    """
    attempts, countries = phone_retry_plan(pool.settings)
    # Reuse a still-active fallback number before buying in another country.
    # Reordering keeps the same country set and the same paid retry budget.
    reusable = pool.reusable_country()
    if reusable in countries:
        countries = [reusable, *(country for country in countries if country != reusable)]
    total_attempts = attempts * len(countries)
    last_error: AuthFlowError | None = None
    initial_url = str(page.url)

    def deadline_error(total_attempt: int) -> AuthFlowError:
        return AuthFlowError(
            "circuit_open",
            f"接码总时限已用尽（第 {total_attempt}/{total_attempts} 次尝试，小重试 {attempts - 1} 次、大重试 {len(countries) - 1} 次），本批次已熔断",
        )

    def check_retry_state(total_attempt: int) -> None:
        try:
            _check_phone_stop(should_stop, deadline)
        except AuthFlowError as exc:
            if exc.category == "timeout":
                raise deadline_error(total_attempt) from exc
            raise

    for country_index, country in enumerate(countries):
        for attempt in range(1, attempts + 1):
            total_attempt = country_index * attempts + attempt
            try:
                check_retry_state(total_attempt)
                pool.switch_country(country, should_stop=should_stop, deadline=deadline)
                log(f"接码：国家轮次 {country_index + 1}/{len(countries)} · {country_label(country)} · 当前国家尝试 {attempt}/{attempts}（总计 {total_attempt}/{total_attempts}）")
                return _complete_phone_attempt(page, pool, should_stop, deadline=deadline, human=human)
            except Exception as error:
                if getattr(error, "phone_info", {}).get("status") == "verified":
                    # Already bound: cleanup failure must never buy another
                    # number for this account or lose its successful result.
                    raise
                if isinstance(error, AuthFlowError):
                    exc = error
                elif getattr(error, "category", ""):
                    exc = AuthFlowError(error.category, str(error))
                else:
                    exc = AuthFlowError("failed", "接码页面操作失败，请检查浏览器后重试")
                pool.cancel_current()
                last_error = exc
                if exc.category == "timeout":
                    check_retry_state(total_attempt)
                    raise deadline_error(total_attempt) from error
                if exc.category not in {"sms_unavailable", "phone_rejected", "sms_timeout"}:
                    raise exc from error
                check_retry_state(total_attempt)
                if total_attempt >= total_attempts:
                    raise AuthFlowError(
                        "circuit_open",
                        f"接码重试已用尽（每国首次尝试 + {attempts - 1} 次重试，大重试 {len(countries) - 1} 次，共 {total_attempts} 次尝试），本批次已熔断；最后原因：{exc}",
                    ) from error
                try:
                    pool.ensure_released()
                except PhonePoolError as cleanup_error:
                    raise AuthFlowError(cleanup_error.category, str(cleanup_error)) from cleanup_error
                if attempt == attempts:
                    log(f"接码：{country_label(country)} 小重试已用尽；大重试 {country_index + 1}/{len(countries) - 1}，切换至 {country_label(countries[country_index + 1])}（{exc}）")
                else:
                    log(f"接码：{country_label(country)} 尝试 {attempt}/{attempts} 失败，准备小重试 {attempt}/{attempts - 1}（{exc}）")
                if exc.category == "sms_unavailable":
                    continue
                # The frontend can replace phone fields without changing URL.
                # Reload the observed entry route before the next number.
                retry_timeout = 15_000 if deadline is None else max(1, min(15_000, int((deadline - time.monotonic()) * 1000)))
                try:
                    page.goto(initial_url, wait_until="domcontentloaded", timeout=retry_timeout)
                except Exception as retry_error:
                    check_retry_state(total_attempt)
                    raise AuthFlowError("sms_network", "接码重试页面加载失败，已停止本批次；请检查网络后重新开始") from retry_error
    raise last_error or AuthFlowError("failed", "手机号验证失败")


def make_phone_handler(pool: PhonePool, human: HumanSettings | None = None) -> Callable:
    def handler(
        page: Any,
        account: AccountInput,
        should_stop: Callable[[], bool] | None = None,
        *,
        deadline: float | None = None,
    ) -> dict:
        try:
            return complete_phone_on_page(page, pool, should_stop=should_stop, deadline=deadline, human=human)
        except (PhonePoolError, SmsBowerError) as exc:
            # Only these application-owned errors contain safe messages;
            # arbitrary HTTP/Playwright errors may expose URLs or fill values.
            raise AuthFlowError(exc.category, str(exc)) from exc

    return handler


def _phone_result_record(result: Any) -> dict[str, Any]:
    info = getattr(result, "phone_info", None) or {}
    return {
        "email": result.email,
        "phone_status": getattr(result, "phone_status", "unconfirmed"),
        "phone_info": {key: info[key] for key in ("phone", "reuse_count", "max_reuse", "remaining", "price") if key in info},
        "oauth_ok": bool(result.ok),
        "category": result.category,
        "error": result.error,
        "phone_error": getattr(result, "phone_error", None),
    }


def _write_phone_report(path: Path, report: dict[str, Any]) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def run_batch_phone_verify(
    accounts: list[AccountInput],
    settings: SmsbowerSettings,
    timeout: float = 180,
    proxy: str | None = None,
    headless: bool = True,
    should_stop: Callable[[], bool] | None = None,
    on_progress=None,
    recovery_dir=None,
    human_options: dict[str, Any] | None = None,
):
    if not settings.api_key.strip():
        raise ValueError("请填写 SMSBower API Key")
    human = human_settings_from_options(human_options)
    # Reject invalid paid retry plans before creating reports, browsers or
    # clients. Keep the configured primary country unchanged across accounts.
    attempts, countries = phone_retry_plan(settings)
    # One explicit setting controls browser, mailbox, token exchange and SMS.
    # None inherits settings; an explicit empty proxy means direct connection.
    effective_proxy = normalize_proxy(settings.proxy if proxy is None else proxy) or ""
    source = "override" if proxy is not None else settings.network_source
    source = source if source in {"system", "direct", "custom", "explicit", "override"} else "explicit"
    settings = replace(settings, proxy=effective_proxy, network_source=source)
    # Orders are recoverable across interrupted runs, including batches that
    # opt out of token checkpointing. The journal contains ids, never API keys.
    journal_dir = Path(recovery_dir) if recovery_dir is not None else Path(__file__).resolve().parent / "recovery"
    journal_dir.mkdir(parents=True, exist_ok=True)
    report_path = journal_dir / (datetime.now().strftime("phone-results-%Y%m%d-%H%M%S-") + uuid4().hex[:8] + ".json")
    report: dict[str, Any] = {
        "type": "openai-phone-results",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "finished_at": None,
        "total": len(accounts),
        "auto_retry_count": attempts - 1,
        "country_retry_count": len(countries) - 1,
        "primary_country": countries[0],
        "fallback_countries": countries[1:],
        "max_attempts_per_account": attempts * len(countries),
        "max_price": settings.max_price,
        "auto_price_match": settings.auto_price_match,
        "headless": bool(headless),
        "network": {"source": source, "mode": "proxy" if effective_proxy else "direct", "proxy_scheme": urlparse(effective_proxy).scheme if effective_proxy else None},
        "browser_user_agent": "native",
        "human_pacing": {"enabled": human.enabled, "scale": human.scale, "typing": human.typing},
        "attempted": 0,
        "unattempted": len(accounts),
        "results": [],
    }
    _write_phone_report(report_path, report)
    log(f"手机号绑定结果自动保存到：{report_path}")

    def checkpoint(index: int, total: int, result: Any) -> None:
        report["results"].append(_phone_result_record(result))
        report["attempted"] = len(report["results"])
        report["unattempted"] = max(0, len(accounts) - report["attempted"])
        try:
            _write_phone_report(report_path, report)
        except OSError as exc:
            raise AuthFlowError("checkpoint_error", "手机号绑定结果保存失败，已停止后续账号；请保存当前日志") from exc
        if on_progress is not None:
            on_progress(index, total, result)

    with PhoneBatchLease(journal_dir / "phone-orders.lock"):
        pool = PhonePool(settings, journal_path=journal_dir / "phone-orders.json")
        try:
            results = run_batch_reauth(
                accounts,
                timeout=timeout,
                proxy=effective_proxy or None,
                headless=headless,
                should_stop=should_stop,
                on_progress=checkpoint,
                recovery_dir=recovery_dir,
                phone_handler=make_phone_handler(pool, human),
                human=human,
            )
            report["results"] = [_phone_result_record(result) for result in results]
            report["attempted"] = len(results)
            report["unattempted"] = max(0, len(accounts) - len(results))
            return results
        finally:
            try:
                pending = pool.close()
                report["pending_cleanup_count"] = len(pending)
                if pending:
                    log("短信订单未全部释放，请在 SMSBower 检查未完成订单；本次不会再买号")
            except Exception:
                report["cleanup_error"] = "短信订单收尾未完成，请检查 SMSBower 订单"
                log(report["cleanup_error"])
            report["finished_at"] = datetime.now(timezone.utc).isoformat()
            try:
                _write_phone_report(report_path, report)
            except OSError:
                log("手机号绑定最终汇总保存失败，请保存当前日志；此前已保存的逐条结果仍保留")
