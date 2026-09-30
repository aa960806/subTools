"""Validate phone sends before forwarding them; diagnostics contain no secrets."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from openai_reauth import AuthFlowError
from phone_smsbower import normalize_phone


PHONE_URL = re.compile(r"^https://auth\.openai\.com/api/accounts/(?:add-phone/send|phone-otp/validate)(?:\?.*)?$")
PHONE_KEYS = ("phone_number", "phoneNumber")
CHANNEL_KEYS = ("channel", "delivery_channel", "delivery_method", "method")


def masked_phone(phone: str) -> str:
    value = normalize_phone(phone)
    return "***" + value[-4:] if len(value) > 4 else "***"


def check_send_payload(payload, expected_phone: str) -> tuple[bool, str, str]:
    """Return fixed diagnostic labels, never provider-controlled payload text."""
    if not isinstance(payload, dict):
        return False, "unknown", "发送请求不是可识别的手机号表单，已阻止发送"
    numbers = [payload[key] for key in PHONE_KEYS if key in payload]
    if not numbers or any(
        not isinstance(number, str)
        or not re.fullmatch(r"[+0-9() .-]+", number)
        or normalize_phone(number) != normalize_phone(expected_phone)
        for number in numbers
    ):
        return False, "unknown", "实际发送请求的手机号与购买号码不一致，已阻止发送"
    channels = [payload[key] for key in CHANNEL_KEYS if key in payload]
    if any(not isinstance(value, str) or value.lower().strip() not in {"sms", "text", "text_message"} for value in channels):
        return False, "other", "实际发送请求未使用短信通道，已阻止发送"
    return True, "sms" if channels else "unspecified", ""


class PhoneSendGuard:
    """One send and one validation per attempt; unrelated routes remain intact."""

    def __init__(self, page, expected_phone: str, logger):
        self.page = page
        self.expected_phone = expected_phone
        self.log = logger
        self.count = 0
        self.duplicates = 0
        self.validation_count = 0
        self.completed = False
        self.allowed = 0
        self.error = ""
        self.handler = self._route

    def __enter__(self):
        # An unrecognised browser API must not silently skip a paid-send check.
        try:
            self.page.route(PHONE_URL, self.handler)
        except Exception:
            raise AuthFlowError("needs_interaction", "无法安装手机号提交校验，已停止发送") from None
        return self

    def _route(self, route):
        request = route.request
        if request.method != "POST":
            route.fallback()
            return
        if urlparse(request.url).path == "/api/accounts/phone-otp/validate":
            self.validation_count += 1
            if self.validation_count > 1 or self.completed:
                self.log("接码：已阻止页面重复提交验证码，保留首次验证结果")
                route.abort()
            else:
                route.fallback()
            return
        self.count += 1
        if self.count > 1:
            self.duplicates += 1
            self.log("接码：已阻止页面重复发送短信，继续等待首次请求的验证码")
            route.abort()
            return
        try:
            payload = request.post_data_json
        except Exception:
            payload = None
        valid, channel, self.error = check_send_payload(payload, self.expected_phone)
        self.log(f"接码提交校验：号码={masked_phone(self.expected_phone)} · 号码匹配={'是' if valid else '否或通道异常'} · 请求通道={channel}")
        if not valid:
            route.abort()
            return
        self.allowed += 1
        # Only presence is recorded. Cookies and header values never enter logs.
        flags = {}
        for label, names in (
            ("device", ("oai-device-id", "oai-did")),
            ("sentinel", ("openai-sentinel-token", "openai-sentinel-proof-token")),
        ):
            try:
                flags[label] = any(bool(request.header_value(name)) for name in names)
            except Exception:
                flags[label] = None
        self.log("接码请求头观察：" + " · ".join(f"{key}={'未读取' if value is None else '有' if value else '无'}" for key, value in flags.items())
                 + "（仅检查指定头；未检查 Cookie 或其他验证数据，不能据此判断风控原因）")
        # fallback preserves local fixture routes and any application's routing.
        route.fallback()

    def __exit__(self, exc_type, exc, traceback):
        if not self.completed:
            try:
                self.page.unroute(PHONE_URL, self.handler)
            except Exception:
                failure = AuthFlowError("needs_interaction", "手机号提交校验未能正常收尾，已停止；请关闭本次浏览器后重试")
                info = getattr(exc, "phone_info", None)
                if isinstance(info, dict) and info.get("status") == "verified":
                    failure.phone_info = info
                raise failure from exc
        if self.error:
            raise AuthFlowError("needs_interaction", self.error) from None
        if exc is None and not self.allowed:
            raise AuthFlowError("needs_interaction", "未捕获到可核对的发送短信请求，已停止；请检查手机号表单")
        return False

    def keep_until_page_close(self):
        # An OTP input can submit on a delayed timer, after the explicit click
        # already succeeded. This page belongs to one account and is closed by
        # reauth_account; retain the blocker through its OAuth continuation.
        self.completed = True

    def check_sent(self):
        if self.error:
            raise AuthFlowError("needs_interaction", self.error) from None
        if not self.allowed:
            raise AuthFlowError("needs_interaction", "未捕获到可核对的发送短信请求，已停止；请检查手机号表单")


def response_diagnostic(response) -> str:
    """Keep only the endpoint stage and a strictly shaped request identifier."""
    path = urlparse(str(getattr(response, "url", ""))).path
    stage = "发送" if path.endswith("/add-phone/send") else "验证码验证"
    request_id = "未提供"
    for key in ("x-request-id", "request-id"):
        try:
            candidate = response.header_value(key) or ""
        except Exception:
            continue
        if re.fullmatch(r"(?:req_[A-Za-z0-9]{8,64}|[a-fA-F0-9]{32}|[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12})", candidate):
            request_id = candidate
            break
    return f"接码{stage}响应：request_id={request_id}"
