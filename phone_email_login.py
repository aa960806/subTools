"""Mailbox-link login shared by authorization, pool-push and phone workflows."""
from __future__ import annotations

import re
import time
import json
from urllib.parse import urlparse

from openai_reauth import AuthFlowError, first_visible, log, visible_error_text
from phone_mailbox import MailboxClient, MailboxError


EMAIL_METHOD = re.compile(
    r"^(?:Use (?:a |an )?(?:one[- ]time |email )?(?:code|passcode)(?: instead)?|"
    r"(?:Email|Send)(?: me)? (?:a |an )?(?:one[- ]time )?(?:code|passcode)|"
    r"(?:Log|Sign) in with (?:a |an )?(?:one[- ]time |email )?(?:code|passcode)|"
    r"Continue with (?:a |an )?(?:one[- ]time |email )?(?:code|passcode))$", re.I,
)


class EmailLogin:
    def __init__(self, account, proxy=None):
        self.account = account
        self.client = MailboxClient(account.mailbox_url, account.email, proxy=proxy)
        self.baseline = None
        self.issued_after = 0.0
        self.submitted_at = None
        self.method_clicked = False

    def prime(self, deadline, should_stop):
        if should_stop and should_stop():
            raise AuthFlowError("cancelled", "已停止邮箱登录")
        try:
            self.baseline = self.client.snapshot(deadline=min(deadline, time.monotonic() + 30), should_stop=should_stop)
        except MailboxError as exc:
            raise AuthFlowError(exc.category, str(exc)) from None
        self.issued_after = time.time()

    def close(self):
        self.client.close()

    def handle_page(self, page, text, deadline, should_stop):
        path = urlparse(page.url).path.lower()
        on_email_page = ("email-verification" in path or "email-otp" in path
                         or re.search(r"check your (?:email|inbox)|code (?:we (?:just )?)?sent to", text, re.I))
        if on_email_page:
            if self.submitted_at is not None:
                if visible_error_text(page):
                    raise AuthFlowError("mailbox_code_rejected", "邮箱验证码未通过，未重复提交旧验证码")
                if time.monotonic() - self.submitted_at > 15:
                    raise AuthFlowError("needs_interaction", "邮箱验证码提交后页面未继续，请显示浏览器检查")
                page.wait_for_timeout(150)
                return True
            field = first_visible(page, ['input[autocomplete="one-time-code"]', 'input[name="code"]', 'input[name="otp"]', 'input[maxlength="1"]'], 300)
            if field is None:
                page.wait_for_timeout(150)
                return True
            log(f"{self.account.email}: 等待本次登录的邮箱验证码")
            try:
                code = self.client.wait_for_code(self.baseline, issued_after=self.issued_after,
                                                deadline=min(deadline, time.monotonic() + 90), should_stop=should_stop)
            except MailboxError as exc:
                raise AuthFlowError(exc.category, str(exc)) from None
            if should_stop and should_stop():
                raise AuthFlowError("cancelled", "已停止邮箱登录")
            if not code:
                raise AuthFlowError("mailbox_timeout", "未收到本次登录的邮箱验证码，未使用历史邮件")
            # Use the same response listener that avoids double-submit when
            # the frontend automatically submits the final digit.
            from phone_flow import _fill_otp_code, _submit_and_capture, _response_succeeded

            def fill():
                if not _fill_otp_code(page, code):
                    raise AuthFlowError("needs_interaction", "无法填写邮箱验证码")

            timeout = max(1, min(12_000, int((deadline - time.monotonic()) * 1000)))
            status, body = _submit_and_capture(page, "/api/accounts/email-otp/validate", timeout_ms=timeout, before_submit=fill)
            self.submitted_at = time.monotonic()
            try:
                parsed = json.loads(body)
            except (ValueError, TypeError):
                parsed = None
            # Navigation may discard the old document before response.text()
            # is readable. Let the main loop validate its callback/next page;
            # unreadable content is not evidence of an explicit rejection.
            rejected = status is not None and (not 200 <= status < 300 or
                        (isinstance(parsed, dict) and not _response_succeeded(status, body)))
            if rejected:
                category = "rate_limited" if status == 429 else "mailbox_code_rejected"
                raise AuthFlowError(category, f"邮箱验证码验证失败（HTTP {status}）")
            log(f"{self.account.email}: 已提交本次邮箱验证码")
            return True
        if not self.account.password and first_visible(page, ['input[type="password"]'], 200):
            if self.method_clicked:
                page.wait_for_timeout(150)
                return True
            for role in ("button", "link"):
                options = page.get_by_role(role, name=EMAIL_METHOD)
                for index in range(options.count()):
                    option = options.nth(index)
                    if option.is_visible() and option.is_enabled():
                        option.click()
                        self.method_clicked = True
                        log(f"{self.account.email}: 已选择邮箱验证码登录")
                        return True
            raise AuthFlowError("needs_interaction", "该账号要求密码且页面未提供邮箱验证码登录，请补充密码或显示浏览器")
        return False
