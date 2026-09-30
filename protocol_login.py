"""Optional HTTP login adapter adapted from toSub2 v1.7.1 (MIT).

Copyright (c) 2026 poxiao33. See THIRD_PARTY_NOTICES.md for the license.
Ports loginChatgptWeb, completeTotpMfaIfNeeded, runCodexOauth,
pickWorkspaceId and extractFirstSessionId from src/protocol-login.mjs at
8548397e89bf80e508eda64a87e0d556d43abc84. Uses our token validation, proxy,
deadline, error and recovery contracts. Security challenges require browser
interaction; no challenge solver, profile creation or SMS purchase is included.
"""
from __future__ import annotations

import html
import re
import secrets
import time
import uuid
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit

import httpx
import pyotp

from flow_control import AuthFlowError, check_running
from human_pacing import human_delay
from openai_reauth import (ReauthResult, generate_oauth_session, exchange_code,
                           build_account_payload, write_export_file, normalize_proxy,
                           log)
from phone_mailbox import MailboxClient, MailboxError
from progress_events import emit
from protocol_transport import CurlTransport

CHATGPT = 'https://chatgpt.com'
AUTH = 'https://auth.openai.com'
ALLOWED_ORIGINS = {CHATGPT, AUTH}


def continue_url(payload):
    return mapping(payload).get('continue_url') or mapping(mapping(mapping(payload).get('page')).get('payload')).get('url') or ''


def mapping(value):
    return value if isinstance(value, dict) else {}


def workspace_id(payload):
    spaces = mapping(mapping(payload).get('oai-client-auth-session')).get('workspaces') or []
    if not isinstance(spaces, list):
        return None
    available = [s for s in spaces if isinstance(s, dict) and isinstance(s.get('id'), str) and s['id']]
    chosen = next((s for s in available if s.get('kind') == 'organization'), available[0] if available else {})
    return chosen.get('id')


def first_session_id(text):
    text = html.unescape(text)
    patterns = (r'"session_id"\s*:\s*"(us_[^"\s]+)"',
                r'session_id\\",\\"(us_[^"\\\s]+)',
                r'name="session_id"[^>]+value="(us_[^"\s]+)"',
                r'value="(us_[^"\s]+)"[^>]+name="session_id"',
                r'\b(us_[A-Za-z0-9_-]{10,})\b')
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(1)
    return None


def trusted_url(value, base=AUTH):
    if not isinstance(value, str) or not value or len(value) > 16384 or '\\' in value or any(c.isspace() for c in value):
        raise AuthFlowError('oauth_error', '登录响应包含无效跳转地址，已停止')
    value = urljoin(base + '/', value)
    try:
        parsed = urlsplit(value)
        valid = (f'{parsed.scheme}://{parsed.netloc}' in ALLOWED_ORIGINS
                 and not parsed.username and not parsed.password and not parsed.fragment)
    except ValueError:
        valid = False
    if not valid:
        raise AuthFlowError('needs_interaction', '登录需要外部身份提供方或未知跳转，请改用浏览器登录')
    return value


def callback_code(value, session):
    """Return None for a normal redirect; validate every OAuth callback field."""
    try:
        parsed, expected = urlsplit(value), urlsplit(session.redirect_uri)
        if parsed.hostname not in (expected.hostname, 'localhost', '127.0.0.1'):
            return None
        if parsed.scheme not in ('http', 'https') or parsed.username or parsed.password or parsed.fragment:
            raise ValueError
        if (parsed.scheme, parsed.hostname, parsed.port, parsed.path) != (expected.scheme, expected.hostname, expected.port, expected.path):
            if parsed.hostname in ('localhost', '127.0.0.1'):
                raise ValueError
            return None
        query = parse_qs(parsed.query, keep_blank_values=True)
        if any(len(query.get(k, [])) != 1 for k in ('code', 'state')) or 'error' in query:
            raise ValueError
        state = query['state'][0]
        if not state.isascii() or not secrets.compare_digest(state, session.state) or not query['code'][0]:
            raise ValueError
        return query['code'][0]
    except (ValueError, TypeError):
        raise AuthFlowError('oauth_error', 'OAuth 回调地址、state 或授权码校验失败，未换取凭据') from None


class ProtocolClient:
    def __init__(self, *, proxy=None, deadline, should_stop=None, transport=None):
        self.deadline, self.should_stop = deadline, should_stop
        self.proxy = normalize_proxy(proxy)
        self.requests = 0
        # This transport owns the explicit proxy; httpx must not create a second
        # proxy transport that would bypass either curl or the test fixture.
        transport = transport or CurlTransport(proxy=self.proxy, deadline=deadline, should_stop=should_stop)
        self.http = httpx.Client(transport=transport,
                                 trust_env=False, follow_redirects=False,
                                 headers={'Accept-Language':'en-US,en;q=0.9'})

    def close(self):
        self.http.close()

    def cookie(self, name, host):
        return next((c.value for c in self.http.cookies.jar if c.name == name
                     and (host == c.domain.lstrip('.') or host.endswith('.' + c.domain.lstrip('.')))), '')

    def request(self, method, url, *, referer=None, **options):
        check_running(self.should_stop, self.deadline)
        self.requests += 1
        if self.requests > 80:
            raise AuthFlowError('needs_interaction', '协议登录步骤超过限制，请改用浏览器检查')
        url = trusted_url(url)
        headers = {'Accept':'application/json, text/plain, */*'}
        if referer:
            headers['Referer'] = trusted_url(referer)
        if method == 'POST':
            parsed = urlsplit(url)
            headers['Origin'] = f'{parsed.scheme}://{parsed.netloc}'
            headers['x-access-flow-invocation-id'] = uuid.uuid4().hex
        try:
            with self.http.stream(method, url, headers=headers,
                                  timeout=max(.05, min(15, self.deadline-time.monotonic())), **options) as response:
                chunks, size = [], 0
                for chunk in response.iter_bytes():
                    check_running(self.should_stop, self.deadline)
                    size += len(chunk)
                    if size > 4 * 1024 * 1024:
                        raise AuthFlowError('needs_interaction', '登录响应过大，已停止协议处理')
                    chunks.append(chunk)
                response._content = b''.join(chunks)
        except httpx.HTTPError:
            check_running(self.should_stop, self.deadline)
            raise AuthFlowError('network', '协议请求未获确认，已停止；不会自动重发密码、验证码或登录请求') from None
        check_running(self.should_stop, self.deadline)
        status = response.status_code
        try:
            body = response.json()
        except ValueError:
            body = {}
        error = body.get('error') if isinstance(body, dict) else None
        code = str((error.get('code') or error.get('type') or '') if isinstance(error, dict)
                   else error or (body.get('code', '') if isinstance(body, dict) else '')).lower()
        if status == 429 or code in ('rate_limit_exceeded', 'too_many_requests'):
            raise AuthFlowError('rate_limited', '登录服务限流，已停止本批次，请稍后处理')
        if code == 'fraud_guard':
            raise AuthFlowError('phone_fraud', '登录服务拒绝安全校验，已停止本批次，需要人工检查')
        if code in ('account_deactivated', 'account_deleted', 'account_suspended'):
            raise AuthFlowError('failed', '账号已停用或删除')
        if code in ('invalid_password', 'incorrect_password', 'wrong_password'):
            raise AuthFlowError('failed', '登录密码被拒绝，未重复提交')
        if code in ('wrong_email_otp_code', 'invalid_otp', 'invalid_totp', 'invalid_code', 'incorrect_code'):
            raise AuthFlowError('failed', '验证码被拒绝，未重复提交旧验证码')
        content = response.text
        challenge = ('challenge' in response.headers.get('cf-mitigated', '').lower()
                     or bool(re.search(r'<title>\s*(?:Just a moment|Verify you are human)|cf-challenge', content, re.I)))
        if challenge or status == 403 or any(s in code for s in ('sentinel', 'security', 'challenge', 'captcha')) or code == 'invalid_auth_step':
            raise AuthFlowError('needs_interaction', f'协议登录遇到安全校验（HTTP {status}），请改用浏览器登录；未自动重试或切换网络')
        if status >= 400 or error:
            raise AuthFlowError('failed', f'协议登录请求被拒绝（HTTP {status}），请检查账号或改用浏览器')
        return response

    def json(self, method, url, **options):
        response = self.request(method, url, **options)
        try:
            value = response.json()
            if not isinstance(value, dict):
                raise ValueError
            return value
        except ValueError:
            raise AuthFlowError('needs_interaction', '登录接口未返回预期数据，请改用浏览器检查') from None

    def follow(self, url, *, session=None):
        for _ in range(12):
            if session and callback_code(url, session) is not None:
                return url, None
            response = self.request('GET', url)
            if response.status_code not in (301, 302, 303, 307, 308):
                return str(response.url), response
            location = response.headers.get('Location')
            if not location:
                raise AuthFlowError('needs_interaction', '登录跳转缺少地址，请改用浏览器')
            url = urljoin(str(response.url), location)
        raise AuthFlowError('needs_interaction', '登录跳转次数超过限制，请改用浏览器')


class ProtocolLogin:
    def __init__(self, account, client, *, prompt=None, human=None, mailbox_factory=MailboxClient):
        self.account, self.client, self.prompt, self.human = account, client, prompt, human
        self.mailbox_factory = mailbox_factory
        self.mailbox = None
        self.baseline = None
        self.issued_after = 0
        self.password_sent = self.email_sent = self.totp_sent = False
        self.selected_workspace = None
        self.workspaces_sent = set()

    def check(self):
        check_running(self.client.should_stop, self.client.deadline)

    def stage(self, stage):
        self.check()
        emit(self.account.email, stage)
        log(f'{self.account.email}: 协议登录 · ' + {'page':'打开授权流程','email':'提交邮箱',
            'password':'验证密码','otp':'验证登录验证码','workspace':'选择工作空间','token':'换取凭据',
            'interaction':'等待网页输入'}[stage])

    def ask(self, kind):
        self.stage('interaction')
        if self.prompt is None:
            raise AuthFlowError('needs_interaction', '协议登录缺少密码或验证码，请补充资料或改用浏览器')
        value = self.prompt(self.account.email, kind, deadline=self.client.deadline, should_stop=self.client.should_stop)
        self.check()
        return value

    def post(self, path, payload, referer=None):
        return self.client.json('POST', AUTH + path, json=payload, referer=referer)

    def password(self, referer):
        if self.password_sent:
            raise AuthFlowError('needs_interaction', '密码验证后仍停留原步骤，未重复提交；请改用浏览器')
        value = self.account.password or self.ask('password')
        self.stage('password')
        self.password_sent = True
        return self.post('/api/accounts/password/verify', {'password':value}, referer)

    def email_otp(self, referer):
        if self.email_sent:
            raise AuthFlowError('needs_interaction', '邮箱验证后仍停留原步骤，未重复发送或提交验证码')
        self.stage('otp')
        if self.mailbox:
            code = self.mailbox.wait_for_code(self.baseline, issued_after=self.issued_after,
                                             deadline=self.client.deadline, should_stop=self.client.should_stop)
            if not code:
                raise AuthFlowError('mailbox_timeout', '没有收到本次登录的邮箱验证码')
        else:
            code = self.ask('email_code')
        self.email_sent = True
        return self.post('/api/accounts/email-otp/validate', {'code':code}, referer)

    def totp(self, payload, referer):
        if self.totp_sent:
            raise AuthFlowError('needs_interaction', '二次验证后仍停留原步骤，未重复提交验证码')
        session = mapping(payload.get('oai-client-auth-session'))
        factors = [f for key in ('mfa_challenge_factors', 'mfa_factors')
                   for f in (session.get(key) if isinstance(session.get(key), list) else [])]
        factor = next((f for f in factors if isinstance(f, dict) and f.get('factor_type') == 'totp'
                       and isinstance(f.get('id'), str) and f['id']), None)
        if not factor:
            raise AuthFlowError('needs_interaction', '需要未支持的二次验证方式，请改用浏览器')
        self.stage('otp')
        self.post('/api/accounts/mfa/issue_challenge', {'type':'totp', 'id':factor['id'], 'force_fresh_challenge':False}, referer)
        code = pyotp.TOTP(self.account.totp_secret).now() if self.account.totp_secret else self.ask('totp')
        self.totp_sent = True
        return self.post('/api/accounts/mfa/verify', {'type':'totp', 'id':factor['id'], 'code':code}, referer)

    def advance(self, payload, *, oauth=None):
        for _ in range(16):
            self.check()
            target = continue_url(payload)
            if oauth and target and callback_code(target, oauth) is not None:
                return target
            if target:
                target = trusted_url(target)
            path = urlsplit(target).path if target else ''
            page_type = mapping(mapping(payload).get('page')).get('type')
            if page_type == 'add_phone' or path in ('/add-phone', '/phone-verification'):
                emit(self.account.email, 'phone')
                raise AuthFlowError('phone_required', '待补手机：协议登录已跳过手机验证，未调用接码服务')
            if page_type == 'about_you' or path == '/about-you':
                raise AuthFlowError('needs_interaction', '账号需要补充个人资料，请改用浏览器确认')
            if page_type == 'mfa_challenge' or path.startswith('/mfa-challenge/'):
                payload = self.totp(payload, target or AUTH + '/log-in/password')
                continue
            if path == '/log-in/password':
                payload = self.password(target)
                continue
            if path == '/email-verification':
                payload = self.email_otp(target)
                continue
            selected = workspace_id(payload)
            if selected:
                selection = (bool(oauth), selected)
                if selection in self.workspaces_sent:
                    raise AuthFlowError('needs_interaction', '工作空间选择未确认，未重复提交；请改用浏览器')
                self.workspaces_sent.add(selection)
                self.stage('workspace')
                payload = self.post('/api/accounts/workspace/select', {'workspace_id':selected}, target or AUTH + '/workspace')
                if oauth:
                    self.selected_workspace = selected
                continue
            if not target:
                raise AuthFlowError('needs_interaction', '协议登录收到未适配的步骤，请改用浏览器')
            final, response = self.client.follow(target, session=oauth)
            if oauth and callback_code(final, oauth) is not None:
                return final
            parsed = urlsplit(final)
            if not oauth and parsed.scheme + '://' + parsed.netloc == CHATGPT and parsed.path == '/' and self.client.cookie('__Secure-next-auth.session-token', 'chatgpt.com'):
                return final
            if parsed.path in ('/log-in/password', '/email-verification', '/add-phone', '/phone-verification', '/about-you'):
                payload = {'continue_url':final}
                continue
            if response and 'application/json' in response.headers.get('Content-Type', ''):
                try:
                    payload = response.json()
                    if isinstance(payload, dict):
                        continue
                except ValueError:
                    pass
            raise AuthFlowError('needs_interaction', '协议登录遇到未适配页面，请改用浏览器完成')
        raise AuthFlowError('needs_interaction', '协议登录步骤未收敛，已停止，请改用浏览器')

    def run(self):
        try:
            if self.account.mailbox_url:
                self.mailbox = self.mailbox_factory(self.account.mailbox_url, self.account.email, proxy=self.client.proxy)
                self.baseline = self.mailbox.snapshot(deadline=self.client.deadline, should_stop=self.client.should_stop)
            self.stage('page')
            human_delay(self.human, 'open_page', should_stop=self.client.should_stop, deadline=self.client.deadline, log_fn=log)
            self.client.follow(CHATGPT + '/')
            self.client.json('GET', CHATGPT + '/api/auth/providers')
            csrf = self.client.json('GET', CHATGPT + '/api/auth/csrf')
            if not isinstance(csrf.get('csrfToken'), str) or not csrf['csrfToken'] or not self.client.cookie('__Host-next-auth.csrf-token', 'chatgpt.com'):
                raise AuthFlowError('needs_interaction', '未建立完整登录会话，请改用浏览器')
            device = self.client.cookie('oai-did', 'chatgpt.com') or str(uuid.uuid4())
            self.stage('email')
            self.issued_after = time.time()
            signin = self.client.json('POST', CHATGPT + '/api/auth/signin/openai?' + urlencode({
                'prompt':'login', 'ext-oai-did':device, 'auth_session_logging_id':str(uuid.uuid4()),
                'screen_hint':'login_or_signup', 'login_hint':self.account.email}),
                data={'callbackUrl':CHATGPT+'/', 'csrfToken':csrf['csrfToken'], 'json':'true'}, referer=CHATGPT+'/')
            first, _ = self.client.follow(trusted_url(signin.get('url')))
            if not (first == CHATGPT + '/' and self.client.cookie('__Secure-next-auth.session-token', 'chatgpt.com')):
                self.advance({'continue_url':first})
            session = generate_oauth_session()
            final, response = self.client.follow(session.auth_url, session=session)
            if callback_code(final, session) is None:
                if urlsplit(final).path in ('/add-phone', '/phone-verification'):
                    raise AuthFlowError('phone_required', '待补手机：协议登录已跳过手机验证，未调用接码服务')
                session_id = first_session_id(response.text if response is not None else '')
                if not session_id:
                    raise AuthFlowError('needs_interaction', 'Codex 会话选择页面无法识别，请改用浏览器')
                payload = self.post('/api/accounts/session/select', {'session_id':session_id}, final)
                final = self.advance(payload, oauth=session)
            code = callback_code(final, session)
            if not code:
                raise AuthFlowError('oauth_error', '未收到有效 OAuth 授权码')
            return code, session, self.selected_workspace
        finally:
            if self.mailbox:
                self.mailbox.close()


def run_batch_protocol(accounts, timeout=180, proxy=None, headless=True, should_stop=None,
                       on_progress=None, recovery_dir=None, human=None, result_transform=None,
                       skip_phone_verification=False, *, prompt=None, transport=None, exchange=None):
    """Same result contract as run_batch_reauth; never launches a browser."""
    if not accounts or timeout <= 0:
        raise ValueError('没有账号或处理超时无效')
    proxy = normalize_proxy(proxy)
    recovery_file = None
    if recovery_dir is not None:
        folder = Path(recovery_dir) / (datetime.now().strftime('%Y%m%d-%H%M%S') + '-protocol-' + secrets.token_hex(4))
        folder.mkdir(parents=True, exist_ok=False)
        recovery_file = folder / 'accounts.json'
        write_export_file(recovery_file, [])
        log(f'协议登录成功结果自动保存到：{recovery_file}')
    log('本轮使用协议登录；遇到安全校验可手动改用浏览器，手机验证跳过')
    results = []
    for index, account in enumerate(accounts, 1):
        if should_stop and should_stop():
            break
        client = None
        try:
            client = ProtocolClient(proxy=proxy, deadline=time.monotonic()+timeout, should_stop=should_stop, transport=transport)
            code, session, selected = ProtocolLogin(account, client, prompt=prompt, human=human).run()
            check_running(should_stop, client.deadline)
            emit(account.email, 'token')
            token = (exchange or exchange_code)(code, session.code_verifier, session.redirect_uri, proxy, trust_env=False)
            # Once exchange succeeds, validate and persist the result even if stop was requested.
            payload = build_account_payload(token, account.email)
            if selected and payload['credentials'].get('chatgpt_account_id') != selected:
                raise AuthFlowError('identity', 'OAuth 返回的工作空间与选择不一致，未推送或替换账号')
            result = ReauthResult(account.email, True, account=payload, category='success')
        except (AuthFlowError, MailboxError) as exc:
            result = ReauthResult(account.email, False, category=exc.category, error=str(exc))
        except ValueError:
            result = ReauthResult(account.email, False, error='协议登录数据或凭据校验失败，请检查输入或改用浏览器')
        except Exception as exc:
            result = ReauthResult(account.email, False, error=f'协议登录未完成（{type(exc).__name__}），请检查网络或改用浏览器')
        finally:
            if client:
                client.close()
        if result_transform:
            result = result_transform(account, result)
        results.append(result)
        save_failed = False
        if result.ok and recovery_file:
            try:
                write_export_file(recovery_file, [r.account for r in results if r.ok and r.account])
            except OSError:
                log('自动保存失败，已停止后续账号；请立即导出当前结果')
                save_failed = True
        log(f'[{index}/{len(accounts)}] {account.email}: ' + ('协议授权成功' if result.ok else result.error or result.category))
        if on_progress:
            on_progress(index, len(accounts), result)
        if save_failed or result.category in ('cancelled', 'rate_limited', 'phone_fraud'):
            break
    return results
