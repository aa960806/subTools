"""Pure registration parsing and progress policy; no browser or account I/O."""
import re
from html.parser import HTMLParser


class _MailText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hidden = 0
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag in {'style', 'script'}:
            self.hidden += 1
        elif not self.hidden:
            self.parts.append(' ')

    def handle_endtag(self, tag):
        if tag in {'style', 'script'} and self.hidden:
            self.hidden -= 1
        elif not self.hidden:
            self.parts.append(' ')

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


OTP_WORDS = re.compile(r'code|verification|验证码|代码|确认码|確認コード|認証|検証|인증|확인', re.I)
OTP_DIGITS = re.compile(r'(?<!\d)\d{6}(?!\d)')


def graph_message_codes(message):
    sender = (((message.get('from') or {}).get('emailAddress') or {}).get('address') or '').casefold()
    subject = str(message.get('subject') or '')
    if not (sender.endswith('@openai.com') or re.search(r'openai|chatgpt', subject, re.I)):
        return set()
    parser = _MailText()
    parser.feed(str((message.get('body') or {}).get('content') or ''))
    body = ''.join(parser.parts)
    if not OTP_WORDS.search(subject + ' ' + body):
        return set()
    subject_codes = set(OTP_DIGITS.findall(subject))
    if subject_codes:
        # Preserve ambiguity; never guess the first of several subject codes.
        return subject_codes
    matches = list(OTP_DIGITS.finditer(body))
    contextual = {m.group() for m in matches if OTP_WORDS.search(body[max(0, m.start()-50):m.end()+50])}
    return contextual or {m.group() for m in matches}


def session_candidate(data):
    if not isinstance(data, dict) or data.get('error'):
        return {}
    candidate = data.get('session') if isinstance(data.get('session'), dict) else data
    if candidate.get('error'):
        return {}
    token = candidate.get('accessToken') or candidate.get('access_token') or data.get('accessToken') or data.get('access_token')
    if not isinstance(token, str) or not token.strip():
        return {}
    user = candidate.get('user') if isinstance(candidate.get('user'), dict) else data.get('user')
    return {'access_token': token.strip(), 'email': str((user or {}).get('email') or data.get('email') or '').strip()}


def registration_progress(item, row, account=None):
    """Public facts/actions only. Credentials remain in the encrypted task."""
    cp = item.get('checkpoint') or {}
    effects = cp.get('side_effects') or {}
    complete = bool(account and account.get('platform') == 'openai' and row.get('state') == 'success')
    created = bool(cp.get('create_confirmed') or complete)
    existing = row.get('state') in {'existing_account', 'partial_registered'}
    creation = '已创建' if created else '已有账号' if existing else '待核对' if any(effects.values()) else '未确认'
    totp = ('已确认' if effects.get('totp_confirmed') or complete and (account.get('extra') or {}).get('registration_totp', {}).get('enrolled')
            else '激活待核对' if effects.get('totp_activation_attempted') else '未绑定')
    facts = {'creation': creation, 'session': '已确认' if effects.get('session_confirmed') or complete else '未确认',
             'totp': totp, 'oauth': '已完成' if complete else '未完成'}
    actions = []
    if not row.get('source_task'):
        if complete:
            actions.append('pool')
        elif created or existing or row.get('state') == 'phone_required':
            actions.append('auth')
            if row.get('state') == 'phone_required':
                actions.append('phone')
    return {'facts': facts, 'actions': actions}
