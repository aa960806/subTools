"""Ephemeral manual protocol-login input, isolated by task and prompt ID."""
import threading
import uuid

from flow_control import check_running


class LoginInteraction:
    def __init__(self):
        self.lock = threading.Lock()
        self.ready = threading.Event()
        self.prompt = None
        self.value = None

    def snapshot(self):
        with self.lock:
            return dict(self.prompt) if self.prompt else None

    def request(self, email, kind, *, deadline, should_stop):
        labels = {'password':'登录密码', 'email_code':'邮箱验证码', 'totp':'验证器验证码'}
        with self.lock:
            self.ready.clear()
            self.value = None
            self.prompt = {'id':uuid.uuid4().hex, 'email':email, 'kind':kind, 'label':labels[kind]}
        try:
            while True:
                check_running(should_stop, deadline)
                if self.ready.wait(.2):
                    check_running(should_stop, deadline)
                    with self.lock:
                        return self.value
        finally:
            self.clear()

    def submit(self, prompt_id, value):
        with self.lock:
            if not self.prompt or self.ready.is_set() or prompt_id != self.prompt['id']:
                raise ValueError('此输入请求已结束或已切换账号，请等待最新提示')
            if not isinstance(value, str) or not value or len(value) > 4096:
                raise ValueError('输入不能为空，且不能超过 4096 个字符')
            if self.prompt['kind'] != 'password' and (len(value) != 6 or not value.isascii() or not value.isdigit()):
                raise ValueError('验证码须为 6 位数字')
            self.value = value
            self.ready.set()

    def clear(self):
        with self.lock:
            self.prompt = self.value = None
            self.ready.clear()
