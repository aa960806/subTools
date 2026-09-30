"""Optional per-thread observations; observers never control account operations."""
import threading

_local = threading.local()
LABELS = {
    'page': '打开授权页', 'email': '提交邮箱', 'password': '提交密码',
    'otp': '二次验证', 'workspace': '选择空间', 'interaction': '等待人工操作',
    'phone': '手机号验证', 'token': '换取凭据', 'refresh': '刷新凭据',
    'pushing': '核对并推送',
}


def bind(callback=None):
    _local.callback = callback


def emit(email, stage):
    callback = getattr(_local, 'callback', None)
    if callback and stage in LABELS:
        try:
            callback(email, stage)
        except Exception:
            # A presentation observer must not trigger a repeated login/write.
            pass
