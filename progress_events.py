"""Optional per-thread observations; observers never control account operations."""
import threading

_local = threading.local()
LABELS = {
    'page': '打开授权页', 'email': '提交邮箱', 'password': '提交密码',
    'otp': '二次验证', 'workspace': '选择空间', 'interaction': '等待人工操作',
    'phone': '手机号验证', 'token': '换取凭据', 'refresh': '刷新凭据',
    'pushing': '核对并推送',
    'mailbox_ready': '准备邮箱', 'sentinel': '准备身份校验',
    'identity_ready': '准备注册身份', 'auth_flow': '打开注册流程',
    'user_register': '提交注册信息', 'email_otp_send': '发送邮箱验证码',
    'email_otp_wait': '等待邮箱验证码', 'email_otp_validate': '校验邮箱验证码',
    'email_verification': '确认邮箱验证',
    'create_account': '创建账号', 'auth_session': '获取会话',
    'totp_enroll': '绑定二次验证',
    'access_token_probe': '验证凭据', 'finalize': '保存注册结果',
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
