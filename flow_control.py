"""Shared cancellation/deadline errors for browser and local operations."""
import time


class AuthFlowError(RuntimeError):
    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category


def check_running(should_stop=None, deadline=None):
    if should_stop is not None and should_stop():
        raise AuthFlowError("cancelled", "已取消当前账号")
    if deadline is not None and time.monotonic() >= deadline:
        raise AuthFlowError("timeout", "当前账号已超过处理时间限制")
