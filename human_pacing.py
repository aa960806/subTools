"""Interruptible step waits shared by the authorization and phone flows.

Waits are part of the account's total deadline. Cancellation is an exception,
never an indication that waiting or typing completed successfully.
"""

from __future__ import annotations

import random
import math
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from flow_control import AuthFlowError, check_running


def validate_scale(value) -> float:
    try:
        scale = float(value)
    except (ValueError, TypeError):
        raise ValueError("等待倍数必须为 0.1–10 之间的有限数值") from None
    if not math.isfinite(scale) or not 0.1 <= scale <= 10:
        raise ValueError("等待倍数必须为 0.1–10 之间的有限数值")
    return scale

# Per-step default ranges in seconds: (minimum, maximum).
STEP_RANGES: dict[str, tuple[float, float]] = {
    "open_page": (1.0, 2.0),
    "page_settle": (0.6, 1.4),
    "type_email": (0.8, 2.2),
    "after_email": (0.6, 1.5),
    "type_password": (0.9, 2.4),
    "after_password": (0.7, 1.8),
    "type_otp": (1.0, 2.6),
    "after_otp": (0.7, 1.8),
    "click": (0.25, 0.75),
    "between_accounts": (1.5, 3.5),
    "phone_form": (0.8, 2.0),
    "phone_send": (0.5, 1.4),
    "phone_wait_code": (0.3, 0.9),
    "phone_type_code": (0.9, 2.2),
    "phone_after_code": (0.6, 1.6),
}

STEP_LABELS: dict[str, str] = {
    "open_page": "打开授权页",
    "page_settle": "等待页面就绪",
    "type_email": "输入邮箱",
    "after_email": "提交邮箱后",
    "type_password": "输入密码",
    "after_password": "提交密码后",
    "type_otp": "输入验证码",
    "after_otp": "提交验证码后",
    "click": "点击按钮前",
    "between_accounts": "切换账号前",
    "phone_form": "填写手机号前",
    "phone_send": "发送短信前",
    "phone_wait_code": "等待短信前",
    "phone_type_code": "输入短信验证码",
    "phone_after_code": "提交短信验证码后",
}


@dataclass
class HumanSettings:
    """Randomized pacing configuration.

    ``scale`` multiplies every range, so a slower profile can be selected
    without editing each step; ``enabled=False`` disables all waiting.
    """

    enabled: bool = True
    scale: float = 1.0
    typing: bool = True
    seed: int | None = None
    overrides: dict[str, tuple[float, float]] = field(default_factory=dict)

    def __post_init__(self):
        self.scale = validate_scale(self.scale)

    def range_for(self, step: str) -> tuple[float, float] | None:
        if not self.enabled:
            return None
        low, high = self.overrides.get(step) or STEP_RANGES.get(step, (0.0, 0.0))
        low, high = max(0.0, float(low)) * self.scale, max(0.0, float(high)) * self.scale
        if high < low:
            low, high = high, low
        return (low, high)


_local = threading.local()


def _rng(settings: HumanSettings) -> random.Random:
    """Return a per-thread RNG; a fixed seed keeps tests reproducible."""
    if settings.seed is not None:
        return random.Random(settings.seed)
    rng = getattr(_local, "rng", None)
    if rng is None:
        rng = random.Random()
        _local.rng = rng
    return rng


def human_delay(
    settings: HumanSettings | None,
    step: str,
    *,
    should_stop: Callable[[], bool] | None = None,
    deadline: float | None = None,
    log_fn: Callable[[str], None] | None = None,
    reason: str = "",
) -> float:
    """Sleep a randomized interval for ``step`` and return the slept seconds.

    Cancellation/deadline expiry raises AuthFlowError. ``log_fn`` is called
    once per wait with a redacted, step-level description.
    """
    check_running(should_stop, deadline)
    if settings is None:
        return 0.0
    bounds = settings.range_for(step)
    if not bounds:
        return 0.0
    low, high = bounds
    seconds = low if high <= low else _rng(settings).uniform(low, high)
    if deadline is not None:
        remaining = deadline - time.monotonic()
        seconds = min(seconds, max(0.0, remaining))
    if log_fn is not None and seconds > 0.05:
        label = STEP_LABELS.get(step, step)
        suffix = f"（{reason}）" if reason else ""
        log_fn(f"模拟人工：{label} 等待 {seconds:.1f} 秒{suffix}")
    slept = 0.0
    end = time.monotonic() + seconds
    while True:
        check_running(should_stop, deadline)
        chunk = min(0.1, end - time.monotonic())
        if chunk <= 0:
            return seconds
        time.sleep(chunk)
        slept += chunk


def type_like_human(
    locator: Any,
    text: str,
    settings: HumanSettings | None,
    *,
    should_stop: Callable[[], bool] | None = None,
    deadline: float | None = None,
    log_fn: Callable[[str], None] | None = None,
) -> bool:
    """Fill ``locator`` by typing character by character.

    Returns True when the value was typed key by key; False tells the caller to
    fall back to a single ``fill`` (secure fields, or typing unavailable).
    """
    check_running(should_stop, deadline)
    if settings is None or not settings.enabled or not settings.typing:
        return False
    value = str(text or "")
    if not value:
        return False
    delay_min, delay_max = 0.04 * settings.scale, 0.14 * settings.scale
    try:
        locator.click()
        check_running(should_stop, deadline)
        locator.press("Control+a")
        locator.press("Delete")
    except AuthFlowError:
        raise
    except Exception:
        return False
    try:
        for chunk in _typing_chunks(value, settings):
            check_running(should_stop, deadline)
            locator.type(chunk, delay=int(_rng(settings).uniform(delay_min, delay_max) * 1000))
        check_running(should_stop, deadline)
        return True
    except AuthFlowError:
        raise
    except Exception:
        # A field that rejects synthetic keys still accepts the value.
        try:
            check_running(should_stop, deadline)
            locator.fill(value)
            return True
        except AuthFlowError:
            raise
        except Exception:
            return False


def _typing_chunks(value: str, settings: HumanSettings) -> list[str]:
    chunks: list[str] = []
    index = 0
    rng = _rng(settings)
    while index < len(value):
        size = rng.choice((1, 1, 1, 2, 3))
        chunks.append(value[index:index + size])
        index += size
    return chunks


def human_settings_from_options(options: dict[str, Any] | None) -> HumanSettings:
    """Build settings from a GUI/options mapping, ignoring unknown keys.

    ``None`` (library and test callers that did not ask for pacing) means
    disabled, so existing callers keep their previous immediate behaviour;
    enabling is an explicit opt-in from the UI or a caller-built mapping.
    """
    if not options:
        return HumanSettings(enabled=False)
    scale = validate_scale(options.get("scale", 1.0))
    return HumanSettings(
        enabled=bool(options.get("enabled", True)),
        scale=scale,
        typing=bool(options.get("typing", True)),
        seed=options.get("seed"),
    )
