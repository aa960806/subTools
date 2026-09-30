"""SMSBower number pool with per-number reuse, aligned with GPT-Register-Tool."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from phone_pricing import matching_offers, lowest_price_group

from phone_smsbower import (
    DEFAULT_ENDPOINT,
    GHANA_COUNTRY_CODE,
    OPENAI_SERVICE_CODE,
    SmsBowerClient,
    normalize_phone,
    normalize_service,
    parse_country_choice,
    validate_price,
)


@dataclass
class SmsbowerSettings:
    api_key: str = field(default="", repr=False)
    endpoint: str = DEFAULT_ENDPOINT
    country: str = GHANA_COUNTRY_CODE
    service: str = OPENAI_SERVICE_CODE
    min_price: str = ""
    max_price: str = "0.06"
    max_reuse: int = 3
    sms_timeout: int = 120
    sms_poll_interval: int = 5
    # Total phone-flow attempts per account: the initial attempt plus retries.
    # The page handler owns this budget; buying a number never retries itself.
    number_attempts: int = 3
    country_retry_count: int = 0
    fallback_countries: list[str] = field(default_factory=list)
    proxy: str = field(default="", repr=False)
    # Describes where the already-resolved proxy came from; never re-resolve
    # system settings midway through a paid batch.
    network_source: str = "explicit"
    auto_price_match: bool = False


def phone_retry_plan(settings: SmsbowerSettings) -> tuple[int, list[str]]:
    """Validate paid retry limits and return the ordered country rounds."""
    def count(value, minimum: int, label: str) -> int:
        if isinstance(value, bool) or not (
            isinstance(value, int)
            or isinstance(value, str) and value.isascii() and value.isdecimal()
        ):
            raise ValueError(f"{label}必须为整数")
        number = int(value)
        if number < minimum:
            raise ValueError(f"{label}必须大于等于 {minimum}")
        return number

    attempts = count(settings.number_attempts, 1, "每个国家的尝试次数")
    switches = count(settings.country_retry_count, 0, "大重试次数")
    primary = parse_country_choice(settings.country)
    if not isinstance(settings.fallback_countries, (list, tuple)):
        raise ValueError("备用国家必须为国家列表")
    fallbacks = []
    for value in settings.fallback_countries:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("备用国家不能为空")
        country = parse_country_choice(value)
        if country != primary and country not in fallbacks:
            fallbacks.append(country)
    if len(fallbacks) < switches:
        raise ValueError(f"大重试 {switches} 次需要至少 {switches} 个不同于首选国家的备用国家")
    return attempts, [primary, *fallbacks[:switches]]


class PhonePoolError(RuntimeError):
    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category


@dataclass
class PhoneSlot:
    settings: SmsbowerSettings
    phone: str = ""
    activation_id: str = ""
    reuse_count: int = 0
    last_sms_code: str = ""
    price: str = ""

    @property
    def max_reuse_count(self) -> int:
        return max(1, int(self.settings.max_reuse or 1))

    @property
    def remaining(self) -> int:
        return max(0, self.max_reuse_count - self.reuse_count)

    @property
    def is_exhausted(self) -> bool:
        return self.reuse_count >= self.max_reuse_count


class PhonePool:
    def __init__(self, settings: SmsbowerSettings, journal_path: str | Path | None = None) -> None:
        _attempts, countries = phone_retry_plan(settings)
        validate_price(settings.max_price)
        validate_price(settings.min_price)
        matching_offers([], countries[0], normalize_service(settings.service), settings.min_price, settings.max_price)
        self.settings = settings
        self.active_country = countries[0]
        self._quote_retry_countries: set[str] = set()
        self._unavailable_quotes: dict[str, set[tuple[str, str]]] = {}
        self.lock = threading.Lock()
        self.slot = PhoneSlot(settings=settings)
        # Activation ids are retained when SMSBower declines a status change.
        # Losing the id makes it impossible to retry cleanup or explain a
        # potentially billable order to the user.
        self.pending_cleanup: dict[str, str] = {}
        self.journal_path = Path(journal_path) if journal_path is not None else None
        self._owner = hashlib.sha256((settings.endpoint + settings.api_key).encode()).hexdigest()
        self.client = SmsBowerClient(
            api_key=settings.api_key.strip(),
            endpoint=settings.endpoint.strip() or DEFAULT_ENDPOINT,
            proxy=settings.proxy or None,
        )
        if self.journal_path is not None and self.journal_path.exists():
            try:
                data = json.loads(self.journal_path.read_text(encoding="utf-8"))
                for record in data:
                    if record.get("owner") == self._owner:
                        self.pending_cleanup[str(record["activation_id"])] = str(record["operation"])
            except (OSError, ValueError, KeyError, TypeError) as exc:
                raise PhonePoolError("sms_cleanup_required", "短信订单恢复记录无法读取，请检查 recovery/phone-orders.json") from exc

    def _save_journal(self) -> None:
        if self.journal_path is None:
            return
        records = []
        try:
            if self.journal_path.exists():
                records = [item for item in json.loads(self.journal_path.read_text(encoding="utf-8")) if item.get("owner") != self._owner]
            records.extend({"owner": self._owner, "activation_id": activation_id, "operation": operation}
                           for activation_id, operation in self.pending_cleanup.items())
            if self.slot.activation_id:
                records.append({"owner": self._owner, "activation_id": self.slot.activation_id,
                                "operation": "complete" if self.slot.reuse_count else "cancel"})
            self.journal_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.journal_path.with_suffix(".tmp")
            temporary.write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")
            temporary.replace(self.journal_path)
        except (OSError, ValueError, TypeError) as exc:
            raise PhonePoolError("sms_cleanup_required", "短信订单记录保存失败，已停止继续买号") from exc

    def _remember_cleanup(self, activation_id: str, operation: str) -> None:
        if activation_id:
            self.pending_cleanup.setdefault(activation_id, operation)

    def _release_slot(self, complete: bool) -> bool:
        """Finish/cancel the current activation and always clear local use state."""
        activation_id = self.slot.activation_id
        if not activation_id:
            self.slot = PhoneSlot(settings=self.settings)
            return True
        # A previous account may already have consumed an SMS from this order.
        # Failure/stop on a later reuse must finish that used order, not request
        # cancellation of an unused purchase.
        complete = complete or self.slot.reuse_count > 0
        try:
            ok = self.client.complete(activation_id) if complete else self.client.cancel(activation_id)
        except Exception:
            ok = False
        if not ok:
            self._remember_cleanup(activation_id, "complete" if complete else "cancel")
        self.slot = PhoneSlot(settings=self.settings)
        self._save_journal()
        return bool(ok)

    @staticmethod
    def _check_deadline(should_stop, deadline) -> None:
        if should_stop and should_stop():
            raise PhonePoolError("cancelled", "已取消购买号码")
        if deadline is not None and time.monotonic() >= deadline:
            raise PhonePoolError("timeout", "账号处理已超时，停止购买号码")

    def _acquire(self, should_stop=None, deadline=None) -> bool:
        self._check_deadline(should_stop, deadline)
        provider_options = {}
        availability_note = ""
        selected = []
        purchase_min, purchase_max = self.settings.min_price, self.settings.max_price
        if self.settings.auto_price_match:
            offers = self.client.get_prices(
                normalize_service(self.settings.service), self.active_country,
                timeout=None if deadline is None else max(0.05, deadline - time.monotonic()),
            )
            self._check_deadline(should_stop, deadline)
            eligible = matching_offers(offers, self.active_country, normalize_service(self.settings.service),
                                       purchase_min, purchase_max,
                                       self._unavailable_quotes.get(self.active_country, set()))
            selected = lowest_price_group(eligible)
            if not selected:
                within_cap = matching_offers(offers, self.active_country, normalize_service(self.settings.service), purchase_min, purchase_max)
                if within_cap:
                    detail = "限价内的报价供应商在本批次均已返回 NO_NUMBERS；不会突破最高单价"
                elif offers:
                    detail = f"当前最低报价 ${min(Decimal(row['price']) for row in offers)}，没有符合价格范围的库存；请调整限价或备用国家"
                else:
                    detail = "当前国家没有报价库存"
                raise PhonePoolError("sms_unavailable", f"自动匹配未找到可购买报价：{detail}")
            purchase_min = purchase_max = selected[0]["price"]
            provider_options["provider_ids"] = ",".join(dict.fromkeys(row["provider_id"] for row in selected))
            availability_note = f"自动匹配 ${purchase_max} 的供应商未分配号码；后续重试将跳过本批次已缺号的报价"
            from openai_reauth import log
            log(f"SMSBower 自动匹配：${purchase_max} · 报价库存 {sum(row['count'] for row in selected)} · 最高单价 {('$' + self.settings.max_price) if self.settings.max_price else '不限'}")
        elif self.active_country in self._quote_retry_countries:
            offers = self.client.get_prices(
                normalize_service(self.settings.service), self.active_country,
                timeout=None if deadline is None else max(0.05, deadline - time.monotonic()),
            )
            self._check_deadline(should_stop, deadline)
            # The quote response is advisory; even empty/stale inventory must
            # not cause an unbounded retry or silently increase the price cap.
            if isinstance(offers, list):
                minimum = Decimal(self.settings.min_price) if self.settings.min_price else Decimal(0)
                maximum = Decimal(self.settings.max_price) if self.settings.max_price else Decimal("Infinity")
                eligible = [offer for offer in offers if minimum <= Decimal(offer["price"]) <= maximum]
                if eligible:
                    provider_options["provider_ids"] = ",".join(dict.fromkeys(offer["provider_id"] for offer in eligible))
                    lowest = min(Decimal(offer["price"]) for offer in eligible)
                    availability_note = f"报价显示范围内有库存（最低 ${lowest}），但供应商仍未分配号码；报价可能延迟或存在供号限制"
                    from openai_reauth import log
                    log(f"SMSBower：报价最低 ${lowest}，本次重试指定 {len(provider_options['provider_ids'].split(','))} 个价格范围内的供应商，保留原购买上限")
                elif offers:
                    lowest = min(Decimal(offer["price"]) for offer in offers)
                    availability_note = f"当前报价最低 ${lowest}，没有符合所设价格范围的库存"
                else:
                    availability_note = "报价查询也未返回有库存的供应商"
        try:
            activation = self.client.get_number(
                service=normalize_service(self.settings.service),
                country=self.active_country,
                min_price=purchase_min,
                max_price=purchase_max,
                timeout=None if deadline is None else max(0.05, deadline - time.monotonic()),
                **provider_options,
            )
        except Exception as exc:
            category = getattr(exc, "category", "")
            if category in {"sms_fatal", "rate_limited", "sms_network", "sms_cleanup_required", "cancelled"}:
                raise
            marker = str(exc).upper()
            if "NO_BALANCE" in marker:
                raise PhonePoolError("sms_fatal", "SMSBower 余额不足") from exc
            if "BAD_KEY" in marker or "BAD_KEY" in marker.replace(" ", "_"):
                raise PhonePoolError("sms_fatal", "SMSBower API Key 无效") from exc
            if not category:
                raise PhonePoolError("sms_network", "买号请求结果未知，已停止重试，避免重复购买；请检查 SMSBower 订单") from exc
            if category != "sms_unavailable":
                raise PhonePoolError("sms_fatal", "买号结果无法确认，已停止重试；请检查 SMSBower 订单") from exc
            self._check_deadline(should_stop, deadline)
            self._quote_retry_countries.add(self.active_country)
            if selected:
                self._unavailable_quotes.setdefault(self.active_country, set()).update(
                    (row["provider_id"], str(Decimal(row["price"]).normalize())) for row in selected)
            # Only the caller retries, sharing its limit with send/receive errors.
            if availability_note:
                raise PhonePoolError("sms_unavailable", f"SMSBower 未分配到号码（NO_NUMBERS）；{availability_note}") from exc
            raise
        self._quote_retry_countries.discard(self.active_country)
        self.slot.phone = normalize_phone(activation.phone)
        self.slot.activation_id = activation.activation_id
        self.slot.reuse_count = 0
        self.slot.last_sms_code = ""
        self.slot.price = activation.price
        self._save_journal()
        if selected and activation.price:
            try:
                price = Decimal(validate_price(activation.price))
                over_budget = price > Decimal(purchase_max)
            except (ValueError, ArithmeticError):
                over_budget = True
            if over_budget:
                self._release_slot(complete=False)
                self.ensure_released()
                raise PhonePoolError("sms_fatal", "供应商返回的订单价格超出匹配报价或无法确认，已取消并停止；请核对短信平台订单")
        return True

    def ensure_released(self) -> None:
        """Do not start another paid attempt after uncertain order cleanup."""
        if self.pending_cleanup:
            raise PhonePoolError("sms_cleanup_required", "短信订单未成功释放，已停止重试及切换国家；请检查 SMSBower 订单")

    def switch_country(self, country: str, should_stop=None, deadline=None) -> None:
        target = parse_country_choice(country)
        with self.lock:
            self._check_deadline(should_stop, deadline)
            if target == self.active_country:
                return
            self.ensure_released()
            if self.slot.activation_id:
                self._release_slot(complete=self.slot.reuse_count > 0)
                self.ensure_released()
            self._check_deadline(should_stop, deadline)
            self.active_country = target

    def reusable_country(self) -> str | None:
        with self.lock:
            if self.slot.activation_id and self.slot.reuse_count > 0 and not self.slot.is_exhausted:
                return self.active_country
        return None

    def prepare_for_send(self, should_stop=None, deadline=None) -> str:
        self._check_deadline(should_stop, deadline)
        if self.pending_cleanup:
            self.cleanup()
            if self.pending_cleanup:
                raise PhonePoolError("sms_cleanup_required", "仍有短信订单未成功释放，已停止买号；请稍后重试或在 SMSBower 处理订单")
        with self.lock:
            self._check_deadline(should_stop, deadline)
            if self.slot.is_exhausted or not self.slot.activation_id:
                if self.slot.activation_id:
                    self._release_slot(complete=True)
                    if self.pending_cleanup:
                        raise PhonePoolError("sms_cleanup_required", "短信订单未成功完成，已停止买号")
                if not self._acquire(should_stop, deadline):
                    raise RuntimeError("smsbower_prepare_failed")
            elif self.slot.reuse_count > 0:
                if not self.client.request_additional(self.slot.activation_id):
                    self._release_slot(complete=False)
                    if self.pending_cleanup:
                        raise PhonePoolError("sms_cleanup_required", "短信订单未成功释放，已停止买号")
                    if not self._acquire(should_stop, deadline):
                        raise RuntimeError("smsbower_prepare_failed")
            return self.slot.phone

    def wait_code(self, should_stop=None, timeout=None) -> str:
        with self.lock:
            activation_id = self.slot.activation_id
            previous = self.slot.last_sms_code
            timeout = min(self.settings.sms_timeout, timeout) if timeout is not None else self.settings.sms_timeout
            interval = self.settings.sms_poll_interval
        if not activation_id:
            raise RuntimeError("smsbower_no_active_number")
        if should_stop and should_stop():
            self.cancel_current()
            raise RuntimeError("sms_cancelled")
        code = self.client.wait_for_code(
            activation_id,
            timeout=timeout,
            poll_interval=interval,
            previous_code=previous,
            should_stop=should_stop,
        )
        if not code:
            stopped = bool(should_stop and should_stop())
            with self.lock:
                if self.slot.activation_id:
                    self._release_slot(complete=False)
            raise RuntimeError("sms_cancelled" if stopped else "phone_sms_timeout")
        with self.lock:
            self.slot.last_sms_code = code
        return code

    def mark_used(self) -> dict:
        with self.lock:
            if not self.slot.activation_id:
                raise RuntimeError("smsbower_no_active_number")
            self.slot.reuse_count += 1
            info = {
                "status": "verified",
                "phone": self.slot.phone,
                "activation_id": self.slot.activation_id,
                "reuse_count": self.slot.reuse_count,
                "max_reuse": self.slot.max_reuse_count,
                "remaining": self.slot.remaining,
                "price": self.slot.price,
            }
            try:
                if self.slot.is_exhausted:
                    if not self._release_slot(complete=True):
                        raise PhonePoolError("sms_cleanup_required", "已绑定手机号，但短信订单未成功完成")
                else:
                    self._save_journal()
            except Exception as exc:
                # OpenAI has already accepted the code. A later local write or
                # provider cleanup failure must not turn it into a binding
                # failure and invite another paid attempt for the same account.
                error = PhonePoolError("sms_cleanup_required", "手机号已绑定，但短信订单记录或收尾失败，已停止后续账号")
                error.phone_info = info
                raise error from exc
            return info

    def cancel_current(self) -> None:
        with self.lock:
            self._release_slot(complete=False)

    def cleanup(self) -> dict[str, bool]:
        """Retry status updates for activations left by a failed request.

        This is safe to call from a batch ``finally`` block. Successful entries
        are removed; failures remain in ``pending_cleanup`` for a later retry and
        are reported to the caller.
        """
        with self.lock:
            result: dict[str, bool] = {}
            for activation_id, operation in list(self.pending_cleanup.items()):
                try:
                    ok = self.client.complete(activation_id) if operation == "complete" else self.client.cancel(activation_id)
                except Exception:
                    ok = False
                result[activation_id] = bool(ok)
                if ok:
                    self.pending_cleanup.pop(activation_id, None)
            self._save_journal()
            return result

    def close(self) -> dict[str, bool]:
        with self.lock:
            if self.slot.activation_id:
                self._release_slot(complete=self.slot.reuse_count > 0)
        self.cleanup()
        return {activation_id: False for activation_id in self.pending_cleanup}
