"""SMSBower handler API client, aligned with GPT-Register-Tool."""

from __future__ import annotations

import json
import time
import re
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any, Optional

import httpx

DEFAULT_ENDPOINT = "https://smsbower.page/stubs/handler_api.php"
OPENAI_SERVICE_CODE = "dr"
GHANA_COUNTRY_CODE = "38"


class SmsBowerError(RuntimeError):
    """A safe provider error; never includes the request URL or credentials."""

    def __init__(self, category: str, message: str, code: str = "") -> None:
        super().__init__(message)
        self.category = category
        self.code = code


def provider_error(raw: str) -> SmsBowerError:
    known = {
        "NO_BALANCE": ("sms_fatal", "SMSBower 余额不足，已暂停批次"),
        "BAD_KEY": ("sms_fatal", "SMSBower API Key 无效，已暂停批次"),
        "NO_KEY": ("sms_fatal", "SMSBower API Key 缺失，已暂停批次"),
        "BANNED": ("sms_fatal", "SMSBower 账号受限，已暂停批次"),
        "NO_NUMBERS": ("sms_unavailable", "SMSBower 当前国家或价格没有可用号码"),
        "NO_ACTIVATION": ("sms_order", "SMSBower 订单不存在或已结束"),
        "BAD_STATUS": ("sms_order", "SMSBower 不接受当前订单状态变更"),
        "BAD_SERVICE": ("sms_fatal", "SMSBower 服务码无效"),
        "BAD_ACTION": ("sms_fatal", "SMSBower 接口动作无效"),
    }
    for code, (category, message) in known.items():
        if re.search(r"\b" + code + r"\b", str(raw).upper()):
            return SmsBowerError(category, f"{message}（{code}）", code)
    return SmsBowerError("sms_provider", "SMSBower 返回无法识别的结果，请检查服务状态", "UNKNOWN")


def validate_price(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        amount = Decimal(text)
    except InvalidOperation as exc:
        raise ValueError("最高单价必须是正数或留空") from exc
    if not amount.is_finite() or amount <= 0:
        raise ValueError("最高单价必须是正数或留空")
    return format(amount, "f")

SERVICE_ALIASES = {
    "openai": OPENAI_SERVICE_CODE,
    "chatgpt": OPENAI_SERVICE_CODE,
    "openai(chatgpt)": OPENAI_SERVICE_CODE,
    "openai (chatgpt)": OPENAI_SERVICE_CODE,
}

# SMSBower/sms-activate country ids with names people can read.
COUNTRY_CATALOG: tuple[tuple[str, str, str], ...] = (
    ("0", "俄罗斯", "Russia"),
    ("1", "乌克兰", "Ukraine"),
    ("2", "哈萨克斯坦", "Kazakhstan"),
    ("3", "中国", "China"),
    ("4", "菲律宾", "Philippines"),
    ("5", "缅甸", "Myanmar"),
    ("6", "印度尼西亚", "Indonesia"),
    ("7", "马来西亚", "Malaysia"),
    ("8", "肯尼亚", "Kenya"),
    ("9", "坦桑尼亚", "Tanzania"),
    ("10", "越南", "Vietnam"),
    ("11", "吉尔吉斯斯坦", "Kyrgyzstan"),
    ("12", "美国虚拟号", "USA virtual"),
    ("13", "以色列", "Israel"),
    ("14", "中国香港", "Hong Kong"),
    ("15", "波兰", "Poland"),
    ("16", "英国", "United Kingdom"),
    ("17", "马达加斯加", "Madagascar"),
    ("19", "尼日利亚", "Nigeria"),
    ("21", "埃及", "Egypt"),
    ("22", "印度", "India"),
    ("23", "爱尔兰", "Ireland"),
    ("24", "柬埔寨", "Cambodia"),
    ("31", "南非", "South Africa"),
    ("32", "罗马尼亚", "Romania"),
    ("33", "哥伦比亚", "Colombia"),
    ("36", "加拿大", "Canada"),
    ("37", "摩洛哥", "Morocco"),
    ("38", "加纳", "Ghana"),
    ("39", "阿根廷", "Argentina"),
    ("43", "德国", "Germany"),
    ("48", "荷兰", "Netherlands"),
    ("52", "泰国", "Thailand"),
    ("54", "墨西哥", "Mexico"),
    ("55", "中国台湾", "Taiwan"),
    ("56", "西班牙", "Spain"),
    ("62", "土耳其", "Turkey"),
    ("63", "捷克", "Czechia"),
    ("65", "秘鲁", "Peru"),
    ("66", "巴基斯坦", "Pakistan"),
    ("67", "新西兰", "New Zealand"),
    ("73", "巴西", "Brazil"),
    ("78", "法国", "France"),
    ("82", "比利时", "Belgium"),
    ("86", "意大利", "Italy"),
    ("95", "阿联酋", "UAE"),
    ("117", "葡萄牙", "Portugal"),
    ("129", "希腊", "Greece"),
    ("163", "芬兰", "Finland"),
    ("172", "丹麦", "Denmark"),
    ("173", "瑞士", "Switzerland"),
    ("174", "挪威", "Norway"),
    ("175", "澳大利亚", "Australia"),
    ("187", "美国", "USA"),
    ("196", "新加坡", "Singapore"),
)

COUNTRY_ALIASES = {
    "ghana": GHANA_COUNTRY_CODE,
    "gh": GHANA_COUNTRY_CODE,
    "加纳": GHANA_COUNTRY_CODE,
    "+233": GHANA_COUNTRY_CODE,
    "233": GHANA_COUNTRY_CODE,
}
COUNTRY_ALIASES.update({code: code for code, _zh, _en in COUNTRY_CATALOG})
COUNTRY_ALIASES.update({zh: code for code, zh, _en in COUNTRY_CATALOG})
COUNTRY_ALIASES.update({en.lower(): code for code, _zh, en in COUNTRY_CATALOG})
COUNTRY_ALIASES.update({f"{zh} {en}".lower(): code for code, zh, en in COUNTRY_CATALOG})
COUNTRY_ALIASES.update({f"{zh}（{en}）".lower(): code for code, zh, en in COUNTRY_CATALOG})


def country_label(code: str) -> str:
    wanted = str(code or GHANA_COUNTRY_CODE).strip()
    for item_code, zh, en in COUNTRY_CATALOG:
        if item_code == wanted:
            return f"{zh}（{en}）"
    return wanted or "加纳（Ghana）"


# Explicit pinyin avoids a platform-dependent locale or an extra runtime
# dependency. Keep provider codes and labels unchanged for existing configs.
COUNTRY_PINYIN = {
    "0": "eluosi", "1": "wukelan", "2": "hasakesitan", "3": "zhongguo",
    "4": "feilvbin", "5": "miandian", "6": "yindunixiya", "7": "malaixiya",
    "8": "kenniya", "9": "tansangniya", "10": "yuenan", "11": "jierjisisitan",
    "12": "meiguoxunihao", "13": "yiselie", "14": "zhongguoxianggang",
    "15": "bolan", "16": "yingguo", "17": "madajiasijia", "19": "niriliya",
    "21": "aiji", "22": "yindu", "23": "aierlan", "24": "jianpuzhai",
    "31": "nanfei", "32": "luomaniya", "33": "gelunbiya", "36": "jianada",
    "37": "moluoge", "38": "jiana", "39": "agenting", "43": "deguo",
    "48": "helan", "52": "taiguo", "54": "moxige", "55": "zhongguotaiwan",
    "56": "xibanya", "62": "tuerqi", "63": "jieke", "65": "bilu",
    "66": "bajisitan", "67": "xinxilan", "73": "baxi", "78": "faguo",
    "82": "bilishi", "86": "yidali", "95": "alianqiu", "117": "putaoya",
    "129": "xila", "163": "fenlan", "172": "danmai", "173": "ruishi",
    "174": "nuowei", "175": "aodaliya", "187": "meiguo", "196": "xinjiapo",
}


def country_dropdown_values() -> list[str]:
    return [country_label(code) for code, _zh, _en in
            sorted(COUNTRY_CATALOG, key=lambda item: COUNTRY_PINYIN[item[0]])]


def parse_country_choice(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return GHANA_COUNTRY_CODE
    code = COUNTRY_ALIASES.get(text.lower(), COUNTRY_ALIASES.get(text))
    if code is None:
        raise ValueError("无法识别接码国家，请重新从列表选择")
    return code


def normalize_service(service: str) -> str:
    value = str(service or OPENAI_SERVICE_CODE).strip()
    if not value:
        return OPENAI_SERVICE_CODE
    return SERVICE_ALIASES.get(value.lower(), value)


def normalize_country(country: str) -> str:
    value = str(country or GHANA_COUNTRY_CODE).strip()
    if not value:
        return GHANA_COUNTRY_CODE
    mapped = COUNTRY_ALIASES.get(value.lower(), COUNTRY_ALIASES.get(value, value))
    return mapped or GHANA_COUNTRY_CODE


def normalize_phone(phone: str) -> str:
    value = str(phone or "").strip()
    if not value:
        return ""
    if value.startswith("+"):
        return "+" + "".join(ch for ch in value[1:] if ch.isdigit())
    if value.startswith("00"):
        return "+" + "".join(ch for ch in value[2:] if ch.isdigit())
    digits = "".join(ch for ch in value if ch.isdigit())
    return f"+{digits}" if digits else ""


@dataclass
class SmsBowerActivation:
    activation_id: str
    phone: str
    service: str
    country: str
    price: str = ""
    acquired_at: float = field(default_factory=time.time)


@dataclass
class SmsBowerClient:
    api_key: str = field(default="", repr=False)
    endpoint: str = DEFAULT_ENDPOINT
    timeout: int = 15
    proxy: str | None = field(default=None, repr=False)

    def _do(self, action: str, params: dict | None = None, *, timeout: float | None = None) -> str:
        query = {"api_key": self.api_key, "action": action}
        if params:
            query.update(params)
        try:
            request_timeout = self.timeout if timeout is None else min(self.timeout, max(0.05, timeout))
            with httpx.Client(proxy=self.proxy or None, timeout=request_timeout, follow_redirects=False, trust_env=False) as client:
                response = client.get(self.endpoint, params=query)
                response.raise_for_status()
                return response.text.strip()
        except httpx.HTTPStatusError as exc:
            category = "rate_limited" if exc.response.status_code == 429 else "sms_network"
            raise SmsBowerError(category, f"SMSBower HTTP {exc.response.status_code}") from None
        except httpx.RequestError:
            message = "SMSBower 网络请求失败"
            if action == "getNumberV2":
                message += "，买号结果未知；请在订单页核对后重试"
            raise SmsBowerError("sms_fatal" if action == "getNumberV2" else "sms_network", message) from None

    def get_number(
        self,
        service: str = OPENAI_SERVICE_CODE,
        country: str = GHANA_COUNTRY_CODE,
        max_price: str = "",
        min_price: str = "",
        provider_ids: str = "",
        timeout: float | None = None,
    ) -> SmsBowerActivation:
        service_code = normalize_service(service)
        country_code = normalize_country(country)
        params: dict[str, str] = {"service": service_code, "country": country_code}
        if max_price:
            params["maxPrice"] = validate_price(max_price)
        if min_price:
            params["minPrice"] = validate_price(min_price)
        if provider_ids:
            params["providerIds"] = str(provider_ids)
        result = self._do("getNumberV2", params, timeout=timeout)
        try:
            if result.startswith("{"):
                activation = self._parse_get_number_v2(result, service_code, country_code)
            else:
                activation = self._parse_access_number(result, service_code, country_code)
            if not activation.activation_id or not re.fullmatch(r"\+[1-9]\d{6,14}", activation.phone):
                raise provider_error("")
            return activation
        except SmsBowerError as exc:
            if exc.code == "UNKNOWN":
                # A malformed success body may follow a real allocation. A
                # second getNumber call is not a safe retry of that purchase.
                raise SmsBowerError("sms_fatal", "买号返回结果无法确认，已暂停批次；请先在 SMSBower 核对订单", "UNKNOWN_PURCHASE") from None
            raise

    def _parse_get_number_v2(self, result: str, service: str, country: str) -> SmsBowerActivation:
        try:
            data = json.loads(result)
        except (ValueError, TypeError):
            raise provider_error("") from None
        if not isinstance(data, dict):
            raise provider_error("")
        activation_id = str(data.get("activationId") or data.get("activation_id") or data.get("id") or "").strip()
        phone = normalize_phone(data.get("phoneNumber") or data.get("phone") or data.get("number") or "")
        price = str(data.get("activationCost") or data.get("price") or "")
        if not activation_id or not phone:
            error = data.get("error") or data.get("message") or result[:200]
            raise provider_error(str(error))
        return SmsBowerActivation(
            activation_id=activation_id,
            phone=phone,
            service=service,
            country=country,
            price=price,
        )

    def _parse_access_number(self, result: str, service: str, country: str) -> SmsBowerActivation:
        parts = result.split(":", 2)
        if len(parts) != 3 or parts[0] != "ACCESS_NUMBER":
            raise provider_error(result)
        return SmsBowerActivation(
            activation_id=parts[1],
            phone=normalize_phone(parts[2]),
            service=service,
            country=country,
        )

    def get_status(self, activation_id: str, *, timeout: float | None = None) -> dict[str, Any]:
        return self._parse_status(self._do("getStatus", {"id": activation_id}, timeout=timeout))

    def _parse_status(self, result: str) -> dict[str, Any]:
        if result.startswith("STATUS_OK:"):
            return {"status": "OK", "code": result[len("STATUS_OK:"):].strip().strip("'\"")}
        if result == "STATUS_WAIT_CODE":
            return {"status": "WAIT_CODE"}
        if result.startswith("STATUS_WAIT_RETRY:"):
            return {"status": "WAIT_RETRY", "code": result[len("STATUS_WAIT_RETRY:"):].strip().strip("'\"" )}
        if result == "STATUS_CANCEL":
            return {"status": "CANCEL"}
        raise provider_error(result)

    def wait_for_code(
        self,
        activation_id: str,
        timeout: int = 120,
        poll_interval: int = 5,
        previous_code: str = "",
        should_stop=None,
    ) -> Optional[str]:
        deadline = time.monotonic() + timeout
        previous_code = str(previous_code or "").strip()
        last_network_error = None
        while time.monotonic() < deadline:
            if should_stop and should_stop():
                raise SmsBowerError("cancelled", "已停止等待短信")
            try:
                status = self.get_status(activation_id, timeout=max(0.05, deadline - time.monotonic()))
                last_network_error = None
                if status["status"] == "OK":
                    code = str(status.get("code") or "").strip()
                    if code and code != previous_code:
                        return code
                if status["status"] == "CANCEL":
                    return None
            except SmsBowerError as exc:
                if exc.category != "sms_network":
                    raise
                last_network_error = exc
            wait_until = min(deadline, time.monotonic() + poll_interval)
            while time.monotonic() < wait_until:
                if should_stop and should_stop():
                    raise SmsBowerError("cancelled", "已停止等待短信")
                time.sleep(min(0.2, max(0, wait_until - time.monotonic())))
        if last_network_error is not None:
            raise SmsBowerError("sms_network", "短信查询连接失败，无法确认是否收到短信；已停止继续买号")
        return None

    def set_status(self, activation_id: str, status: str) -> str:
        return self._do("setStatus", {"id": activation_id, "status": str(status)})

    def complete(self, activation_id: str) -> bool:
        try:
            # A retry after an ambiguous response can find an already closed or
            # expired order. There is no remaining activation to release.
            return self.set_status(activation_id, "6") in {"ACCESS_ACTIVATION", "NO_ACTIVATION"}
        except Exception:
            return False

    def cancel(self, activation_id: str) -> bool:
        try:
            return self.set_status(activation_id, "8") in {"ACCESS_CANCEL", "NO_ACTIVATION"}
        except Exception:
            return False

    def request_additional(self, activation_id: str) -> bool:
        try:
            return self.set_status(activation_id, "3") in {"ACCESS_RETRY_GET", "ACCESS_READY"}
        except Exception:
            return False

    def get_balance(self) -> str:
        result = self._do("getBalance")
        if not result.startswith("ACCESS_BALANCE:"):
            raise provider_error(result)
        return result.split(":", 1)[1]

    def get_prices(self, service: str, country: str, *, timeout: float | None = None) -> list[dict]:
        """Return validated provider quotes, never allocate or reserve a number."""
        service, country = normalize_service(service), normalize_country(country)
        raw = self._do("getPricesV3", {"service": service, "country": country}, timeout=timeout)
        try:
            data = json.loads(raw)
        except (ValueError, TypeError):
            raise provider_error(raw) from None
        if not isinstance(data, dict) or data.get("error"):
            raise provider_error(raw)
        services = data.get(country, {})
        providers = services.get(service, {}) if isinstance(services, dict) else None
        if not isinstance(providers, dict):
            raise SmsBowerError("sms_provider", "SMSBower 报价格式无法识别")
        offers = []
        for key, row in providers.items():
            if not isinstance(row, dict):
                continue
            provider_id = str(row.get("provider_id", key))
            count_text = str(row.get("count", ""))
            if not re.fullmatch(r"[0-9]{1,12}", provider_id) or not re.fullmatch(r"[0-9]{1,12}", count_text):
                continue
            try:
                price = validate_price(str(row.get("price", "")))
            except ValueError:
                continue
            if not price or int(count_text) <= 0:
                continue
            offers.append({"country": country, "service": service, "provider_id": provider_id,
                           "price": price, "count": int(count_text)})
        return sorted(offers, key=lambda row: (Decimal(row["price"]), row["provider_id"]))

    def get_price_options(self, service="dr", *, timeout=12) -> list[dict]:
        """Read a country-level catalogue; allocation still uses live V3 quotes."""
        from phone_price_data import normalize_price_options
        service = normalize_service(service)
        raw = self._do("getPrices", {"service": service}, timeout=timeout)
        try:
            prices = json.loads(raw)
        except (TypeError, ValueError):
            raise provider_error(raw) from None
        if not isinstance(prices, dict) or prices.get("error"):
            raise provider_error(raw)
        countries = self.get_countries(timeout=timeout)
        return normalize_price_options(prices, countries, service)

    def get_countries(self, *, timeout=None) -> dict:
        result = self._do("getCountries", timeout=timeout)
        try:
            data = json.loads(result)
        except ValueError:
            raise provider_error(result) from None
        if not isinstance(data, (dict, list)):
            raise provider_error(result)
        if isinstance(data, list):
            return {str(item["id"]): item for item in data if isinstance(item, dict) and "id" in item}
        return data
