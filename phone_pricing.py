"""Price selection shared by the phone page and the paid number pool."""
from decimal import Decimal

from phone_smsbower import validate_price


def matching_offers(offers: list[dict], country: str, service: str, minimum: str = "", maximum: str = "",
                    excluded: set[tuple[str, str]] | None = None) -> list[dict]:
    low = Decimal(validate_price(minimum) or "0")
    high = Decimal(validate_price(maximum) or "Infinity")
    if low > high:
        raise ValueError("最低单价不能高于最高单价")
    return sorted((row for row in offers
                   if row["country"] == country and row["service"] == service and row["count"] > 0
                   and low <= Decimal(row["price"]) <= high
                   and (row["provider_id"], str(Decimal(row["price"]).normalize())) not in (excluded or set())),
                  key=lambda row: (Decimal(row["price"]), row["provider_id"]))


def lowest_price_group(offers: list[dict]) -> list[dict]:
    if not offers:
        return []
    price = min(Decimal(row["price"]) for row in offers)
    return [row for row in offers if Decimal(row["price"]) == price]


def price_summary(offers: list[dict], country: str, maximum: str) -> str:
    eligible = matching_offers(offers, country, "dr", maximum=maximum)
    available = matching_offers(offers, country, "dr")
    if not available:
        return "当前没有报价库存；可稍后刷新或选择其他国家。"
    prices = sorted({Decimal(row["price"]) for row in available})
    price_list = " / ".join(f"${price}" for price in prices[:5]) + (" …" if len(prices) > 5 else "")
    if not eligible:
        return f"当前最低 ${prices[0]}，超过最高单价 ${maximum}，不会购买。\n报价：{price_list}"
    group = lowest_price_group(eligible)
    count = sum(row["count"] for row in group)
    return (f"自动匹配：${group[0]['price']} · 报价库存 {count} · {len(group)} 家供应商\n"
            f"报价：{price_list}\n库存以实际分配为准；缺号时按重试次数匹配下一档，始终遵守限价。")
