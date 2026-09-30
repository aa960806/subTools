"""Pure country quote normalization, shared by web and desktop views."""
from decimal import Decimal
import re
from phone_smsbower import SmsBowerError, COUNTRY_PINYIN, country_label, validate_price


def normalize_price_options(prices, countries, service):
    if not isinstance(prices, dict):
        raise SmsBowerError("sms_provider", "SMSBower 国家报价格式无法识别")
    country_index = {}
    records = countries.items() if isinstance(countries, dict) else enumerate(countries) if isinstance(countries, list) else ()
    for alias, record in records:
        if not isinstance(record, dict):
            continue
        for key in (alias, record.get("activate_org_code"), record.get("id"), record.get("slug"),
                    record.get("title"), record.get("eng"), record.get("chn"), record.get("iso")):
            if key is not None and str(key):
                country_index[str(key).casefold()] = record
    options = {}
    for key, services in prices.items():
        if not isinstance(services, dict):
            continue
        details = services.get(service, services)
        if not isinstance(details, dict):
            continue
        info = country_index.get(str(key).casefold(), {})
        country = str(info.get("activate_org_code", key))
        if not re.fullmatch(r"[0-9]{1,5}", country):
            continue
        count = str(details.get("count", ""))
        if not re.fullmatch(r"[0-9]{1,12}", count) or int(count) <= 0:
            continue
        try:
            price = validate_price(str(details.get("cost", "")))
        except ValueError:
            continue
        if not price:
            continue
        known = country in COUNTRY_PINYIN
        title = country_label(country) if known else str(info.get("chn") or info.get("eng") or info.get("title") or f"国家 {country}")
        title = re.sub(r"[^\w\s（）()\-]", "", title)[:70]
        option = {"country": country, "title": title, "price": price, "count": int(count), "supported": known}
        previous = options.get(country)
        if previous is None or Decimal(price) < Decimal(previous["price"]):
            options[country] = option
    return sorted(options.values(), key=lambda row: (Decimal(row["price"]), -row["count"], row["country"]))
