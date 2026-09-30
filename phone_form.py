"""Phone-page input checks before a paid SMS request is submitted."""

from __future__ import annotations

import json
import re
from typing import Any

import phonenumbers
from phonenumbers.geocoder import country_name_for_number

from openai_reauth import AuthFlowError, first_visible
from phone_smsbower import normalize_phone


PHONE_INPUTS = [
    'input[type="tel"]', 'input[name="phone"]', 'input[name="phone_number"]',
    'input[autocomplete="tel"]', 'input[autocomplete="tel-national"]',
    'input[inputmode="tel"]', 'input[aria-label*="phone" i]',
]
COUNTRY_HINT = re.compile(r"country|calling.?code|dial.?code|国家|國家|区号|區號", re.I)
SMS_NAME = re.compile(r"\bsms\b|\btext messages?\b|短信|简讯|簡訊", re.I)
WHATSAPP_NAME = re.compile(r"whats\s*app", re.I)


def _stop(message: str) -> None:
    raise AuthFlowError("needs_interaction", message + "，已停止发送")


def _scope(page: Any, target: Any | None = None) -> Any:
    target = target if target is not None else first_visible(page, PHONE_INPUTS, timeout_ms=800)
    if target is not None:
        form = target.locator("xpath=ancestor::form[1]")
        if form.count():
            return form
    return page


def _control_description(control: Any) -> str:
    return control.evaluate("""el => [el.getAttribute('aria-label'), el.getAttribute('name'),
      el.getAttribute('id'), el.getAttribute('title'),
      ...Array.from(el.labels || [], label => label.textContent),
      ...((el.getAttribute('aria-labelledby') || '').split(/\\s+/).filter(Boolean)
        .map(id => document.getElementById(id)?.textContent || ''))].filter(Boolean).join(' ')""")


def _country_aliases(number: Any, region: str) -> set[str]:
    aliases = {region.casefold()}
    for language in ("en", "zh"):
        name = country_name_for_number(number, language)
        if name:
            aliases.add(name.casefold())
    # Common option values use these abbreviations instead of ISO alpha-2.
    if region == "US":
        aliases.update(("usa", "u.s.", "united states of america"))
    return aliases


def _option_matches(option: dict[str, Any], aliases: set[str], region: str) -> bool:
    for key in ("value", "country", "code"):
        if str(option.get(key, "")).strip().casefold() in aliases:
            return True
    text = str(option.get("text", "")).strip().casefold()
    # Ignore flags and the displayed calling code, but never match a different
    # country just because it shares +1 (or another shared calling code).
    text = re.sub(r"[\U0001f1e6-\U0001f1ff]", "", text)
    text = re.sub(r"\(?\s*\+\d{1,4}\s*\)?", " ", text).strip(" \t-–—,()")
    return text in aliases or text == region.casefold()


def _native_options(control: Any) -> list[dict[str, Any]]:
    return control.locator("option").evaluate_all("""options => options.map((el, index) => ({
      index, value: el.value, text: el.textContent, country: el.dataset.country,
      code: el.dataset.countryCode, disabled: el.disabled
    }))""")


def _select_country(page: Any, scope: Any, number: Any, region: str) -> bool:
    aliases = _country_aliases(number, region)
    native_matches = []
    suspicious_native = False
    selects = scope.locator("select")
    for index in range(selects.count()):
        control = selects.nth(index)
        options = _native_options(control)
        matches = [item for item in options if _option_matches(item, aliases, region) and not item["disabled"]]
        hint = _control_description(control)
        looks_country = (bool(COUNTRY_HINT.search(hint)) or
                         sum(str(item["value"]).upper() in phonenumbers.SUPPORTED_REGIONS for item in options) >= 2 or
                         sum(bool(re.search(r"\+\d{1,4}", item["text"] or "")) for item in options) >= 2)
        if matches:
            if len(matches) != 1:
                _stop("手机号表单包含多个匹配国家，无法确认区号")
            native_matches.append((control, matches[0]))
        elif looks_country:
            suspicious_native = True
    if len(native_matches) > 1 or (native_matches and suspicious_native):
        _stop("手机号表单包含多个国家选择器，无法确认区号")
    if native_matches:
        control, option = native_matches[0]
        control.select_option(index=option["index"], force=True)
        if control.evaluate("el => el.selectedIndex") != option["index"]:
            _stop("手机号表单未应用所选国家")
        return True
    if suspicious_native:
        _stop("手机号表单的国家列表不包含购买号码所属国家")

    controls = scope.locator('[role="combobox"]:not(input), button[aria-haspopup="listbox"], button[aria-haspopup="dialog"]')
    candidates = []
    for index in range(controls.count()):
        control = controls.nth(index)
        if control.is_visible():
            candidates.append(control)
    if not candidates:
        return False
    if len(candidates) != 1:
        _stop("手机号表单的自定义选择器不明确")
    control = candidates[0]
    description = _control_description(control) + " " + control.inner_text()
    if not COUNTRY_HINT.search(description) and not re.search(r"\+\d{1,4}\b", description):
        _stop("无法确认手机号表单中的自定义国家选择器")
    control.click()
    # Custom popovers may be rendered outside the form. An explicit option role
    # is required; guessing clickable text could select a different UI action.
    options = page.get_by_role("option")
    matches = []
    for index in range(options.count()):
        option = options.nth(index)
        if not option.is_visible() or option.get_attribute("aria-disabled") == "true":
            continue
        data = {"text": option.inner_text(), "value": option.get_attribute("data-value") or option.get_attribute("value"),
                "country": option.get_attribute("data-country"), "code": option.get_attribute("data-country-code")}
        if _option_matches(data, aliases, region):
            matches.append(option)
    if len(matches) != 1:
        _stop("无法唯一识别购买号码对应的国家选项")
    matches[0].click()
    for _ in range(6):
        selected = {"text": control.inner_text(), "value": control.get_attribute("data-value") or control.get_attribute("value"),
                    "country": control.get_attribute("data-country"), "code": control.get_attribute("data-country-code")}
        if _option_matches(selected, aliases, region):
            return True
        page.wait_for_timeout(50)
    _stop("无法核实自定义国家选择器的已选国家")


def fill_phone_number(page: Any, phone: str) -> bool:
    """Fill E.164 or national input and verify available canonical form value."""
    target = first_visible(page, PHONE_INPUTS, timeout_ms=800)
    if target is None:
        return False
    scope = _scope(page, target)
    inputs = scope.locator(",".join(PHONE_INPUTS))
    if sum(inputs.nth(index).is_visible() for index in range(inputs.count())) != 1:
        _stop("手机号表单存在多个号码输入框")
    expected = normalize_phone(phone)
    try:
        number = phonenumbers.parse(expected, None)
    except phonenumbers.NumberParseException:
        _stop("购买号码不是可识别的国际手机号")
    region = (phonenumbers.region_code_for_number(number) or
              phonenumbers.region_code_for_country_code(number.country_code))
    if not region or region == "001":
        _stop("无法确认购买号码所属国家")
    has_country = _select_country(page, scope, number, region)
    if not has_country and (target.get_attribute("autocomplete") == "tel-national" or
                            re.search(r"national|本地号码|国内号码|國內號碼", _control_description(target), re.I)):
        _stop("本地号码输入框缺少可确认的国家区号")
    target.fill(phonenumbers.national_significant_number(number) if has_country else expected)
    canonical = scope.locator('input[type="hidden"][name="phoneNumber"], input[type="hidden"][name="phone_number"]')
    if canonical.count():
        for _ in range(6):
            if all(normalize_phone(canonical.nth(index).input_value()) == expected for index in range(canonical.count())):
                return True
            page.wait_for_timeout(50)
        _stop("手机号表单的国家区号与购买号码不一致")
    return True


def _radio_description(radio: Any) -> str:
    return _control_description(radio) + " " + radio.evaluate("""el => [el.value,
      el.textContent, el.closest('label')?.textContent,
      el.closest('[role="radio"]')?.textContent].filter(Boolean).join(' ')""")


def _radio_label(scope: Any, radio: Any) -> Any | None:
    label = radio.locator("xpath=ancestor::label[1]")
    if not label.count():
        identifier = radio.get_attribute("id")
        if identifier:
            label = scope.locator(f'label[for={json.dumps(identifier)}]')
    if label.count() == 1 and label.is_visible():
        return label
    wrapper = radio.locator('xpath=ancestor::*[@role="radio"][1]')
    if wrapper.count() == 1 and wrapper.is_visible():
        return wrapper
    return None


def ensure_sms_channel(page: Any) -> str:
    """Select and verify SMS when the form offers delivery-channel radios."""
    scope = _scope(page)
    radios = scope.locator('input[type="radio"], [role="radio"]')
    sms = []
    whatsapp = []
    for index in range(radios.count()):
        radio = radios.nth(index)
        native = radio.evaluate("el => el.tagName === 'INPUT'")
        if not native and radio.locator('input[type="radio"]').count():
            continue
        if not native and not radio.is_visible():
            continue
        if native and not radio.is_visible() and _radio_label(scope, radio) is None:
            continue
        description = _radio_description(radio)
        is_sms, is_whatsapp = bool(SMS_NAME.search(description)), bool(WHATSAPP_NAME.search(description))
        if is_sms and is_whatsapp:
            _stop("无法区分短信和 WhatsApp 选项")
        if is_sms:
            sms.append((radio, native))
        if is_whatsapp:
            whatsapp.append((radio, native))
    if not sms and not whatsapp:
        # A segmented button or select without radio semantics cannot be safely
        # verified. Preserve older forms which genuinely have no channel UI.
        unknown = scope.get_by_role("button", name=re.compile(r"^(SMS|短信|简讯|簡訊|WhatsApp)$", re.I))
        if any(unknown.nth(index).is_visible() for index in range(unknown.count())):
            _stop("短信通道控件不支持已选状态校验")
        selects = scope.locator("select")
        for index in range(selects.count()):
            if any(WHATSAPP_NAME.search(item["text"] or "") for item in _native_options(selects.nth(index))):
                _stop("短信通道下拉框不支持已选状态校验")
        return "unspecified"
    if len(sms) != 1:
        _stop("未找到唯一的短信通道选项")
    radio, native = sms[0]
    if native:
        if not radio.is_checked():
            if radio.is_visible():
                radio.check()
            else:
                label = _radio_label(scope, radio)
                if label is None:
                    _stop("无法操作短信通道选项")
                label.click()
    elif radio.get_attribute("aria-checked") != "true":
        radio.click()
    for _ in range(6):
        selected = radio.is_checked() if native else radio.get_attribute("aria-checked") == "true"
        other_selected = any(item.is_checked() if is_native else item.get_attribute("aria-checked") == "true"
                             for item, is_native in whatsapp)
        if selected and not other_selected:
            return "sms"
        page.wait_for_timeout(50)
    _stop("短信通道未成功选中")
