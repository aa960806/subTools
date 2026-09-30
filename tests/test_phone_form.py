"""Local browser fixtures for country and SMS selection; no external requests."""

import pytest
from playwright.sync_api import sync_playwright

from openai_reauth import AuthFlowError, launch_browser
from phone_form import ensure_sms_channel, fill_phone_number


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as playwright:
        instance = launch_browser(playwright, True, None)
        yield instance
        instance.close()


@pytest.fixture
def page(browser):
    context = browser.new_context()
    context.route("**/*", lambda route: route.abort())
    tab = context.new_page()
    yield tab
    context.close()


def native_form(label="电话号码", *, channel=""):
    return f'''<form onsubmit="return false">
      <label>国家<select name="country" onchange="syncPhone()">
        <option value="US">美国 (+1)</option><option value="GH">加纳 (+233)</option>
      </select></label>
      <input type="tel" aria-label="{label}" oninput="syncPhone()">
      <input type="hidden" name="phoneNumber">
      {channel}
      <script>function syncPhone() {{
        document.querySelector('[name=phoneNumber]').value =
          (document.querySelector('select').value === 'GH' ? '+233' : '+1') +
          document.querySelector('input[type=tel]').value;
      }}</script></form>'''


@pytest.mark.parametrize("phone,region,national", [
    ("+12025550123", "US", "2025550123"),
    ("+233241234567", "GH", "241234567"),
])
@pytest.mark.parametrize("label", ["电话号码", "National number", "Phone number"])
def test_country_structure_selects_region_independent_of_input_label(page, phone, region, national, label):
    page.set_content(native_form(label))
    assert fill_phone_number(page, phone)
    assert page.locator("select").input_value() == region
    assert page.locator('input[type="tel"]').input_value() == national
    assert page.locator('[name="phoneNumber"]').input_value() == phone


def test_hidden_native_country_select_still_updates_canonical_number(page):
    page.set_content(native_form().replace('name="country"', 'name="country" style="display:none"'))
    assert fill_phone_number(page, "+233241234567")
    assert page.locator('[name="phoneNumber"]').input_value() == "+233241234567"


def test_custom_country_option_uses_selected_region_not_shared_calling_code(page):
    page.set_content('''<form onsubmit="return false">
      <button role="combobox" aria-label="国家" data-country="US"
        onclick="document.querySelector('[role=listbox]').hidden=false">美国 (+1)</button>
      <div role="listbox" hidden>
        <div role="option" data-value="US" onclick="country(this)">美国 (+1)</div>
        <div role="option" data-value="CA" onclick="country(this)">加拿大 (+1)</div>
        <div role="option" data-value="GH" onclick="country(this)">加纳 (+233)</div>
      </div>
      <input type="tel" aria-label="电话号码" oninput="syncPhone()">
      <input type="hidden" name="phoneNumber">
      <script>
      function country(option) {
        let selector = document.querySelector('[role=combobox]');
        selector.dataset.country = option.dataset.value; selector.textContent = option.textContent;
        option.parentElement.hidden = true; syncPhone();
      }
      function syncPhone() {
        document.querySelector('[name=phoneNumber]').value =
          (document.querySelector('[role=combobox]').dataset.country === 'GH' ? '+233' : '+1') +
          document.querySelector('input[type=tel]').value;
      }</script></form>''')
    assert fill_phone_number(page, "+233241234567")
    assert page.locator('[role="combobox"]').get_attribute("data-country") == "GH"
    assert page.locator('[name="phoneNumber"]').input_value() == "+233241234567"


@pytest.mark.parametrize("html", [
    '<select aria-label="国家"><option value="US">美国 (+1)</option><option value="CA">加拿大 (+1)</option></select><input type="tel">',
    '<select><option value="GH">Ghana (+233)</option></select><select><option value="GH">Ghana (+233)</option></select><input type="tel">',
    '<button role="combobox">Unknown</button><input type="tel">',
    '<input type="tel" autocomplete="tel-national">',
    '<input type="tel"><input type="tel">',
    '<input type="tel"><input type="hidden" name="phoneNumber" value="+12025550123">',
])
def test_ambiguous_or_inconsistent_form_stops_before_submission(page, html):
    page.set_content(f'<form onsubmit="window.sent=true; return false">{html}<button>Continue</button></form>')
    with pytest.raises(AuthFlowError) as error:
        fill_phone_number(page, "+233241234567")
    assert error.value.category == "needs_interaction"
    assert not page.evaluate("Boolean(window.sent)")


def test_custom_country_without_verifiable_selection_stops(page):
    page.set_content('''<form><button type="button" role="combobox" aria-label="Country">+1</button>
      <div role="option" data-value="GH">Ghana (+233)</div><input type="tel"></form>''')
    with pytest.raises(AuthFlowError):
        fill_phone_number(page, "+233241234567")


def test_old_international_form_remains_supported(page):
    page.set_content('<form><input type="tel"></form>')
    assert fill_phone_number(page, "+12025550123")
    assert page.locator("input").input_value() == "+12025550123"
    assert ensure_sms_channel(page) == "unspecified"


def test_native_channel_changes_whatsapp_to_sms_and_verifies_state(page):
    page.set_content(native_form(channel='''
      <label><input type="radio" name="channel" value="sms">短信</label>
      <label><input type="radio" name="channel" value="whatsapp" checked>WhatsApp</label>'''))
    assert ensure_sms_channel(page) == "sms"
    assert page.locator('[value="sms"]').is_checked()
    assert not page.locator('[value="whatsapp"]').is_checked()


def test_hidden_native_channel_uses_visible_label(page):
    page.set_content('''<form><input type="tel">
      <input type="radio" id="sms" name="channel" value="sms" style="display:none"><label for="sms">短信</label>
      <input type="radio" id="wa" name="channel" value="whatsapp" checked style="display:none"><label for="wa">WhatsApp</label>
      </form>''')
    assert ensure_sms_channel(page) == "sms"
    assert page.locator("#sms").is_checked()


def test_custom_radio_changes_whatsapp_to_sms(page):
    page.set_content('''<form><input type="tel"><div role="radiogroup">
      <div role="radio" aria-checked="false" onclick="selectChannel(this)">短信</div>
      <div role="radio" aria-checked="true" onclick="selectChannel(this)">WhatsApp</div>
      </div><script>function selectChannel(el) {
        document.querySelectorAll('[role=radio]').forEach(radio => radio.setAttribute('aria-checked', String(radio===el)));
      }</script></form>''')
    assert ensure_sms_channel(page) == "sms"
    assert page.get_by_role("radio", name="短信").get_attribute("aria-checked") == "true"
    assert page.get_by_role("radio", name="WhatsApp").get_attribute("aria-checked") == "false"


def test_custom_radio_wrapping_hidden_native_input_is_not_counted_twice(page):
    page.set_content('''<form><input type="tel">
      <div role="radio" onclick="this.querySelector('input').checked=true">
        <input type="radio" name="channel" value="0" hidden>短信</div>
      <div role="radio" onclick="this.querySelector('input').checked=true">
        <input type="radio" name="channel" value="1" hidden checked>WhatsApp</div>
      </form>''')
    assert ensure_sms_channel(page) == "sms"
    assert page.locator('[value="0"]').is_checked()
    assert not page.locator('[value="1"]').is_checked()


def test_hidden_old_channel_template_does_not_override_current_controls(page):
    page.set_content('''<form><input type="tel">
      <div hidden><label><input type="radio" value="sms" checked>短信</label></div>
      <button type="button">短信</button><button type="button">WhatsApp</button></form>''')
    with pytest.raises(AuthFlowError):
        ensure_sms_channel(page)


@pytest.mark.parametrize("controls", [
    '<div role="radio" aria-checked="false">SMS</div><div role="radio" aria-checked="true">WhatsApp</div>',
    '<input type="radio" value="whatsapp" checked>',
    '<label><input type="radio" value="sms">SMS</label><label><input type="radio" value="sms">短信</label>',
    '<button type="button">短信</button><button type="button">WhatsApp</button>',
    '<select name="channel"><option>短信</option><option>WhatsApp</option></select>',
])
def test_ambiguous_unselected_or_unknown_channel_stops(page, controls):
    page.set_content(f'<form><input type="tel">{controls}</form>')
    with pytest.raises(AuthFlowError) as error:
        ensure_sms_channel(page)
    assert error.value.category == "needs_interaction"
