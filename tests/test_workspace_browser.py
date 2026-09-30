"""Local HTML regressions for OpenAI's workspace control (no network/login)."""
import sys
import time
from pathlib import Path
from urllib.parse import quote

import pytest
from playwright.sync_api import sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import openai_reauth as core


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as playwright:
        try:
            instance = core.launch_browser(playwright, True, None)
        except RuntimeError:
            pytest.skip("No supported local browser is installed")
        yield instance
        instance.close()


def test_single_disabled_checked_workspace_can_continue(browser):
    page = browser.new_page()
    try:
        page.set_content('''<h1>Select a workspace</h1>
            <label>Pa <span>Personal account</span>
            <input type="radio" name="workspace_id" checked disabled></label>
            <button onclick="document.querySelector('h1').textContent='Complete'">Continue</button>''')
        assert core.maybe_select_workspace(page)
        assert page.get_by_role("heading").inner_text() == "Complete"
    finally:
        page.close()


def test_multiple_organizations_preserve_selected_organization(browser):
    page = browser.new_page()
    try:
        page.set_content('''<h1>Select a workspace</h1>
            <label>Organization A<input id="org-a" type="radio" name="workspace_id"></label>
            <label>Organization B<input id="org-b" type="radio" name="workspace_id" checked></label>
            <button onclick="document.querySelector('h1').textContent='Complete'">Continue</button>''')
        assert core.maybe_select_workspace(page)
        assert page.locator("#org-b").is_checked()
        assert page.get_by_role("heading").inner_text() == "Complete"
    finally:
        page.close()


@pytest.mark.parametrize("personal", ["Personal account", "P Personal workspace", "M个人账户", "个人账号"])
def test_organization_wins_over_selected_personal_and_avatar(browser, personal):
    page = browser.new_page()
    try:
        page.set_content(f'''<h1>选择一个工作空间</h1>
            <label>{personal}<input id="personal" type="radio" name="workspace_id" checked></label>
            <label>LE SE 的工作空间<input id="org" type="radio" name="workspace_id"></label>
            <button onclick="document.body.dataset.submitted='yes'">继续</button>''')
        assert core.maybe_select_workspace(page)
        assert page.locator("#org").is_checked()
        assert not page.locator("#personal").is_checked()
        assert page.locator("body").get_attribute("data-submitted") == "yes"
    finally:
        page.close()


def test_first_available_organization_is_selected(browser):
    page = browser.new_page()
    try:
        page.set_content('''<h1>Choose a workspace</h1>
            <label>Personal account<input type="radio" name="workspace_id" checked></label>
            <label>Unavailable organization<input type="radio" name="workspace_id" disabled></label>
            <label>Organization A<input id="org-a" type="radio" name="workspace_id"></label>
            <label>Organization B<input id="org-b" type="radio" name="workspace_id"></label>
            <button>Continue</button>''')
        assert core.maybe_select_workspace(page)
        assert page.locator("#org-a").is_checked()
        assert not page.locator("#org-b").is_checked()
    finally:
        page.close()


def test_disabled_organization_does_not_silently_fall_back_to_personal(browser):
    page = browser.new_page()
    try:
        page.set_content('''<h1>选择一个工作空间</h1>
            <label>个人账户<input type="radio" name="workspace_id" checked></label>
            <label>公司空间<input type="radio" name="workspace_id" disabled></label>
            <button onclick="document.body.dataset.submitted='yes'">继续</button>''')
        assert not core.maybe_select_workspace(page)
        assert page.locator("body").get_attribute("data-submitted") is None
    finally:
        page.close()


@pytest.mark.parametrize("label", ["M 个人账户", "Company workspace"])
def test_single_fixed_workspace_can_continue_in_chinese(browser, label):
    page = browser.new_page()
    try:
        page.set_content(f'''<h1>选择一个工作空间</h1>
            <label>{label}<input type="radio" name="workspace_id" checked disabled></label>
            <button onclick="document.body.dataset.submitted='yes'">继续</button>''')
        assert core.maybe_select_workspace(page)
        assert page.locator("body").get_attribute("data-submitted") == "yes"
    finally:
        page.close()


def test_hidden_radio_with_external_label_selects_organization(browser):
    page = browser.new_page()
    try:
        page.set_content('''<h1>Select a workspace</h1>
            <input id="personal" type="radio" name="workspace_id" checked style="display:none">
            <label for="personal"><span>P</span> <span>Personal account</span></label>
            <input id="org" type="radio" name="workspace_id" style="display:none">
            <label for="org">Organization A</label>
            <button>Continue</button>''')
        assert core.maybe_select_workspace(page)
        assert page.locator("#org").is_checked()
    finally:
        page.close()


def test_role_radio_selects_organization_and_confirms_aria_checked(browser):
    page = browser.new_page()
    try:
        page.set_content('''<h1>选择一个工作空间</h1>
            <div role="radiogroup">
              <div id="personal" role="radio" aria-checked="true"><span>M</span><span>个人账户</span></div>
              <div id="org" role="radio" aria-checked="false" onclick="
                document.querySelector('#personal').setAttribute('aria-checked','false');
                this.setAttribute('aria-checked','true');">LE SE 的工作空间</div>
            </div>
            <button onclick="document.body.dataset.submitted='yes'">继续</button>''')
        assert core.maybe_select_workspace(page)
        assert page.locator("#org").get_attribute("aria-checked") == "true"
        assert page.locator("body").get_attribute("data-submitted") == "yes"
    finally:
        page.close()


def test_ignored_role_radio_click_does_not_submit_personal(browser):
    page = browser.new_page()
    try:
        page.set_content('''<h1>Choose a workspace</h1>
            <div role="radio" aria-checked="true">Personal account</div>
            <div role="radio" aria-checked="false">Organization A</div>
            <button onclick="document.body.dataset.submitted='yes'">Continue</button>''')
        assert not core.maybe_select_workspace(page)
        assert page.locator("body").get_attribute("data-submitted") is None
    finally:
        page.close()


def test_selected_workspace_waits_for_enabled_continue(browser):
    page = browser.new_page()
    try:
        page.set_content('''<h1>Select a workspace</h1>
            <label>Organization A<input type="radio" checked></label>
            <button disabled>Continue</button>''')
        assert not core.maybe_select_workspace(page)
    finally:
        page.close()


@pytest.mark.parametrize("heading, button", [("Select a workspace", "Continue"), ("选择一个工作空间", "继续")])
def test_delayed_workspace_controls_do_not_require_manual_login(browser, heading, button):
    page = browser.new_page()
    callback = core.CallbackServer(0)
    state = "fixture-state"
    page.expose_function("finishFixture", lambda: callback.set_result(core.CallbackResult(code="fixture-code", state=state)))
    html = '''<h1>HEADING</h1><main></main><script>
      setTimeout(() => {document.querySelector('main').innerHTML =
        '<label>Personal account<input type="radio" name="workspace_id" checked disabled></label>' +
        '<button onclick="finishFixture()">BUTTON</button>';}, 700);
      </script>'''.replace("HEADING", heading).replace("BUTTON", button)
    session = core.OAuthSession(state, "fixture-verifier", core.DEFAULT_REDIRECT_URI, "data:text/html;charset=utf-8," + quote(html))
    account = core.AccountInput("fixture@example.com", "dummy", "JBSWY3DPEHPK3PXP", 1)
    try:
        result = core.login_with_browser(page, account, session, callback, 5, headless=True)
        assert result.code == "fixture-code"
    finally:
        page.close()


def test_waiting_for_totp_does_not_submit_empty_code(browser, monkeypatch):
    page = browser.new_page()
    html = '''<p>Enter your authenticator code or use email</p><input name="code">
      <button onclick="document.body.dataset.submitted='yes'">Continue</button>'''
    session = core.OAuthSession("state", "fixture-verifier", core.DEFAULT_REDIRECT_URI, "data:text/html," + quote(html))
    account = core.AccountInput("fixture@example.com", "dummy", "JBSWY3DPEHPK3PXP", 1)
    monkeypatch.setattr(core, "fill_otp", lambda *_args: False)
    deadline = time.monotonic() + 0.8
    try:
        with pytest.raises(core.AuthFlowError) as caught:
            core.login_with_browser(page, account, session, core.CallbackServer(0), 5, lambda: time.monotonic() > deadline)
        assert caught.value.category == "cancelled"
        assert page.locator("body").get_attribute("data-submitted") is None
    finally:
        page.close()
