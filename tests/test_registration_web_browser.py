"""Real web UI for recovery; all registration/auth operations are fixtures."""
import os
import re
from types import SimpleNamespace

import pytest
from playwright.sync_api import expect

from registration_flow import RegistrationResult
from test_registration_flow import registration_text
from test_web_browser import browser, site

pytestmark = pytest.mark.skipif(os.environ.get('SUBTOOLS_BROWSER_TEST') != '1', reason='opt-in local browser smoke')


def test_registration_recovery_and_duplicate_navigation(browser, site, monkeypatch):
    calls = []
    def register(item, **opts):
        calls.append(item.email)
        cp = {'create_confirmed':True, 'stage':'auth_session', 'side_effects':{'profile_submit_attempted':True}}
        opts['on_checkpoint'](cp)
        return RegistrationResult(item.email, category='auth_session_pending', error='账号已创建，OAuth 待完成', checkpoint=cp)
    monkeypatch.setattr('server_engine.PlaywrightRegistrationAdapter', lambda:SimpleNamespace(register=register))
    page = browser.new_page(viewport={'width':1440,'height':1050})
    errors = []
    page.on('pageerror', lambda e:errors.append(str(e)))
    page.goto(site)
    page.locator('#login-password').fill('fixture-password-for-web')
    page.locator('#login-form button').click()
    page.locator('[data-page=register]').click()
    page.locator('[data-field=driver]').select_option('playwright')
    page.locator('[data-field=page_timeout]').fill('75')
    page.locator('#account-input').fill(registration_text('fixture@example.com'))
    page.locator('#start').click()
    expect(page.locator('#result-rows')).to_contain_text('账号：已创建')
    expect(page.locator('#transfer-auth')).to_be_enabled()
    expect(page.locator('#transfer-phone')).to_be_disabled()
    expect(page.locator('#transfer-pool')).to_be_disabled()
    expect(page.locator('#start')).to_be_enabled()
    page.locator('#start').click()
    expect(page.locator('[data-registration-source]')).to_be_visible()
    expect(page.locator('#transfer-auth')).to_be_disabled()
    page.locator('[data-registration-source]').click()
    expect(page.locator('#result-rows')).to_contain_text('OAuth 待完成')
    expect(page.locator('#transfer-auth')).to_be_enabled()
    page.locator('#transfer-auth').click()
    expect(page.locator('#page-title')).to_have_text('批量授权')
    expect(page.locator('#account-input')).to_have_value(re.compile('fixture@example.com'))
    expect(page.locator('#transfer-auth')).to_be_hidden()
    # Transfer only prepared the draft. The existing auth flow starts explicitly.
    page.locator('#start').click()
    expect(page.locator('#stat-success')).to_have_text('1')
    assert calls == ['fixture@example.com'] and not errors
    page.locator('[data-page=register]').click()
    page.set_viewport_size({'width':430,'height':932})
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1')
    page.close()
