"""Opt-in real Chromium UI checks against a local fixture service."""
import os
import socket
import threading
import time
from pathlib import Path

import pytest
import uvicorn
from cryptography.fernet import Fernet
from playwright.sync_api import sync_playwright, expect

from browser_bridge import BrowserBridge, StopEvent, bind, attach, detach
from web_app import create_app
from test_web import fake_login

pytestmark=pytest.mark.skipif(os.environ.get('SUBTOOLS_BROWSER_TEST')!='1',reason='opt-in local browser smoke')


@pytest.fixture
def browser():
    with sync_playwright() as p:
        channel=os.environ.get('SUBTOOLS_TEST_BROWSER_CHANNEL')
        b=p.chromium.launch(headless=True,**({'channel':channel} if channel else {}))
        yield b
        b.close()


@pytest.fixture
def site(tmp_path, monkeypatch):
    monkeypatch.setenv('SUBTOOLS_SECRET_KEY',Fernet.generate_key().decode())
    monkeypatch.delenv('SUBTOOLS_SECRET_KEY_FILE',raising=False)
    monkeypatch.delenv('SUBTOOLS_PUBLIC_ORIGIN',raising=False)
    monkeypatch.setenv('SUBTOOLS_DATA_DIR',str(tmp_path))
    monkeypatch.setattr('server_engine.run_batch_reauth',fake_login)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        port=sock.getsockname()[1]
    server=uvicorn.Server(uvicorn.Config(create_app(tmp_path,'fixture-password-for-web'),host='127.0.0.1',port=port,log_level='error'))
    thread=threading.Thread(target=server.run,daemon=True)
    thread.start()
    for _ in range(100):
        if server.started: break
        time.sleep(.05)
    assert server.started
    yield f'http://127.0.0.1:{port}'
    server.should_exit=True
    thread.join(5)


def test_full_web_navigation_and_fixture_workflow(browser,site,tmp_path):
    page=browser.new_page(viewport={'width':1440,'height':1050})
    errors=[]
    page.on('pageerror',lambda e: errors.append(str(e)))
    page.on('dialog',lambda dialog: dialog.accept())
    page.goto(site)
    page.locator('#login-password').fill('fixture-password-for-web')
    page.locator('#login-form button').click()
    page.locator('#app').wait_for(state='visible')
    page.locator('[data-field=timeout]').fill('240')
    page.locator('#account-input').fill('fixture@example.com----fixture-pass')
    page.locator('[data-page=phone]').click()
    page.locator('#fallback-choice').select_option('4')
    page.locator('#fallback-add').click()
    assert '菲律宾' in page.locator('#fallback-list').inner_text()
    page.locator('[data-page=auth]').click()
    assert page.locator('[data-field=timeout]').input_value()=='240'
    assert 'fixture@example.com' in page.locator('#account-input').input_value()
    page.locator('#recognize').click()
    page.locator('#start').click()
    page.locator('#stat-success').filter(has_text='1').wait_for(timeout=15000)
    page.locator('#transfer-pool').click()
    expect(page.locator('#page-title')).to_have_text('推送到池')
    assert 'fixture-access' in page.locator('#account-input').input_value()
    for tab in ('groups','models','connection'):
        page.locator(f'[data-settings-tab={tab}]').click()
        assert page.locator(f'[data-settings-panel={tab}]').is_visible()
    page.locator('[data-page=convert]').click()
    page.locator('#convert-input').fill('{"type":"codex","email":"fixture@example.com","account_id":"space-fixture","access_token":"fixture-access","refresh_token":"fixture-refresh"}')
    page.locator('#convert-preview-btn').click()
    page.locator('#convert-count').filter(has_text='1 个账号').wait_for(timeout=15000)
    assert 'sub2api-data' in page.locator('#convert-preview').inner_text()
    with page.expect_download() as download:
        page.locator('#convert-save').click()
    assert download.value.suggested_filename=='accounts.json'
    page.locator('[data-page=history]').click()
    page.locator('[data-history]').first.wait_for()
    page.locator('[data-history]').first.click()
    expect(page.locator('#page-title')).to_have_text('批量授权')
    output=Path('.browser-smoke');output.mkdir(exist_ok=True)
    page.screenshot(path=str(output/'desktop.png'),full_page=True)
    page.set_viewport_size({'width':430,'height':932})
    page.screenshot(path=str(output/'mobile.png'),full_page=True)
    assert page.evaluate('document.documentElement.scrollWidth<=innerWidth+1')
    assert not errors
    page.locator('#logout').click(force=True)
    page.locator('#login').wait_for(state='visible')
    assert page.locator('#account-input').input_value()==''
    page.close()


def test_browser_handoff_commands_and_cancellation(browser):
    page=browser.new_page(viewport={'width':1280,'height':900})
    page.set_content('<input style="position:absolute;top:20px;left:20px;width:400px;height:40px"><button onclick="document.title=\'clicked\'" style="position:absolute;top:90px;left:20px">submit</button>')
    bridge=BrowserBridge();bridge.enabled=True
    bind(bridge);attach(page)
    stop=StopEvent(bridge);stop.owner=threading.get_ident()
    bridge.commands.put({'action':'click','x':60,'y':40})
    bridge.commands.put({'action':'text','text':'fixture-manual-input'})
    assert not stop.is_set()
    assert page.locator('input').input_value()=='fixture-manual-input'
    assert bridge.frame[:2]==b'\xff\xd8'
    bridge.commands.put({'action':'click','x':50,'y':100})
    stop.is_set()
    assert page.title()=='clicked'
    stop.set();assert stop.is_set()
    detach();bind(None);page.close()
    assert bridge.page is None and bridge.frame is None


def test_import_selection_archive_and_single_download(browser, site, monkeypatch):
    import progress_events
    def observed_login(items, **options):
        for stage in ('page', 'email', 'password', 'otp', 'workspace', 'token'):
            progress_events.emit(items[0].email, stage)
        return fake_login(items, **options)
    monkeypatch.setattr('server_engine.run_batch_reauth', observed_login)
    page = browser.new_page(viewport={'width':1440, 'height':1000})
    errors = []
    page.on('pageerror', lambda e: errors.append(str(e)))
    page.on('dialog', lambda d: d.accept())
    page.goto(site)
    page.locator('#login-password').fill('fixture-password-for-web')
    page.locator('#login-form button').click()
    page.locator('#app').wait_for(state='visible')
    page.locator('#account-input').fill('fixture@example.com----fixture-pass\nbroken-line----private-fixture')
    page.locator('#recognize').click()
    expect(page.locator('[data-row="1"]')).to_be_disabled()
    expect(page.locator('[data-row="0"]')).to_be_checked()
    assert 'private-fixture' not in page.locator('#result-rows').inner_text()
    page.locator('#start').click()
    expect(page.locator('#stat-success')).to_have_text('1', timeout=15000)
    expect(page.locator('.step-chip')).to_have_count(6)
    expect(page.locator('.step-chip.active')).to_have_count(0)
    page.screenshot(path='.browser-smoke/stages-desktop.png', full_page=True)
    page.locator('[data-row="0"]').check()
    with page.expect_download() as download:
        page.locator('#export-cpa').click()
    assert download.value.suggested_filename == 'fixture@example.com.json'
    page.locator('[data-page=history]').click()
    page.locator('[data-archive]').first.click()
    expect(page.locator('[data-history]')).to_have_count(0)
    page.locator('#history-filter').select_option('archived')
    expect(page.locator('[data-history]')).to_have_count(1)
    page.locator('[data-archive]').click()
    expect(page.locator('[data-history]')).to_have_count(0)
    page.locator('#history-filter').select_option('current')
    expect(page.locator('[data-history]')).to_have_count(1)
    page.locator('[data-history]').click()
    expect(page.locator('#stat-success')).to_have_text('1')
    page.set_viewport_size({'width':430, 'height':932})
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1')
    assert not errors
    page.close()
