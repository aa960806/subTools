"""Offline deployment smoke: encryption, authenticated API and both browser modes."""
import json
import os
import sys
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient
from playwright.sync_api import sync_playwright
from web_app import create_app
from server_storage import Store
from openai_reauth import launch_browser, CallbackServer
from phone_price_data import normalize_price_options


def main():
    with tempfile.TemporaryDirectory(prefix='subtools-smoke-') as root:
        os.environ.pop('SUBTOOLS_SECRET_KEY',None)
        os.environ.pop('SUBTOOLS_SECRET_KEY_FILE',None)
        os.environ.pop('SUBTOOLS_PUBLIC_ORIGIN',None)
        with TestClient(create_app(root,'fixture-only-smoke-password')) as client:
            assert client.get('/healthz').json()=={'ok':True}
            assert client.get('/api/config').status_code==401
            response=client.post('/api/login',json={'password':'fixture-only-smoke-password'})
            assert response.status_code==200
            client.headers['x-csrf-token']=response.json()['csrf']
            assert client.put('/api/config/phone',json={'api_key':'synthetic-key'}).status_code==200
            assert Store(root).read('config/phone.json')['api_key']=='synthetic-key'
            text=json.dumps({'type':'codex','email':'fixture@example.com','access_token':'fixture-access'})
            assert client.post('/api/convert',json={'text':text}).status_code==200
            assert client.post('/api/convert/export',json={'text':text,'target':'cpa'}).status_code==200
        assert 'tkinter' not in sys.modules
        callback=CallbackServer(1455)
        callback.start();callback.stop()
        with sync_playwright() as playwright:
            for headless in (True,False):
                browser=launch_browser(playwright,headless=headless,proxy=None)
                page=browser.new_page()
                page.set_content('<title>SubTools smoke</title><p>offline fixture</p>')
                assert page.title()=='SubTools smoke'
                # A freshly created Xvfb window may not have a compositor frame
                # yet even though set_content has finished loading the DOM.
                page.evaluate('() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))')
                assert page.screenshot(type='jpeg')[:2]==b'\xff\xd8'
                browser.close()
        assert normalize_price_options({'38':{'dr':{'cost':'0.03','count':10}}},{},'dr')[0]['country']=='38'
    print('PASS: portable storage, login/CSRF API, conversions, callback, headless/headful Chromium; no Tk import')


if __name__=='__main__':
    main()
