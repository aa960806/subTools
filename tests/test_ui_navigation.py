"""Keep categorized navigation and critical controls usable at desktop scales."""
import threading
import tkinter as tk
from unittest.mock import patch

import pytest
import openai_reauth_gui as gui
import pool_gui


@pytest.fixture
def app(tmp_path, request):
    with patch.object(gui, 'AUTH_CONFIG_PATH', tmp_path / 'auth.json'), \
         patch.object(gui, 'PHONE_CONFIG_PATH', tmp_path / 'phone.json'), \
         patch.object(pool_gui, 'CONFIG_PATH', tmp_path / 'pool.json'), \
         patch.object(gui, '_TASK_LOCK', threading.Lock()):
        root = tk.Tk()
        # Tk scaling affects font creation. Set it before building widgets so
        # this models launching the app at each Windows display scale.
        root.tk.call('tk', 'scaling', 96 * getattr(request, 'param', 100) / 100 / 72)
        root.attributes('-alpha', 0)
        root.withdraw()
        app = gui.ReauthApp(root)
        yield app
        if app.phone_page is not None:
            app.phone_page.dispose()
        if app.pool_page is not None:
            app.pool_page.dispose()
        for handle in root.tk.splitlist(root.tk.call('after', 'info')):
            root.after_cancel(handle)
        root.destroy()


@pytest.mark.parametrize('app', [100, 125, 150], indirect=True)
def test_navigation_and_active_controls_fit_small_window(app):
    root = app.root
    root.geometry('980x740')
    root.deiconify()
    for key in ('auth', 'phone', 'convert', 'pool'):
        app.navigation.buttons[key].invoke()
        root.update_idletasks()
        assert app.navigation.active == key
        controls = list(app.navigation.buttons.values())
        if key == 'auth': controls += [app.start_btn, app.accounts_text, app.log_text]
        if key == 'phone': controls += [app.phone_page.start_btn, app.phone_page.input_text, app.phone_page.show_browser_check]
        if key == 'convert': controls += [app.converter.input_text, app.converter.preview_text]
        if key == 'pool': controls += [app.pool_page.input_text, app.pool_page.start_btn, app.pool_page.retry_btn]
        for widget in controls:
            assert widget.winfo_ismapped(), (key, widget)
            assert widget.winfo_height() > 10, (key, widget)
            assert widget.winfo_rootx() + widget.winfo_width() <= root.winfo_rootx() + root.winfo_width(), (key, widget)
            assert widget.winfo_rooty() + widget.winfo_height() <= root.winfo_rooty() + root.winfo_height(), (key, widget)


def test_tabs_preserve_inputs_and_bad_scale_does_not_take_task_lock(app):
    app.open_phone()
    page = app.phone_page
    page.set_input('fixture@example.com----fixture-password')
    page.api_key_var.set('synthetic-key')
    page.network_mode_var.set('直连')
    page.human_scale_var.set('nan')
    app.open_converter()
    app.converter.set_input('{"fixture": true}')
    app.open_phone()
    assert page.input_value() == 'fixture@example.com----fixture-password'
    assert app.converter.input_value() == '{"fixture": true}'
    with patch.object(gui.messagebox, 'showerror') as error, patch.object(gui.threading.Thread, 'start') as start:
        page.start()
    error.assert_called_once()
    start.assert_not_called()
    assert not gui._TASK_LOCK.locked()
