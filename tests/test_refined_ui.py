"""Interaction regressions for the presentation layer, with synthetic data."""
import tkinter as tk
from tkinter import ttk

from test_ui_navigation import app
from reauth_ui import secret_field, text_area


def test_placeholder_is_not_account_data_and_page_switch_keeps_edits(app):
    assert app.accounts_text.get('1.0', 'end-1c') == ''
    assert app.account_text() == ''
    app._clear_placeholder()
    app.accounts_text.insert('1.0', 'fixture@example.com----fixture-password')
    app.open_converter()
    assert app.converter.input_text.get('1.0', 'end-1c') == ''
    app.show_authorization()
    assert app.account_text() == 'fixture@example.com----fixture-password'


def test_secret_visibility_does_not_change_or_resave_value(app):
    value = tk.StringVar(app.root, 'synthetic-api-key')
    writes = []
    value.trace_add('write', lambda *_: writes.append(True))
    holder, entry = secret_field(app.root, value)
    toggle = next(w for w in holder.winfo_children() if isinstance(w, ttk.Button))
    toggle.invoke()
    assert entry.cget('show') == ''
    toggle.invoke()
    assert entry.cget('show') == '•'
    assert value.get() == 'synthetic-api-key'
    assert writes == []
    holder.destroy()


def test_empty_table_and_highlight_preserve_conversion_content(app):
    app.open_converter()
    page = app.converter
    assert not page.account_tree.cget('show')
    page.set_input('{"type":"codex","email":"fixture@example.com",'
                   '"access_token":"synthetic-access","refresh_token":"synthetic-refresh"}')
    assert page.preview()
    assert page.account_tree.get_children()
    assert 'headings' in tuple(map(str, page.account_tree.cget('show')))
    assert page.preview_text.tag_ranges('json_key')
    assert 'synthetic-access' not in page.preview_text.get('1.0', 'end-1c')
    page.clear_input()
    assert not page.account_tree.get_children()
    assert not page.account_tree.cget('show')
    assert page.input_value() == ''


def test_scrollbars_follow_overflow_without_changing_text(app):
    root = app.root
    root.deiconify()
    holder, text = text_area(root, height=3)
    holder.place(x=210, y=160, width=250, height=100)
    root.update_idletasks()
    assert not text._horizontal_scrollbar.winfo_ismapped()
    text.insert('1.0', 'x' * 400)
    root.update_idletasks()
    assert text._horizontal_scrollbar.winfo_ismapped()
    assert text.get('1.0', 'end-1c') == 'x' * 400
    text.delete('1.0', tk.END)
    root.update_idletasks()
    assert not text._horizontal_scrollbar.winfo_ismapped()
    holder.destroy()


def test_custom_button_mouse_binding_still_invokes_and_disabled_blocks(app):
    root = app.root
    root.deiconify()
    calls = []
    button = ttk.Button(root, text='Fixture', style='Primary.TButton', command=lambda: calls.append(True))
    button.place(x=210, y=160)
    root.update_idletasks()
    for disabled in (False, True):
        button.configure(state=tk.DISABLED if disabled else tk.NORMAL)
        button.event_generate('<Enter>', x=20, y=15)
        button.event_generate('<ButtonPress-1>', x=20, y=15)
        button.event_generate('<ButtonRelease-1>', x=20, y=15)
    assert calls == [True]
    button.destroy()
