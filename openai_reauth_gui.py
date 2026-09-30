#!/usr/bin/env python3
"""Windowed OpenAI batch re-auth tool."""

from __future__ import annotations

import json
import base64
import ctypes
import os
from ctypes import wintypes
import queue
import sys
import threading
import traceback
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from urllib.parse import unquote, urlsplit
from tkinter import filedialog, messagebox, ttk
import tkinter as tk

sys.path.insert(0, str(Path(__file__).resolve().parent))

from openai_reauth import (  # noqa: E402
    Accounts,
    TOOL_DIR,
    build_cpa_payload,
    build_export_payload,
    conversion_warnings,
    load_accounts,
    redact_diagnostic,
    run_batch_reauth,
    set_log_callback,
    write_cpa_files,
    write_export_file,
)
from phone_flow import parse_phone_jobs, run_batch_phone_verify
from phone_pool import SmsbowerSettings
from phone_network import NETWORK_MODES, NETWORK_HINTS, resolve_phone_proxy, network_description
from phone_smsbower import SmsBowerClient, SmsBowerError, country_dropdown_values, country_label, parse_country_choice
from phone_pricing import price_summary
from reauth_proxy import normalize_proxy
from reauth_conversion import load_conversion_files, parse_conversion_text as parse_accounts_from_text
from reauth_formats import account_conversion_status
from pool_gui import PoolPushWindow
from task_views import TableFilter
from task_history import HistoryView, read_history_json
from phone_price_catalog import PriceCatalogView

from reauth_ui import COLORS, setup_theme, card, text_area, brand_mark, attach_window_icon, AppNavigation, scroll_settings, page_header, SegmentedNotebook, AutoScrollbar, DataTable, secret_field, json_highlight, set_hint, hide_hint, present_running
from human_pacing import HumanSettings, validate_scale

APP_TITLE = "OpenAI 批量重新授权"
AUTH_CONFIG_PATH = TOOL_DIR / "auth_settings.json"
PLACEHOLDER = "粘贴账号，或从文件导入。\n\n邮箱----密码----2FA密钥（选填）"


def masked_preview(value):
    """Mask secrets in the read-only preview without modifying export data."""
    if isinstance(value, dict):
        return {
            key: ("[已隐藏]" if any(word in str(key).lower() for word in
                                    ("token", "password", "secret", "authorization")) and item else masked_preview(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [masked_preview(item) for item in value]
    return value


class ReauthApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(APP_TITLE)
        self.root.minsize(980, 740)
        self.root.configure(bg=COLORS["bg"])
        self._center_window(1280, 860)

        self.event_queue: queue.Queue[tuple] = queue.Queue()
        self.worker: threading.Thread | None = None
        self.stop_flag = threading.Event()
        self.last_payload_accounts: list[dict] = []
        self.last_failed: list[str] = []
        self.retry_accounts = []
        self._active_accounts = []
        self._batch_failed_accounts = []
        self._batch_done = 0
        self._batch_successes = 0
        self._auth_rows = {}
        self._retry_preserved = []
        self.closing = False
        self._after_ids: set[str] = set()
        self.running = False
        self._task_lock_held = False
        self._auth_log_secrets: tuple[str, ...] = ()
        self.converter = None
        self.phone_page = None
        self.pool_page = None

        self._setup_style()
        self._build()
        self._load_auth_settings()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self._schedule(80, self._drain_events)
        self._schedule(200, self._bring_to_front)
        self._append_log("把账号粘贴到上方，然后点「开始授权」。默认静默运行，不弹出网页，进度看下方日志。")

    def _setup_style(self) -> None:
        setup_theme(self.root)
        attach_window_icon(self.root)

    def _center_window(self, width: int, height: int) -> None:
        self.root.update_idletasks()
        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()
        width, height = min(width, screen_w - 60), min(height, screen_h - 90)
        self.root.minsize(min(980, width), min(740, height))
        x = max((screen_w - width) // 2, 0)
        y = max((screen_h - height) // 2, 0)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def _bring_to_front(self) -> None:
        try:
            self.root.lift()
            self.root.attributes("-topmost", True)
            self._schedule(600, lambda: self.root.attributes("-topmost", False))
            self.root.focus_force()
        except tk.TclError:
            pass

    def _schedule(self, delay: int, callback) -> None:
        """Called only by the Tk thread; workers communicate through event_queue."""
        def invoke():
            self._after_ids.discard(handle)
            callback()

        handle = self.root.after(delay, invoke)
        self._after_ids.add(handle)

    def _make_text(self, parent, *, height, bg=None, fg=None, wrap=tk.NONE,
                   state=tk.NORMAL):
        holder, text = text_area(parent, height=height, bg=bg, fg=fg, wrap=wrap, state=state)
        text.bind("<Control-a>", self._select_all)
        text.bind("<Control-A>", self._select_all)
        return holder, text

    @staticmethod
    def _select_all(event: tk.Event) -> str:
        event.widget.tag_add("sel", "1.0", "end-1c")
        return "break"

    def _build(self) -> None:
        self.navigation = AppNavigation(self.root, {
            "auth": self.show_authorization, "phone": self.open_phone,
            "convert": self.open_converter, "pool": self.open_pool,
        })
        self.navigation.pack(side=tk.LEFT, fill=tk.Y)
        self.root._reauth_navigation = self.navigation
        outer = ttk.Frame(self.root, style="App.TFrame", padding=(24, 20, 24, 16))
        self.main_view = outer
        outer.pack(fill=tk.BOTH, expand=True)
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(1, weight=2, minsize=210)
        outer.rowconfigure(3, weight=3, minsize=210)

        outer.columnconfigure(1, minsize=286)
        self.auth_layout = outer
        header = page_header(outer, "批量授权", "重新获取账号凭据，成功结果自动保存。", "账号处理")
        header.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 16))

        workspace = ttk.Frame(outer, style="App.TFrame")
        workspace.grid(row=1, column=0, sticky="nsew", padx=(0, 14))
        workspace.columnconfigure(0, weight=1)
        workspace.rowconfigure(0, weight=1)

        inputs = card(workspace, padding=12)
        inputs.grid(row=0, column=0, sticky="nsew")
        inputs.columnconfigure(0, weight=1)
        inputs.rowconfigure(2, weight=1)
        input_header = ttk.Frame(inputs, style="Card.TFrame")
        input_header.grid(row=0, column=0, sticky="ew")
        ttk.Label(input_header, text="账号列表", style="Section.TLabel").pack(side=tk.LEFT)
        self.input_count_var = tk.StringVar(value="0 个账号")
        ttk.Label(input_header, textvariable=self.input_count_var, style="Badge.TLabel", padding=(8, 3)).pack(side=tk.LEFT, padx=10)
        ttk.Button(input_header, text="↥ 导入文件", style="Ghost.TButton", command=self.load_file).pack(side=tk.RIGHT)
        ttk.Button(input_header, text="× 清空", style="Ghost.TButton", command=self.clear_accounts).pack(side=tk.RIGHT, padx=(0, 4))
        ttk.Label(inputs, text="账号行 / sub2 / CPA · 有 refresh token 时优先刷新", style="Hint.TLabel").grid(row=1, column=0, sticky="w", pady=(8, 12))
        holder, self.accounts_text = self._make_text(inputs, height=7)
        holder.grid(row=2, column=0, sticky="nsew")
        self._set_placeholder()
        self.accounts_text.bind("<FocusIn>", self._clear_placeholder, add="+")
        self.accounts_text.bind("<FocusOut>", self._restore_placeholder, add="+")
        self.accounts_text.bind("<<Modified>>", self._update_input_count)
        self.accounts_text.edit_modified(False)
        actions = ttk.Frame(inputs, style="Card.TFrame")
        actions.grid(row=4, column=0, sticky="ew", pady=(12, 0))
        self.start_btn = ttk.Button(actions, text="开始授权", style="Primary.TButton", command=self.start)
        self.start_btn.pack(side=tk.LEFT)
        self.stop_btn = ttk.Button(actions, text="停止", style="Danger.TButton", command=self.stop, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=8)

        options_card = card(outer, padding=0)
        options_card.grid(row=1, column=1, rowspan=3, sticky="nsew")
        options_card.columnconfigure(0, weight=1)
        options_card.rowconfigure(0, weight=1)
        self.auth_settings_tabs = SegmentedNotebook(options_card)
        self.auth_settings_tabs.grid(row=0, column=0, sticky="nsew")
        tab, options, self.auth_options_canvas = scroll_settings(self.auth_settings_tabs, width=254)
        self.auth_settings_tabs.add(tab, text="网络")
        tab, runtime_options, self.auth_runtime_canvas = scroll_settings(self.auth_settings_tabs, width=254)
        self.auth_settings_tabs.add(tab, text="运行")
        tab, export_options, _ = scroll_settings(self.auth_settings_tabs, width=254)
        self.auth_settings_tabs.add(tab, text="导出")
        ttk.Label(options, text="网络与代理", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        self.use_proxy_var = tk.BooleanVar(value=False)
        self.network_mode_var = tk.StringVar(value=NETWORK_MODES["direct"])
        ttk.Combobox(options, textvariable=self.network_mode_var, values=tuple(NETWORK_MODES.values()), state="readonly").grid(row=1, column=0, sticky="ew", pady=(12, 6))
        self.use_proxy_var.trace_add("write", self._legacy_proxy_toggle)
        self.network_mode_var.trace_add("write", self._network_mode_changed)
        proxy_protocol = ttk.Frame(options, style="Card.TFrame")
        proxy_protocol.grid(row=2, column=0, sticky="ew", pady=(0, 6))
        ttk.Label(proxy_protocol, text="代理协议", style="Card.TLabel").pack(side=tk.LEFT)
        self.proxy_scheme_var = tk.StringVar(value="HTTP")
        ttk.Combobox(proxy_protocol, textvariable=self.proxy_scheme_var, values=("HTTP", "HTTPS", "SOCKS5"), state="readonly", width=9).pack(side=tk.RIGHT)
        self.proxy_var = tk.StringVar()
        self.proxy_entry = ttk.Entry(options, textvariable=self.proxy_var, width=27, show="•")
        self.proxy_entry.grid(row=3, column=0, sticky="ew")
        self.proxy_var.trace_add("write", self._proxy_edited)
        ttk.Label(options, text="登录、邮箱验证码、刷新与换票使用同一网络。系统模式在开始时读取 Windows 静态代理。自定义支持 IP:端口:用户名:密码或代理 URL。", style="Hint.TLabel", wraplength=250).grid(row=4, column=0, sticky="w", pady=(6, 0))
        self.remember_proxy_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options, text="在本机加密记住代理", variable=self.remember_proxy_var, command=self._save_auth_settings).grid(row=5, column=0, sticky="w", pady=(8, 0))
        options = runtime_options
        ttk.Label(options, text="运行设置", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        timeout_row = ttk.Frame(options, style="Card.TFrame")
        timeout_row.grid(row=6, column=0, sticky="ew", pady=(12, 0))
        ttk.Label(timeout_row, text="单账号超时", style="Card.TLabel").pack(side=tk.LEFT)
        ttk.Label(timeout_row, text="秒", style="Hint.TLabel").pack(side=tk.RIGHT)
        self.timeout_var = tk.StringVar(value="180")
        ttk.Entry(timeout_row, textvariable=self.timeout_var, width=6, justify=tk.CENTER).pack(side=tk.RIGHT, padx=8)
        self.show_browser_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options, text="显示浏览器", variable=self.show_browser_var).grid(row=7, column=0, sticky="w", pady=(8, 0))
        self.human_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options, text="步骤等待（可随时停止）", variable=self.human_var).grid(row=8, column=0, sticky="w", pady=(4, 0))
        pace_row = ttk.Frame(options, style="Card.TFrame")
        pace_row.grid(row=9, column=0, sticky="ew", pady=(6, 0))
        ttk.Label(pace_row, text="等待倍数", style="Card.TLabel").pack(side=tk.LEFT)
        self.human_scale_var = tk.StringVar(value="1.0")
        ttk.Entry(pace_row, textvariable=self.human_scale_var, width=6, justify=tk.CENTER).pack(side=tk.RIGHT)
        ttk.Label(options, text="等待倍数 0.1–10。单账号超时包含所有等待；停止后不再发起新提交。", style="Hint.TLabel", wraplength=250).grid(row=10, column=0, sticky="w", pady=(6, 0))
        options = export_options
        ttk.Label(options, text="结果导出", style="Section.TLabel").grid(row=12, column=0, sticky="w", pady=(0, 8))
        formats = ttk.Frame(options, style="Card.TFrame")
        formats.grid(row=13, column=0, sticky="ew")
        formats.columnconfigure((0, 1), weight=1, uniform="formats")
        self.export_format_var = tk.StringVar(value="sub2")
        ttk.Radiobutton(formats, text="sub2", variable=self.export_format_var, value="sub2", style="Format.TRadiobutton").grid(row=0, column=0, sticky="ew", padx=(0, 4))
        ttk.Radiobutton(formats, text="CPA", variable=self.export_format_var, value="cpa", style="Format.TRadiobutton").grid(row=0, column=1, sticky="ew", padx=(4, 0))
        self.format_hint_var = tk.StringVar(value="合并为一个 JSON，导入 sub2api")
        ttk.Label(options, textvariable=self.format_hint_var, style="Hint.TLabel").grid(row=14, column=0, sticky="w", pady=(8, 0))
        self.export_format_var.trace_add("write", lambda *_: self.format_hint_var.set("按邮箱拆分，每个账号一个 JSON" if self.current_export_format() == "cpa" else "合并为一个 JSON，导入 sub2api"))

        results = ttk.Frame(outer, style="App.TFrame")
        results.grid(row=2, column=0, sticky="ew", padx=(0, 14), pady=12)
        self.success_count_var = tk.StringVar(value="0")
        self.failed_count_var = tk.StringVar(value="0")
        self.pending_count_var = tk.StringVar(value="0")
        results.columnconfigure((0, 1, 2), weight=1, uniform="metrics")
        for i, (label, variable, color) in enumerate((("成功", self.success_count_var, COLORS["success"]), ("失败", self.failed_count_var, COLORS["error"]), ("待处理", self.pending_count_var, COLORS["muted"]))):
            counter = card(results, padding=(12, 8))
            counter.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 6, 0 if i == 2 else 6))
            ttk.Label(counter, textvariable=variable, style="Metric.TLabel", foreground=color).pack(side=tk.LEFT)
            ttk.Label(counter, text=label, style="Hint.TLabel").pack(side=tk.RIGHT)

        activity = card(outer, padding=12)
        activity.grid(row=3, column=0, sticky="nsew", padx=(0, 14))
        activity.columnconfigure(0, weight=1)
        activity.rowconfigure(3, weight=1)
        activity_head = ttk.Frame(activity, style="Card.TFrame")
        activity_head.grid(row=0, column=0, sticky="ew")
        ttk.Label(activity_head, text="运行记录", style="Section.TLabel").pack(side=tk.LEFT)
        self.save_btn = ttk.Button(activity_head, text="导出结果", style="Secondary.TButton", command=self.save_json, state=tk.DISABLED)
        self.save_btn.pack(side=tk.RIGHT)
        self.push_results_btn = ttk.Button(activity_head, text="推送成功结果", style="Ghost.TButton",
                                           command=self.push_success_results, state=tk.DISABLED)
        self.push_results_btn.pack(side=tk.RIGHT, padx=8)
        self.retry_btn = ttk.Button(activity_head, text="重试失败", style="Ghost.TButton", command=self.retry_failed, state=tk.DISABLED)
        self.retry_btn.pack(side=tk.RIGHT, padx=8)
        self.progress = ttk.Progressbar(activity, mode="determinate", style="Slim.Horizontal.TProgressbar")
        self.progress.grid(row=1, column=0, sticky="ew", pady=(8, 7))
        self.status_var = tk.StringVar(value="准备就绪，等待开始")
        self.status_label = ttk.Label(activity, textvariable=self.status_var, style="Hint.TLabel", wraplength=850)
        self.status_label.grid(row=2, column=0, sticky="ew", pady=(0, 8))
        activity.bind("<Configure>", lambda event: self.status_label.configure(wraplength=max(event.width - 40, 200)))
        self.activity_tabs = SegmentedNotebook(activity)
        self.activity_tabs.grid(row=3, column=0, sticky="nsew")
        log_holder, self.log_text = self._make_text(self.activity_tabs, height=5, bg=COLORS["log"], fg=COLORS["log_text"], wrap=tk.WORD, state=tk.DISABLED)
        self.activity_tabs.add(log_holder, text="日志")
        account_results = card(self.activity_tabs, padding=6)
        self.activity_tabs.add(account_results, text="账号结果")
        self.auth_tree = DataTable(account_results, columns=("email", "status", "message"), show="headings", height=3, empty_text="开始任务后可筛选结果，选中账号重试")
        for key, title, width in (("email", "账号", 210), ("status", "状态", 120), ("message", "结果", 290)):
            self.auth_tree.heading(key, text=title)
            self.auth_tree.column(key, width=width, minwidth=65)
        self.auth_filter = TableFilter(account_results, self.auth_tree)
        self.auth_filter.frame.pack(fill=tk.X, pady=(0, 6))
        ttk.Button(account_results, text="重试选中账号", command=self.retry_selected, style="Ghost.TButton").pack(side=tk.BOTTOM, anchor="w")
        sy = AutoScrollbar(account_results, orient=tk.VERTICAL, command=self.auth_tree.yview, content_widget=self.auth_tree)
        sy.pack(side=tk.RIGHT, fill=tk.Y)
        self.auth_tree.configure(yscrollcommand=sy.set)
        self.auth_tree.pack(fill=tk.BOTH, expand=True)
        self.history_view = HistoryView(self.activity_tabs, TOOL_DIR / "recovery", self._open_history_record)
        self.activity_tabs.add(self.history_view.frame, text="任务历史")
        self.log_text.tag_configure("success", foreground=COLORS["success"])
        self.log_text.tag_configure("warning", foreground=COLORS["warning"])
        self.log_text.tag_configure("error", foreground=COLORS["error"])
        footer = ttk.Frame(outer, style="App.TFrame")
        footer.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(12, 0))
        ttk.Label(footer, text="OAuth  /  PKCE", style="Footer.TLabel").pack(side=tk.LEFT)
        ttk.Button(footer, text="打开结果目录", style="Page.Ghost.TButton", command=self.open_recovery).pack(side=tk.RIGHT)

    def _proxy_edited(self, *_args) -> None:
        if not getattr(self, "_loading_auth_settings", False):
            self.use_proxy_var.set(bool(self.proxy_var.get().strip()))

    def _legacy_proxy_toggle(self, *_args):
        if not getattr(self, "_syncing_network", False):
            self.network_mode_var.set(NETWORK_MODES["custom" if self.use_proxy_var.get() else "direct"])

    def _network_mode_changed(self, *_args):
        self._syncing_network = True
        try:
            self.use_proxy_var.set(self.network_mode_var.get() == NETWORK_MODES["custom"])
        finally:
            self._syncing_network = False

    def current_proxy(self) -> str | None:
        mode = next((key for key, label in NETWORK_MODES.items() if label == self.network_mode_var.get()), "")
        return resolve_phone_proxy(mode, self.proxy_var.get(), self.proxy_scheme_var.get().lower()) or None

    def _load_auth_settings(self) -> None:
        try:
            data = json.loads(AUTH_CONFIG_PATH.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return
        if not isinstance(data, dict):
            return
        stored = str(data.get("proxy") or "")
        remember = bool(data.get("remember_proxy", True))
        self._loading_auth_settings = True
        try:
            proxy = _unprotect_setting(stored) if remember else ""
            self.proxy_var.set(proxy)
            self.proxy_scheme_var.set(str(data.get("proxy_scheme") or "HTTP").upper())
            self.use_proxy_var.set(bool(data.get("use_proxy", bool(proxy))) and bool(proxy))
            mode = data.get("network_mode", "custom" if self.use_proxy_var.get() else "direct")
            self.network_mode_var.set(NETWORK_MODES.get(mode, NETWORK_MODES["direct"]))
            self.remember_proxy_var.set(remember)
            self.human_var.set(data.get("human_pacing", True) is True)
            self.human_scale_var.set(str(data.get("human_scale", "1.0")))
        finally:
            self._loading_auth_settings = False
        if stored and not proxy and remember:
            self._append_log("已保存的代理无法解密，请重新填写后启用。")
        if stored and (not remember or not stored.startswith("dpapi:")):
            self._save_auth_settings()

    def _save_auth_settings(self) -> None:
        remember = self.remember_proxy_var.get()
        proxy = self.proxy_var.get().strip()
        encrypted = _protect_setting(proxy) if remember else ""
        payload = {
            "proxy": encrypted,
            "proxy_scheme": self.proxy_scheme_var.get().lower(),
            "use_proxy": self.use_proxy_var.get(),
            "network_mode": next((key for key, label in NETWORK_MODES.items() if label == self.network_mode_var.get()), "direct"),
            "remember_proxy": remember,
            "human_pacing": self.human_var.get(),
            "human_scale": self.human_scale_var.get().strip() or "1.0",
        }
        if remember and proxy and not encrypted:
            self._append_log("代理加密保存不可用，本次仅在内存中使用；下次启动需重新填写。")
        try:
            AUTH_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
            temporary = AUTH_CONFIG_PATH.with_suffix(AUTH_CONFIG_PATH.suffix + ".tmp")
            temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            temporary.replace(AUTH_CONFIG_PATH)
        except (OSError, UnicodeError) as exc:
            self._append_log(f"授权设置保存失败：{type(exc).__name__}")

    def _update_input_count(self, _event=None) -> None:
        count = sum(bool(line.strip()) and not line.lstrip().startswith("#") for line in self.account_text().splitlines())
        self.input_count_var.set(f"{count} 个账号")
        self.accounts_text.edit_modified(False)

    def _update_counters(self) -> None:
        self.success_count_var.set(str(len(self.last_payload_accounts)))
        self.failed_count_var.set(str(len(self.last_failed)))
        self.pending_count_var.set(str(max(len(self._active_accounts) - self._batch_done, 0) if self.running else len(self.retry_accounts)))

    def open_recovery(self) -> None:
        folder = TOOL_DIR / "recovery"
        try:
            folder.mkdir(parents=True, exist_ok=True)
            if sys.platform.startswith("win"):
                import os
                os.startfile(folder)
            else:
                import subprocess
                subprocess.Popen(["xdg-open", str(folder)])
        except OSError as exc:
            messagebox.showerror(APP_TITLE, f"无法打开结果目录：{exc}")

    def _set_placeholder(self) -> None:
        self.accounts_text.delete("1.0", tk.END)
        set_hint(self.accounts_text, "粘贴账号，或导入文件")
        self.placeholder_active = True

    def _clear_placeholder(self, _event: object | None = None) -> None:
        if getattr(self, "placeholder_active", False):
            self.accounts_text.delete("1.0", tk.END)
            hide_hint(self.accounts_text)
            self.accounts_text.configure(fg=COLORS["text"])
            self.placeholder_active = False

    def _restore_placeholder(self, _event: object | None = None) -> None:
        if not self.accounts_text.get("1.0", "end-1c").strip():
            self._set_placeholder()

    def account_text(self) -> str:
        if getattr(self, "placeholder_active", False):
            return ""
        return self.accounts_text.get("1.0", "end-1c")

    def load_file(self) -> None:
        path = filedialog.askopenfilename(
            title="选择账号文件",
            filetypes=[("账号文件", "*.txt *.json"), ("全部文件", "*.*")],
        )
        if not path:
            return
        try:
            content = Path(path).read_text(encoding="utf-8-sig")
        except (OSError, UnicodeError) as exc:
            messagebox.showerror(APP_TITLE, f"无法读取账号文件：{type(exc).__name__}")
            return
        self.placeholder_active = False
        self.accounts_text.configure(fg=COLORS["text"])
        self.accounts_text.delete("1.0", tk.END)
        self.accounts_text.insert("1.0", content)
        hide_hint(self.accounts_text)
        self._append_log(f"已载入文件：{path}")

    def clear_accounts(self) -> None:
        self._set_placeholder()

    def open_debug(self) -> None:
        debug_dir = TOOL_DIR / "debug"
        try:
            debug_dir.mkdir(parents=True, exist_ok=True)
            if sys.platform.startswith("win"):
                import os

                os.startfile(debug_dir)  # type: ignore[attr-defined]
            else:
                import subprocess

                subprocess.Popen(["xdg-open", str(debug_dir)])
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror(APP_TITLE, f"无法打开调试目录：{exc}")

    def start(self) -> None:
        if self.running or self.closing or (self.worker is not None and self.worker.is_alive()):
            return
        try:
            accounts = load_accounts(self.account_text())
        except ValueError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return
        self._start_batch(accounts, retry=False)

    def retry_failed(self) -> None:
        self._retry_authorization(list(self.retry_accounts))

    def retry_selected(self):
        selected = set(self.auth_tree.selection())
        self._retry_authorization([item for item in self.retry_accounts if getattr(item, "_ui_uid", str(id(item))) in selected])

    def _retry_authorization(self, accounts):
        if self.running or self.closing or not self.retry_accounts or (self.worker is not None and self.worker.is_alive()):
            return
        choices = [item for item in accounts if item.oauth_account and item.refresh_state in ("refresh_failed", "refresh_unknown", "refreshing")]
        if choices:
            if not messagebox.askyesno(APP_TITLE, f"有 {len(choices)} 个账号刷新失败或结果不明确。是否改用浏览器重新登录？\n选择否将保留结果，不会自动重登。", parent=self.root):
                accounts = [item for item in accounts if item not in choices]
            else:
                from dataclasses import replace
                replaced = []
                for item in accounts:
                    fresh = replace(item, oauth_account=None, refresh_state="") if item in choices else item
                    fresh._ui_uid = getattr(item, "_ui_uid", str(id(item)))
                    replaced.append(fresh)
                accounts = replaced
        if accounts:
            self._start_batch(accounts, retry=True)

    def _start_batch(self, accounts, *, retry: bool) -> None:
        try:
            timeout = int(self.timeout_var.get().strip() or "180")
            if timeout < 30:
                raise ValueError
        except ValueError:
            messagebox.showerror(APP_TITLE, "超时时间必须是不小于 30 的整数")
            return

        try:
            proxy = self.current_proxy()
        except ValueError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return

        try:
            human = self._human_settings()
        except ValueError as exc:
            messagebox.showerror(APP_TITLE, str(exc), parent=self.root)
            return

        if not _TASK_LOCK.acquire(blocking=False):
            messagebox.showwarning(APP_TITLE, "另一个授权、自动接码或推池任务正在运行，请等待它完成后再启动。")
            return
        self._task_lock_held = True

        self._save_auth_settings()
        self.stop_flag.clear()
        self.running = True
        present_running(self, "auth", True)
        if not retry:
            self.last_payload_accounts = []
            self.auth_filter.clear()
            self._auth_rows.clear()
        selected_ids = {getattr(item, "_ui_uid", str(id(item))) for item in accounts}
        self._retry_preserved = [item for item in self.retry_accounts if getattr(item, "_ui_uid", str(id(item))) not in selected_ids] if retry else []
        self.last_failed = []
        self.retry_accounts = []
        self._active_accounts = list(accounts)
        for item in accounts:
            item._ui_uid = getattr(item, "_ui_uid", str(id(item)))
            self._auth_rows[item._ui_uid] = item
            self.auth_filter.put(item._ui_uid, (item.email, "待处理", "等待处理"))
        self._batch_failed_accounts = []
        self._batch_done = 0
        self._batch_successes = 0
        self.start_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL)
        self.save_btn.configure(state=tk.DISABLED)
        self.retry_btn.configure(state=tk.DISABLED)
        self.progress.configure(maximum=max(len(accounts), 1), value=0)
        silent = False if retry else not self.show_browser_var.get()
        self.status_var.set(f"准备{'静默' if silent else '显示浏览器'}授权 {len(accounts)} 个账号")
        self._append_log(f"开始处理 {len(accounts)} 个账号（{'静默' if silent else '显示浏览器'}）")
        self._append_log("已启用代理，用于浏览器登录及 token 交换。" if proxy else "本轮未启用代理。")

        self._update_counters()
        self.worker = threading.Thread(
            target=self._run_worker,
            args=(accounts, timeout, proxy, silent, human),
            daemon=False,
        )
        try:
            self.worker.start()
        except Exception:
            self._task_lock_held = False
            _TASK_LOCK.release()
            self.running = False
            present_running(self, "auth", False)
            raise

    def stop(self) -> None:
        if not self.running:
            return
        self.stop_flag.set()
        self.status_var.set("正在停止并释放浏览器…")
        self._append_log("已请求停止")

    def current_export_format(self) -> str:
        value = (self.export_format_var.get() or "sub2").strip().lower()
        return "cpa" if value == "cpa" else "sub2"

    def save_json(self) -> None:
        if not self.last_payload_accounts:
            messagebox.showinfo(APP_TITLE, "还没有成功授权的账号可保存")
            return
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        export_format = self.current_export_format()
        try:
            warnings = conversion_warnings(self.last_payload_accounts, export_format)
        except Exception as exc:
            messagebox.showerror(APP_TITLE, f"无法导出：{exc}")
            return
        if warnings:
            messagebox.showwarning(APP_TITLE, "\n".join(warnings))
        if export_format == "cpa":
            folder = filedialog.askdirectory(title="选择 CPA JSON 保存目录")
            if not folder:
                return
            output_dir = Path(folder) / f"cpa-account-{stamp}"
            try:
                written = write_cpa_files(output_dir, self.last_payload_accounts)
            except Exception as exc:
                messagebox.showerror(APP_TITLE, f"保存失败：{exc}")
                return
            self._append_log(f"已按 CPA 格式保存 {len(written)} 个文件到 {output_dir}")
            messagebox.showinfo(APP_TITLE, f"已保存 {len(written)} 个 CPA JSON\n{output_dir}")
            return
        path = filedialog.asksaveasfilename(
            title="保存 sub2api JSON",
            defaultextension=".json",
            initialfile=f"sub2api-account-{stamp}.json",
            filetypes=[("JSON 文件", "*.json")],
        )
        if not path:
            return
        try:
            output = write_export_file(path, self.last_payload_accounts)
        except Exception as exc:
            messagebox.showerror(APP_TITLE, f"保存失败：{exc}")
            return
        self._append_log(f"已按 sub2 格式保存 {len(self.last_payload_accounts)} 个账号到 {output}")
        messagebox.showinfo(APP_TITLE, f"已保存 {len(self.last_payload_accounts)} 个账号\n{output}")

    def _human_settings(self):
        """Build pacing settings from the authorization page controls."""
        return HumanSettings(enabled=bool(self.human_var.get()),
                             scale=validate_scale(self.human_scale_var.get().strip() or "1.0"))

    def open_converter(self) -> None:
        self.navigation.select("convert")
        self.main_view.pack_forget()
        if self.pool_page is not None:
            self.pool_page.win.pack_forget()
        if self.phone_page is not None:
            self.phone_page.win.pack_forget()
        if self.converter is None:
            self.converter = ConvertWindow(self.root, self._append_log, self.show_authorization)
        self.converter.win.pack(fill=tk.BOTH, expand=True)
        self.root.title(f"{CONVERT_TITLE} - OpenAI Reauth")

    def open_phone(self) -> None:
        self.navigation.select("phone")
        self.main_view.pack_forget()
        if self.pool_page is not None:
            self.pool_page.win.pack_forget()
        if self.converter is not None:
            self.converter.win.pack_forget()
        if self.phone_page is None:
            self.phone_page = PhoneWindow(self.root, self._append_log, self.show_authorization)
        self.phone_page.win.pack(fill=tk.BOTH, expand=True)
        self.root.title(f"{PHONE_TITLE} - OpenAI Reauth")

    def _open_history_record(self, record):
        if self.closing or self.running or _TASK_LOCK.locked():
            self.status_var.set("请等待当前任务结束，再打开历史记录")
            return
        try:
            text = read_history_json(record, TOOL_DIR / "recovery")
            if record.kind == "推池任务":
                self.open_pool()
                self.pool_page.restore_task(record.path)
            elif record.kind == "授权结果":
                parse_accounts_from_text(text)
                self.open_converter()
                self.converter.set_input(text)
                self.converter.preview()
            else:
                data = json.loads(text)
                from collections import Counter
                rows = data.get("results", []) if isinstance(data, dict) else data if isinstance(data, list) else []
                states = Counter(str(row.get("phone_status") or row.get("category") or "未分类") for row in rows if isinstance(row, dict))
                self.history_view.status.set(f"接码报告 {len(rows)} 条 · " + " / ".join(f"{key}: {count}" for key, count in states.items()))
        except (OSError, ValueError, TypeError):
            messagebox.showerror(APP_TITLE, "无法打开记录：文件已移动、损坏或格式不支持", parent=self.root)

    def open_pool(self) -> None:
        self.navigation.select("pool")
        self.main_view.pack_forget()
        for page in (self.converter, self.phone_page):
            if page is not None:
                page.win.pack_forget()
        if self.pool_page is None:
            self.pool_page = PoolPushWindow(self.root, on_back=self.show_authorization, task_lock=_TASK_LOCK,
                                            protect=_protect_setting, unprotect=_unprotect_setting,
                                            auth_options=self.current_proxy,
                                            on_phone_inputs=self._receive_pool_phone_inputs)
        self.pool_page.win.pack(fill=tk.BOTH, expand=True)
        self.root.title("自动推池 - OpenAI Reauth")

    def push_success_results(self) -> None:
        """Hand successful OAuth payloads to the pool page without starting a write."""
        if not self.last_payload_accounts or self.closing:
            return
        self.open_pool()
        self.pool_page.receive_accounts(self.last_payload_accounts)

    def _receive_pool_phone_inputs(self, inputs) -> None:
        """Move skipped phone-verification logins to the phone page, never auto-run."""
        if not inputs or self.closing:
            return
        from account_inputs import login_mapping

        content = json.dumps([login_mapping(item) for item in inputs], ensure_ascii=False, indent=2)
        self.open_phone()
        self.phone_page.set_input(content)
        self.phone_page.status_var.set(f"已接收 {len(inputs)} 个待补手机账号；核对接码设置后点击开始接码")

    def show_authorization(self) -> None:
        self.navigation.select("auth")
        if self.pool_page is not None:
            self.pool_page.win.pack_forget()
        if self.converter is not None:
            self.converter.win.pack_forget()
        if self.phone_page is not None:
            self.phone_page.win.pack_forget()
        self.main_view.pack(fill=tk.BOTH, expand=True)
        self.root.title(APP_TITLE)

    def _run_worker(self, accounts, timeout: int, proxy: str | None, headless: bool, human=None) -> None:
        parsed_proxy = urlsplit(proxy) if proxy else None
        self._auth_log_secrets = tuple(value for value in (
            proxy, parsed_proxy.password if parsed_proxy else None,
            unquote(parsed_proxy.password or "") if parsed_proxy else None,
        ) if value)
        self._auth_log_secrets += tuple(value for item in accounts for value in
                                       (item.password, item.totp_secret, item.mailbox_url) if value)
        set_log_callback(self._queue_log)
        try:
            def should_stop() -> bool:
                return self.stop_flag.is_set()

            def on_progress(index: int, total: int, result) -> None:
                self.event_queue.put(("progress", index, total, result))

            from oauth_refresh import run_refresh_first
            results = run_refresh_first(
                accounts,
                authorize=run_batch_reauth,
                timeout=float(timeout),
                proxy=proxy,
                headless=headless,
                should_stop=should_stop,
                on_progress=on_progress,
                recovery_dir=TOOL_DIR / "recovery",
                human=human,
            )
            self.event_queue.put(("finished", len(results), len(accounts)))
        except Exception as exc:  # noqa: BLE001
            message = redact_diagnostic(str(exc), self._auth_log_secrets)
            self._queue_log(f"运行失败：{message}")
            self.event_queue.put(("failed", message))
        finally:
            set_log_callback(None)
            if self._task_lock_held:
                self._task_lock_held = False
                _TASK_LOCK.release()

    def _on_progress(self, index: int, total: int, result) -> None:
        self._batch_done = index
        self.progress.configure(maximum=max(total, 1), value=index)
        success = bool(result.ok and result.account)
        category = getattr(result, "category", "failed")
        state = "成功" if success else {"needs_interaction": "需人工交互", "refresh_failed": "刷新失败，待选择", "refresh_unknown": "刷新待核对", "phone_required": "待补手机", "cancelled": "已取消", "rate_limited": "受限流影响"}.get(category, "失败")
        self.status_var.set(f"{index}/{total} {result.email} {state}")
        if 0 < index <= len(self._active_accounts):
            item = self._active_accounts[index - 1]
            uid = getattr(item, "_ui_uid", str(id(item)))
            self.auth_filter.put(uid, (result.email, state, "授权完成" if success else result.error or "未完成"))
        if success:
            self.last_payload_accounts.append(result.account)
            self._batch_successes += 1
        else:
            self.last_failed.append(f"{result.email}: {state}（{result.error or '未完成授权'}）")
            if 0 < index <= len(self._active_accounts):
                self._batch_failed_accounts.append(self._active_accounts[index - 1])

        self._update_counters()

    def _finish_controls(self) -> None:
        self.running = False
        present_running(self, "auth", False)
        self.retry_accounts = self._retry_preserved + self._batch_failed_accounts + self._active_accounts[self._batch_done:]
        for item in self._active_accounts[self._batch_done:]:
            self.auth_filter.put(getattr(item, "_ui_uid", str(id(item))), (item.email, "未处理", "可选中重试"))
        self._active_accounts = []
        self._batch_failed_accounts = []
        self.start_btn.configure(state=tk.DISABLED if self.closing else tk.NORMAL)
        self.stop_btn.configure(state=tk.DISABLED)
        self.save_btn.configure(state=tk.NORMAL if self.last_payload_accounts and not self.closing else tk.DISABLED)
        self.push_results_btn.configure(state=tk.NORMAL if self.last_payload_accounts and not self.closing else tk.DISABLED)
        self.retry_btn.configure(state=tk.NORMAL if self.retry_accounts and not self.closing else tk.DISABLED)

        self._update_counters()

    def _on_finished(self, done: int, total: int) -> None:
        self._finish_controls()
        self.progress.configure(value=done)
        unattempted = max(total - done, 0)
        self.status_var.set(f"本轮：成功 {self._batch_successes} / 失败 {len(self.last_failed)} / 未处理 {unattempted}；累计成功 {len(self.last_payload_accounts)}")
        if self.last_failed:
            self._append_log("本轮未成功账号（可点击重试，仅处理这些账号和未处理账号）：")
            for item in self.last_failed:
                self._append_log(f"  {item}")
        if self.closing:
            return
        if self.last_payload_accounts:
            fmt = "CPA" if self.current_export_format() == "cpa" else "sub2"
            if messagebox.askyesno(APP_TITLE, f"累计成功 {len(self.last_payload_accounts)} 个，待重试 {len(self.retry_accounts)} 个。\n现在按 {fmt} 格式保存吗？"):
                self.save_json()
        else:
            messagebox.showwarning(APP_TITLE, "本轮没有成功授权的账号。请查看日志；可点击「重试未成功账号」打开浏览器处理。")

    def _on_failed(self, message: str) -> None:
        self._finish_controls()
        self.status_var.set(f"运行中断；已保留 {len(self.last_payload_accounts)} 个成功结果，待重试 {len(self.retry_accounts)} 个")
        if not self.closing:
            messagebox.showerror(APP_TITLE, message)

    def _queue_log(self, line: str) -> None:
        self.event_queue.put(("log", redact_diagnostic(line, self._auth_log_secrets)))

    def _append_log(self, line: str) -> None:
        self.log_text.configure(state=tk.NORMAL)
        tag = "error" if any(word in line for word in ("失败，", "运行失败")) else "warning" if any(word in line for word in ("限流", "未成功", "等待操作")) else "success" if "授权成功" in line else ""
        self.log_text.insert(tk.END, line.rstrip() + "\n", (tag,) if tag else ())
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def _drain_events(self) -> None:
        self.history_view.drain()
        while True:
            try:
                event = self.event_queue.get_nowait()
            except queue.Empty:
                break
            kind, *args = event
            if kind == "log":
                self._append_log(*args)
            elif kind == "progress":
                self._on_progress(*args)
            elif kind == "finished":
                self._on_finished(*args)
            elif kind == "failed":
                self._on_failed(*args)
        self._schedule(80, self._drain_events)

    def on_close(self) -> None:
        if self.closing:
            return
        self._save_auth_settings()
        self.closing = True
        self.stop_flag.set()
        self.start_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.DISABLED)
        self.retry_btn.configure(state=tk.DISABLED)
        self.save_btn.configure(state=tk.DISABLED)
        self.push_results_btn.configure(state=tk.DISABLED)
        self.status_var.set("正在停止并释放浏览器，完成后关闭…")
        if self.phone_page is not None:
            self.phone_page.begin_close()
        if self.pool_page is not None:
            self.pool_page.begin_close()
        self._wait_for_worker_close()

    def _wait_for_worker_close(self) -> None:
        phone_worker = self.phone_page.worker if self.phone_page is not None else None
        pool_worker = self.pool_page.worker if self.pool_page is not None else None
        if ((self.worker is not None and self.worker.is_alive())
                or (phone_worker is not None and phone_worker.is_alive())
                or (pool_worker is not None and pool_worker.is_alive())):
            self._schedule(100, self._wait_for_worker_close)
            return
        self.retry_accounts.clear()
        self._active_accounts.clear()
        self._batch_failed_accounts.clear()
        self.accounts_text.delete("1.0", tk.END)
        for handle in self._after_ids:
            self.root.after_cancel(handle)
        self._after_ids.clear()
        if self.phone_page is not None:
            self.phone_page.dispose()
        if self.pool_page is not None:
            self.pool_page.dispose()
        self.root.destroy()


CONVERT_TITLE = "JSON 格式转换"
CONVERT_PLACEHOLDER = (
    "粘贴 JSON，或导入文件 / 目录。\n\n"
    "支持 sub2、CPA、Session、9router。\n"
    "可混合粘贴多个对象或账号数组。"
)


class ConvertWindow:
    """An in-window conversion page; the name remains for caller compatibility."""

    def __init__(self, master: tk.Tk, log_fn, on_back=None) -> None:
        self.log_fn = log_fn
        self.on_back = on_back
        self.win = ttk.Frame(master, style="App.TFrame")
        setup_theme(master)
        self.accounts: list[dict] = []
        self.source_kind = ""
        self._parsed_input: str | None = None
        self._import_warnings: list[str] = []
        self._import_report = ""
        self._auto_target_kind = ""
        self.target_var = tk.StringVar(master=master, value="sub2")
        self.placeholder_active = True
        self._build()

    def _make_text(self, parent, height, wrap, bg, fg, state=tk.NORMAL):
        holder, text = text_area(parent, height=height, wrap=wrap, bg=bg, fg=fg, state=state)
        text.bind("<Control-a>", self._select_all)
        text.bind("<Control-A>", self._select_all)
        return holder, text

    @staticmethod
    def _select_all(event: tk.Event) -> str:
        event.widget.tag_add("sel", "1.0", "end-1c")
        return "break"

    def _build(self) -> None:
        outer = ttk.Frame(self.win, style="App.TFrame", padding=(24, 20, 24, 16))
        outer.pack(fill=tk.BOTH, expand=True)
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(3, weight=1)
        header = page_header(outer, "格式转换", "sub2 · CPA · Session · 9router，导入后预览并保存。", "数据管理")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 16))
        if self.on_back is not None and not hasattr(self.win.winfo_toplevel(), "_reauth_navigation"):
            ttk.Button(header, text="← 返回批量授权", style="Page.Secondary.TButton", command=self.on_back).pack(side=tk.RIGHT)

        toolbar = ttk.Frame(outer, style="App.TFrame")
        toolbar.grid(row=1, column=0, sticky="ew", pady=(0, 14))
        ttk.Button(toolbar, text="导入文件", style="Page.Secondary.TButton", command=self.load_json_files).pack(side=tk.LEFT)
        ttk.Button(toolbar, text="导入目录", style="Page.Secondary.TButton", command=self.load_json_dir).pack(side=tk.LEFT, padx=8)
        ttk.Label(toolbar, text="目标格式", style="Subtitle.TLabel").pack(side=tk.LEFT, padx=(12, 8))
        target = ttk.Combobox(toolbar, textvariable=self.target_var, values=("sub2", "cpa"), state="readonly", width=8)
        target.pack(side=tk.LEFT)
        target.bind("<<ComboboxSelected>>", lambda _event: self.preview() if self.input_value().strip() else None)
        ttk.Button(toolbar, text="清空输入", style="Page.Ghost.TButton", command=self.clear_input).pack(side=tk.RIGHT)

        summary = card(outer, padding=10)
        summary.grid(row=2, column=0, sticky="ew", pady=(0, 12))
        ttk.Label(summary, text="账号检查 · 仅检查本地数据，未验证在线可用性", style="Hint.TLabel").pack(anchor="w", pady=(0, 8))
        columns = ("email", "account_id", "state", "refresh", "expires")
        self.account_tree = DataTable(summary, columns=columns, show="headings", height=2, empty_text="导入账号后查看数据检查结果", empty_command=self.load_json_files)
        for key, label, width in zip(columns, ("邮箱", "空间 ID", "有效期状态", "自动续期条件", "到期时间 (+08:00)"),
                                     (195, 155, 160, 175, 205)):
            self.account_tree.heading(key, text=label)
            self.account_tree.column(key, width=width, minwidth=100)
        table_scroll = AutoScrollbar(summary, orient=tk.VERTICAL, command=self.account_tree.yview, content_widget=self.account_tree)
        table_scroll_x = AutoScrollbar(summary, orient=tk.HORIZONTAL, command=self.account_tree.xview, content_widget=self.account_tree)
        self.account_tree.configure(yscrollcommand=table_scroll.set, xscrollcommand=table_scroll_x.set)
        table_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        table_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.account_tree.pack(fill=tk.BOTH, expand=True)

        workspace = ttk.Frame(outer, style="App.TFrame")
        workspace.grid(row=3, column=0, sticky="nsew")
        workspace.columnconfigure((0, 1), weight=1, uniform="convert")
        workspace.rowconfigure(0, weight=1)
        source = card(workspace, padding=12)
        source.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        source.columnconfigure(0, weight=1)
        source.rowconfigure(2, weight=1)
        ttk.Label(source, text="输入内容", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(source, text="自动识别格式，可混合导入", style="Hint.TLabel").grid(row=1, column=0, sticky="w", pady=(4, 8))
        holder, self.input_text = self._make_text(source, 12, tk.NONE, COLORS["soft"], COLORS["text"])
        holder.grid(row=2, column=0, sticky="nsew")
        self._set_placeholder()
        self.input_text.bind("<FocusIn>", self._clear_placeholder, add="+")
        self.input_text.bind("<FocusOut>", self._restore_placeholder, add="+")

        result = card(workspace, padding=12)
        result.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        result.columnconfigure(0, weight=1)
        result.rowconfigure(2, weight=1)
        ttk.Label(result, text="转换预览", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(result, text="预览已脱敏，导出保留完整凭据", style="Hint.TLabel").grid(row=1, column=0, sticky="w", pady=(4, 8))
        holder, self.preview_text = self._make_text(result, 12, tk.WORD, COLORS["log"], COLORS["log_text"], state=tk.DISABLED)
        holder.grid(row=2, column=0, sticky="nsew")
        self.set_preview("等待输入 JSON\n\n识别后，将在这里展示转换结果。")

        bottom = ttk.Frame(outer, style="App.TFrame")
        bottom.grid(row=4, column=0, sticky="ew", pady=(10, 6))
        ttk.Button(bottom, text="识别并预览", style="Page.Primary.TButton", command=self.preview).pack(side=tk.LEFT)
        ttk.Button(bottom, text="保存为 CPA", style="Page.Secondary.TButton", command=self.save_as_cpa).pack(side=tk.RIGHT)
        ttk.Button(bottom, text="保存为 sub2", style="Page.Secondary.TButton", command=self.save_as_sub2).pack(side=tk.RIGHT, padx=8)
        self.status_var = tk.StringVar(value="等待输入 · 从文件导入，或直接粘贴 JSON")
        status = ttk.Label(outer, textvariable=self.status_var, style="Subtitle.TLabel", wraplength=980)
        status.grid(row=5, column=0, sticky="ew")
        def resize(event):
            status.configure(wraplength=max(event.width - 55, 250))
            self.account_tree.configure(height=3 if event.height >= 900 else 2)
        outer.bind("<Configure>", resize)

    def _set_placeholder(self) -> None:
        self.input_text.delete("1.0", tk.END)
        set_hint(self.input_text, "粘贴 JSON，或导入文件")
        self.placeholder_active = True

    def _clear_placeholder(self, _event: object | None = None) -> None:
        if self.placeholder_active:
            self.input_text.delete("1.0", tk.END)
            hide_hint(self.input_text)
            self.input_text.configure(fg=COLORS["text"])
            self.placeholder_active = False

    def _restore_placeholder(self, _event: object | None = None) -> None:
        if not self.input_text.get("1.0", "end-1c").strip():
            self._set_placeholder()

    def input_value(self) -> str:
        if self.placeholder_active:
            return ""
        return self.input_text.get("1.0", "end-1c")

    def set_input(self, content: str) -> None:
        self._parsed_input = None
        self._import_warnings = []
        self._import_report = ""
        self._auto_target_kind = ""
        self.account_tree.delete(*self.account_tree.get_children())
        self.accounts = []
        self.source_kind = ""
        self.placeholder_active = False
        self.input_text.configure(fg=COLORS["text"])
        self.input_text.delete("1.0", tk.END)
        self.input_text.insert("1.0", content)
        hide_hint(self.input_text)

    def set_preview(self, content: str) -> None:
        self.preview_text.configure(state=tk.NORMAL)
        self.preview_text.delete("1.0", tk.END)
        self.preview_text.insert("1.0", content)
        json_highlight(self.preview_text)
        self.preview_text.configure(state=tk.DISABLED)

    def clear_input(self) -> None:
        self.accounts = []
        self.source_kind = ""
        self._parsed_input = None
        self._import_warnings = []
        self._import_report = ""
        self._auto_target_kind = ""
        self.account_tree.delete(*self.account_tree.get_children())
        self._set_placeholder()
        self.set_preview("")
        self.status_var.set("等待输入")

    def load_sub2_file(self) -> None:
        path = filedialog.askopenfilename(
            parent=self.win,
            title="选择 sub2 JSON",
            filetypes=[("JSON 文件", "*.json"), ("全部文件", "*.*")],
        )
        if not path:
            return
        self._load_conversion_paths([path])

    def load_cpa_file(self) -> None:
        self.load_json_files()

    def load_json_files(self) -> None:
        paths = filedialog.askopenfilenames(
            parent=self.win,
            title="选择 JSON 文件（可多选、混合格式）",
            filetypes=[("JSON 文件", "*.json"), ("全部文件", "*.*")],
        )
        if not paths:
            return
        self._load_conversion_paths(paths)

    def load_cpa_dir(self) -> None:
        self.load_json_dir()

    def load_json_dir(self) -> None:
        folder = filedialog.askdirectory(parent=self.win, title="选择 JSON 目录（支持混合格式）")
        if not folder:
            return
        try:
            files = sorted((path for path in Path(folder).iterdir()
                            if path.is_file() and path.suffix.lower() == ".json"), key=lambda path: path.name.casefold())
        except OSError:
            messagebox.showerror(CONVERT_TITLE, "无法读取目录", parent=self.win)
            return
        self._load_conversion_paths(files)

    def _load_conversion_paths(self, paths) -> None:
        result = load_conversion_files(paths)
        failures = dict(result.failures)
        report = [f"文件导入：成功 {result.accepted_files}，失败 {len(result.failures)}"]
        for index, path in enumerate(result.files, 1):
            detail = f"已跳过：{failures[index]}" if index in failures else "已载入"
            report.append(f"{index}. {path.name} — {detail}")
        if not result.accounts:
            messagebox.showerror(CONVERT_TITLE, "没有可转换的账号；保留原输入。\n" + "\n".join(report[:21]), parent=self.win)
            return
        self.set_input(result.text)
        self._import_report = "\n".join(report)
        self._import_warnings = [f"第 {index} 个文件已跳过：{reason}" for index, reason in result.failures]
        self._show_accounts(result.kind, result.accounts)

    def preview(self) -> bool:
        try:
            if self.accounts and self._parsed_input == self.input_value():
                kind, accounts = self.source_kind, self.accounts
            else:
                kind, accounts = parse_accounts_from_text(self.input_value())
                accounts.warnings = list(dict.fromkeys(accounts.warnings + self._import_warnings))
            self._show_accounts(kind, accounts)
        except Exception as exc:  # noqa: BLE001
            self.accounts = []
            self.source_kind = ""
            self._parsed_input = None
            self.account_tree.delete(*self.account_tree.get_children())
            self.set_preview("")
            self.status_var.set(str(exc))
            messagebox.showerror(CONVERT_TITLE, str(exc), parent=self.win)
            return False
        return True

    def _show_accounts(self, kind: str, accounts: list[dict]) -> None:
        emails = [str((item.get("credentials") or {}).get("email") or item.get("name") or "") for item in accounts]
        if not self._auto_target_kind:
            self.target_var.set("cpa" if kind == "sub2" else "sub2")
        self._auto_target_kind = kind
        preview_kind = self.target_var.get()
        self.account_tree.delete(*self.account_tree.get_children())
        for account in accounts:
            status = account_conversion_status(account)
            self.account_tree.insert("", tk.END, values=tuple(status[key] for key in self.account_tree["columns"]))
        preview_error = ""
        try:
            warnings = conversion_warnings(accounts, preview_kind)
            if preview_kind == "sub2":
                preview_payload = build_export_payload(accounts)
                preview_payload["accounts"] = preview_payload["accounts"][:20]
                preview = json.dumps(masked_preview(preview_payload), indent=2, ensure_ascii=False)
            else:
                preview_items = [build_cpa_payload(item) for item in accounts[:20]]
                preview = "\n\n".join(json.dumps(masked_preview(item), indent=2, ensure_ascii=False) for item in preview_items)
            if len(accounts) > 20:
                preview += f"\n\n# 共 {len(accounts)} 个账号，预览仅显示前 20 个；保存包括全部账号"
        except (ValueError, TypeError) as exc:
            # Recognition and preservation of the source do not depend on whether
            # the opposite format can represent it (for example, CPA needs email).
            warnings = list(getattr(accounts, "warnings", []))
            preview_error = str(exc)
            preview = f"已识别并保留全部 {kind} 输入。\n无法生成 {preview_kind} 预览：{preview_error}\n可选择保存为原格式；保存其他格式时会再次检查。"
        if warnings:
            preview = "转换提示：\n" + "\n".join(warnings) + "\n\n" + preview
        if self._import_report:
            preview = self._import_report + "\n\n" + preview
        self.source_kind = kind
        self.accounts = accounts
        self._parsed_input = self.input_value()
        self.set_preview(preview)
        sample = "、".join(email for email in emails[:3] if email)
        extra = f"，例如 {sample}" if sample else ""
        warning_hint = f" 有 {len(warnings)} 条转换提示，请看预览。" if warnings else ""
        preview_status = f"{preview_kind} 预览不可用，请看说明。" if preview_error else f"预览为 {preview_kind} 格式。"
        kind_label = {"mixed": "混合格式", "web_session": "网页 Session", "cpa": "CPA"}.get(kind, kind)
        self.status_var.set(f"识别为 {kind_label}，共 {len(accounts)} 个账号{extra}。{preview_status}{warning_hint}")

    def _show_save_warnings(self, target: str) -> bool:
        try:
            warnings = conversion_warnings(self.accounts, target)
        except Exception as exc:
            messagebox.showerror(CONVERT_TITLE, f"无法转换：{exc}", parent=self.win)
            return False
        if warnings:
            shown = warnings[:20]
            if len(warnings) > 20:
                shown.append(f"共 {len(warnings)} 条提示，此处显示前 20 条；请在对应格式预览中查看完整内容。")
            messagebox.showwarning(CONVERT_TITLE, "\n".join(shown), parent=self.win)
        return True

    def save_as_sub2(self) -> None:
        if not self.ensure_accounts() or not self._show_save_warnings("sub2"):
            return
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = filedialog.asksaveasfilename(
            parent=self.win,
            title="保存 sub2 JSON",
            defaultextension=".json",
            initialfile=f"sub2api-from-convert-{stamp}.json",
            filetypes=[("JSON 文件", "*.json")],
        )
        if not path:
            return
        try:
            output = write_export_file(path, self.accounts)
        except Exception as exc:
            messagebox.showerror(CONVERT_TITLE, f"保存失败：{exc}", parent=self.win)
            return
        message = f"已保存 {len(self.accounts)} 个账号到 {output}"
        self.status_var.set(message)
        self.log_fn(f"转换窗口：{message}")
        messagebox.showinfo(CONVERT_TITLE, message, parent=self.win)

    def save_as_cpa(self) -> None:
        if not self.ensure_accounts() or not self._show_save_warnings("cpa"):
            return
        folder = filedialog.askdirectory(parent=self.win, title="选择 CPA JSON 保存目录")
        if not folder:
            return
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        output_dir = Path(folder) / f"cpa-from-convert-{stamp}"
        try:
            written = write_cpa_files(output_dir, self.accounts)
        except Exception as exc:
            messagebox.showerror(CONVERT_TITLE, f"保存失败：{exc}", parent=self.win)
            return
        message = f"已保存 {len(written)} 个 CPA JSON 到 {output_dir}"
        self.status_var.set(message)
        self.log_fn(f"转换窗口：{message}")
        messagebox.showinfo(CONVERT_TITLE, message, parent=self.win)

    def ensure_accounts(self) -> bool:
        if self.accounts and self._parsed_input == self.input_value():
            return True
        return self.preview()


PHONE_TITLE = "自动接码"
PHONE_PLACEHOLDER = (
    "粘贴账号，或导入文件 / 目录。\n\n"
    "邮箱----密码[----2FA]\n"
    "邮箱----邮箱接码地址\n"
    "也支持 sub2 / CPA JSON。"
)
PHONE_CONFIG_PATH = TOOL_DIR / "phone_smsbower.json"

# Playwright's callback server and the module-level log callback are process
# globals.  Only one batch may therefore run at a time, even though the two
# pages live in the same Tk window.
_TASK_LOCK = threading.Lock()


from local_secrets import protect_secret as _protect_setting, unprotect_secret as _unprotect_setting

class PhoneWindow:
    """In-window SMSBower phone verification page."""

    def __init__(self, master: tk.Tk, log_fn, on_back=None) -> None:
        self.log_fn = log_fn
        self.on_back = on_back
        self.win = ttk.Frame(master, style="App.TFrame")
        setup_theme(master)
        self.placeholder_active = True
        self._input_sources: list[tuple[str, str]] | None = None
        self._imported_text = ""
        self.closing = False
        self.last_results = []
        self._log_secrets: tuple[str, ...] = ()
        self.event_queue: queue.Queue[tuple] = queue.Queue()
        self.worker: threading.Thread | None = None
        self.stop_flag = threading.Event()
        self.running = False
        self._task_lock_held = False
        self._after_id = None
        self._quote_ready = False
        self._quote_generation = 0
        self._quote_busy = False
        self._quote_pending = False
        self._quote_worker = None
        self._quote_snapshot = None
        self._build()
        self._load_settings()
        self._quote_ready = True
        self._schedule_drain()

    def _schedule_drain(self) -> None:
        self._after_id = self.win.after(80, self._drain)

    def begin_close(self) -> None:
        self.closing = True
        self._quote_generation += 1
        self._quote_pending = False
        self.stop_flag.set()
        self.start_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.DISABLED)
        self.status_var.set("正在停止并处理短信订单，完成后关闭…")

    def dispose(self) -> None:
        self._quote_ready = False
        self._quote_generation += 1
        if self._after_id is not None:
            self.win.after_cancel(self._after_id)
            self._after_id = None
        self.input_text.delete("1.0", tk.END)
        self.api_key_var.set("")
        self.proxy_var.set("")
        self._input_sources = None
        self._log_secrets = ()

    def _make_text(self, parent, height, wrap, bg, fg, state=tk.NORMAL):
        holder, text = text_area(parent, height=height, wrap=wrap, bg=bg, fg=fg, state=state)
        text.bind("<Control-a>", lambda event: (event.widget.tag_add("sel", "1.0", "end-1c"), "break")[1])
        return holder, text

    def _build(self) -> None:
        outer = ttk.Frame(self.win, style="App.TFrame", padding=(24, 20, 24, 16))
        outer.pack(fill=tk.BOTH, expand=True)
        outer.columnconfigure(0, weight=1)
        outer.columnconfigure(1, minsize=320, weight=0)
        outer.rowconfigure(1, weight=3)
        outer.rowconfigure(2, weight=2)
        header = page_header(outer, "手机接码", "为已有账号补绑手机号，并继续完成授权。", "账号处理")
        header.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 16))
        if self.on_back is not None and not hasattr(self.win.winfo_toplevel(), "_reauth_navigation"):
            ttk.Button(header, text="← 返回批量授权", style="Secondary.TButton", command=self.on_back).pack(side=tk.RIGHT)

        source = card(outer, padding=16)
        source.grid(row=1, column=0, sticky="nsew", padx=(0, 12))
        source.columnconfigure(0, weight=1)
        source.rowconfigure(2, weight=1)
        head = ttk.Frame(source, style="Card.TFrame")
        head.grid(row=0, column=0, sticky="ew")
        ttk.Label(head, text="账号输入", style="Section.TLabel").pack(side=tk.LEFT)
        ttk.Button(head, text="导入文件", style="Ghost.TButton", command=self.load_file).pack(side=tk.RIGHT)
        ttk.Button(head, text="导入目录", style="Ghost.TButton", command=self.load_dir).pack(side=tk.RIGHT, padx=(0, 4))
        ttk.Label(source, text="支持账号行、JSON 与邮箱接码地址", style="Hint.TLabel").grid(row=1, column=0, sticky="w", pady=(8, 10))
        holder, self.input_text = self._make_text(source, 12, tk.NONE, COLORS["soft"], COLORS["text"])
        holder.grid(row=2, column=0, sticky="nsew")
        self._set_placeholder()
        self.input_text.bind("<FocusIn>", self._clear_placeholder, add="+")
        self.input_text.bind("<FocusOut>", self._restore_placeholder, add="+")
        actions = ttk.Frame(source, style="Card.TFrame")
        actions.grid(row=3, column=0, sticky="ew", pady=(12, 0))
        self.start_btn = ttk.Button(actions, text="开始接码", style="Primary.TButton", command=self.start)
        self.start_btn.pack(side=tk.LEFT)
        self.stop_btn = ttk.Button(actions, text="停止", style="Danger.TButton", command=self.stop, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=8)

        options_card = card(outer, padding=0)
        options_card.grid(row=1, column=1, rowspan=2, sticky="nsew")
        options_card.columnconfigure(0, weight=1)
        options_card.rowconfigure(1, weight=1)
        # Keep the settings that decide whether login is reachable visible
        # while the longer SMS/retry configuration scrolls below them.
        self.login_controls = ttk.Frame(options_card, style="Card.TFrame", padding=(12, 8, 12, 0))
        self.login_controls.grid(row=0, column=0, columnspan=2, sticky="ew")
        self.login_controls.columnconfigure(0, weight=1)
        ttk.Label(self.login_controls, text="接码设置", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        self.settings_tabs = SegmentedNotebook(options_card)
        self.settings_tabs.grid(row=1, column=0, sticky="nsew")
        tab, options, self.options_canvas = scroll_settings(self.settings_tabs, width=300)
        self.settings_tabs.add(tab, text="号码")
        tab, retry_options, self.retry_canvas = scroll_settings(self.settings_tabs, width=300)
        self.settings_tabs.add(tab, text="重试")
        tab, runtime_options, self.runtime_canvas = scroll_settings(self.settings_tabs, width=300)
        self.settings_tabs.add(tab, text="运行")
        ttk.Label(options, text="API Key", style="Card.TLabel").grid(row=1, column=0, sticky="w", pady=(12, 6))
        self.api_key_var = tk.StringVar()
        key_field, self.api_key_entry = secret_field(options, self.api_key_var)
        key_field.grid(row=2, column=0, sticky="ew")
        self.api_key_entry.bind("<FocusOut>", lambda _event: self.refresh_quotes())
        self.api_key_var.trace_add("write", self._quote_inputs_changed)
        ttk.Label(options, text="接码国家（拼音 A–Z）", style="Card.TLabel").grid(row=3, column=0, sticky="w", pady=(12, 6))
        self.country_var = tk.StringVar(value=country_label("38"))
        self.country_combo = ttk.Combobox(
            options,
            textvariable=self.country_var,
            values=country_dropdown_values(),
            state="readonly",
        )
        self.country_combo.grid(row=4, column=0, sticky="ew")
        self.country_combo.bind("<<ComboboxSelected>>", lambda _event: self.refresh_quotes())
        self.country_var.trace_add("write", self._quote_inputs_changed)
        budgets = ttk.Frame(options, style="Card.TFrame")
        budgets.grid(row=5, column=0, sticky="ew", pady=(12, 8))
        budgets.columnconfigure((0, 1), weight=1, uniform="budget")
        ttk.Label(budgets, text="一号最多绑定账号数", style="Hint.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 6))
        ttk.Label(budgets, text="最高单价", style="Hint.TLabel").grid(row=0, column=1, sticky="w", padx=(8, 0), pady=(0, 6))
        self.max_reuse_var = tk.StringVar(value="3")
        ttk.Entry(budgets, textvariable=self.max_reuse_var, width=8).grid(row=1, column=0, sticky="ew")
        self.max_price_var = tk.StringVar(value="0.06")
        ttk.Entry(budgets, textvariable=self.max_price_var, width=8).grid(row=1, column=1, sticky="ew", padx=(8, 0))
        ttk.Label(budgets, text="留空不限价", style="Hint.TLabel").grid(row=2, column=1, sticky="w", padx=(8, 0), pady=(4, 0))
        pricing = ttk.Frame(options, style="Card.TFrame")
        pricing.grid(row=8, column=0, sticky="ew")
        pricing.columnconfigure(0, weight=1)
        self.auto_price_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(pricing, text="自动匹配最低可用价", variable=self.auto_price_var,
                        command=self.refresh_quotes).grid(row=1, column=0, sticky="w", pady=(4, 0))
        self.refresh_quotes_btn = ttk.Button(pricing, text="读取当前国家报价", style="Secondary.TButton", command=self.refresh_quotes)
        self.refresh_quotes_btn.grid(row=2, column=0, sticky="ew", pady=(0, 6))
        self.quote_status_var = tk.StringVar(value="选择国家后自动查询；读取报价不会购买号码。")
        ttk.Label(pricing, textvariable=self.quote_status_var, style="Hint.TLabel", wraplength=250,
                  justify=tk.LEFT).grid(row=3, column=0, sticky="ew")
        self.max_price_var.trace_add("write", self._update_quote_display)
        self.auto_price_var.trace_add("write", self._update_quote_display)
        options = retry_options
        ttk.Label(options, text="重试与时限", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(options, text="单账号超时（秒）", style="Card.TLabel").grid(row=9, column=0, sticky="w", pady=(12, 6))
        self.timeout_var = tk.StringVar(value="180")
        ttk.Entry(options, textvariable=self.timeout_var).grid(row=10, column=0, sticky="ew")
        retries = ttk.Frame(options, style="Card.TFrame")
        retries.grid(row=11, column=0, sticky="ew", pady=(12, 6))
        retries.columnconfigure((0, 1), weight=1, uniform="retry")
        ttk.Label(retries, text="小重试 · 当前国家", style="Card.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(retries, text="大重试 · 更换国家", style="Card.TLabel").grid(row=0, column=1, sticky="w", padx=(8, 0))
        self.auto_retry_count_var = tk.StringVar(value="2")
        self.country_retry_count_var = tk.StringVar(value="0")
        self.auto_retry_count_entry = ttk.Entry(retries, textvariable=self.auto_retry_count_var, width=8)
        self.auto_retry_count_entry.grid(row=1, column=0, sticky="ew", pady=(6, 0))
        self.country_retry_count_entry = ttk.Entry(retries, textvariable=self.country_retry_count_var, width=8)
        self.country_retry_count_entry.grid(row=1, column=1, sticky="ew", padx=(8, 0), pady=(6, 0))

        countries = ttk.Frame(options, style="Card.TFrame")
        countries.grid(row=12, column=0, sticky="ew", pady=(6, 0))
        countries.columnconfigure(0, weight=1)
        ttk.Label(countries, text="备用国家（候选按拼音 A–Z）", style="Card.TLabel").grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 6))
        self.fallback_country_var = tk.StringVar()
        self.fallback_country_combo = ttk.Combobox(countries, textvariable=self.fallback_country_var, values=country_dropdown_values(), state="readonly", width=16)
        self.fallback_country_combo.grid(row=1, column=0, sticky="ew")
        ttk.Button(countries, text="添加", style="Ghost.TButton", command=self._add_fallback_country).grid(row=1, column=1, padx=(4, 0))
        self._fallback_countries = []
        self._fallback_config_error = False
        self.fallback_country_list = tk.Listbox(countries, height=3, exportselection=False, relief=tk.FLAT,
                                              bg=COLORS["soft"], fg=COLORS["text"], selectbackground=COLORS["accent"],
                                              selectforeground="white", highlightthickness=1, highlightbackground=COLORS["border"])
        self.fallback_country_list.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        country_actions = ttk.Frame(countries, style="Card.TFrame")
        country_actions.grid(row=3, column=0, columnspan=2, sticky="ew")
        ttk.Button(country_actions, text="上移", style="Ghost.TButton", command=lambda: self._move_fallback_country(-1)).pack(side=tk.LEFT)
        ttk.Button(country_actions, text="下移", style="Ghost.TButton", command=lambda: self._move_fallback_country(1)).pack(side=tk.LEFT)
        ttk.Button(country_actions, text="移除", style="Ghost.TButton", command=self._remove_fallback_country).pack(side=tk.RIGHT)
        self.retry_hint_var = tk.StringVar()
        self.auto_retry_count_var.trace_add("write", self._update_retry_hint)
        self.country_retry_count_var.trace_add("write", self._update_retry_hint)
        self.country_var.trace_add("write", self._refresh_fallback_countries)
        self._refresh_fallback_countries()
        self._update_retry_hint()
        ttk.Label(options, textvariable=self.retry_hint_var, style="Hint.TLabel", wraplength=250, justify=tk.LEFT).grid(row=13, column=0, sticky="ew", pady=(6, 0))
        network_row = ttk.Frame(self.login_controls, style="Card.TFrame")
        network_row.grid(row=1, column=0, sticky="ew", pady=(8, 4))
        ttk.Label(network_row, text="网络模式", style="Card.TLabel").pack(side=tk.LEFT)
        self.network_mode_var = tk.StringVar(value=NETWORK_MODES["system"])
        self.network_mode_combo = ttk.Combobox(network_row, textvariable=self.network_mode_var,
                                              values=list(NETWORK_MODES.values()), state="readonly", width=13)
        self.network_mode_combo.pack(side=tk.RIGHT)
        options = runtime_options
        ttk.Label(options, text="运行", style="Section.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 12))
        proxy_protocol = ttk.Frame(options, style="Card.TFrame")
        proxy_protocol.grid(row=15, column=0, sticky="ew", pady=(0, 6))
        ttk.Label(proxy_protocol, text="代理协议", style="Card.TLabel").pack(side=tk.LEFT)
        self.proxy_scheme_var = tk.StringVar(value="HTTP")
        self.proxy_scheme_combo = ttk.Combobox(proxy_protocol, textvariable=self.proxy_scheme_var, values=("HTTP", "HTTPS", "SOCKS5"), state="readonly", width=9)
        self.proxy_scheme_combo.pack(side=tk.RIGHT)
        self.proxy_var = tk.StringVar()
        self.proxy_entry = ttk.Entry(options, textvariable=self.proxy_var, show="•")
        self.proxy_entry.grid(row=16, column=0, sticky="ew")
        self.proxy_var.trace_add("write", self._proxy_edited)
        self.proxy_var.trace_add("write", self._quote_inputs_changed)
        self.proxy_scheme_var.trace_add("write", self._quote_inputs_changed)
        self.network_hint_var = tk.StringVar()
        ttk.Label(options, textvariable=self.network_hint_var, style="Hint.TLabel", wraplength=250).grid(row=17, column=0, sticky="ew", pady=(6, 0))
        self.network_mode_var.trace_add("write", self._network_mode_changed)
        self._network_mode_changed()
        self.show_browser_var = tk.BooleanVar(value=True)
        self.show_browser_check = ttk.Checkbutton(self.login_controls, text="显示浏览器（可查看登录页面）", variable=self.show_browser_var)
        self.show_browser_check.grid(row=2, column=0, sticky="w")
        hint = ttk.Label(
            options,
            text="代理同时用于登录与短信服务。单账号超时包含登录、发送和收码；停止后先处理订单再退出。",
            style="Hint.TLabel",
            wraplength=250,
            justify=tk.LEFT,
        )
        hint.grid(row=19, column=0, sticky="ew")
        self.remember_key_var = tk.BooleanVar(value=True)
        self.remember_key_check = ttk.Checkbutton(options, text="在本机加密保存 Key / 代理", variable=self.remember_key_var)
        self.remember_key_check.grid(row=23, column=0, sticky="w", pady=(12, 0))
        self.human_var = tk.BooleanVar(value=True)
        self.human_check = ttk.Checkbutton(options, text="步骤等待（可随时停止）", variable=self.human_var)
        self.human_check.grid(row=21, column=0, sticky="w", pady=(6, 0))
        pace_row = ttk.Frame(options, style="Card.TFrame")
        pace_row.grid(row=22, column=0, sticky="ew", pady=(6, 0))
        ttk.Label(pace_row, text="等待倍数", style="Card.TLabel").pack(side=tk.LEFT)
        self.human_scale_var = tk.StringVar(value="1.0")
        ttk.Entry(pace_row, textvariable=self.human_scale_var, width=6, justify=tk.CENTER).pack(side=tk.RIGHT)

        self.phone_activity_tabs = SegmentedNotebook(outer)
        self.phone_activity_tabs.grid(row=2, column=0, sticky="nsew", padx=(0, 12), pady=(16, 0))
        activity = card(self.phone_activity_tabs, padding=16)
        self.phone_activity_tabs.add(activity, text="运行记录")
        activity.columnconfigure(0, weight=1)
        activity.rowconfigure(2, weight=1)
        ttk.Label(activity, text="运行记录", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        self.status_var = tk.StringVar(value="准备就绪")
        status_label = ttk.Label(activity, textvariable=self.status_var, style="Hint.TLabel", wraplength=480, justify=tk.LEFT)
        status_label.grid(row=1, column=0, sticky="ew", pady=(6, 8))
        activity.bind("<Configure>", lambda event: status_label.configure(wraplength=max(240, event.width - 34)))
        holder, self.log_text = self._make_text(activity, 6, tk.WORD, COLORS["log"], COLORS["log_text"], state=tk.DISABLED)
        holder.grid(row=2, column=0, sticky="nsew")

        self.price_catalog = PriceCatalogView(self.phone_activity_tabs, self._catalog_connection,
                                             self._apply_catalog_countries, lambda: self.max_price_var.get())
        self.phone_activity_tabs.add(self.price_catalog.frame, text="国家比价")
        self.max_price_var.trace_add("write", self.price_catalog.render)

    def _catalog_connection(self):
        if self.closing:
            raise ValueError("页面正在关闭")
        return self.api_key_var.get().strip(), self.current_proxy() or None

    def _apply_catalog_countries(self, codes, fallback):
        if self.running or self.closing:
            self.price_catalog.status.set("请等待接码任务结束后再修改国家")
            return
        if fallback:
            primary = parse_country_choice(self.country_var.get())
            for code in codes:
                if code != primary and code not in self._fallback_countries:
                    self._fallback_countries.append(code)
            self._refresh_fallback_countries()
            self._update_retry_hint()
            self.price_catalog.status.set("已加入备用国家；大重试次数和最高单价保持当前设置")
        else:
            self.country_var.set(country_label(codes[0]))
            self._fallback_countries = [code for code in self._fallback_countries if code != codes[0]]
            self._refresh_fallback_countries()
            self.price_catalog.status.set("已设置主国家；最高单价保持当前设置")
        self._save_settings()

    def _quote_inputs_changed(self, *_args) -> None:
        if not self._quote_ready:
            return
        self._quote_generation += 1
        self._quote_snapshot = None
        self.quote_status_var.set("国家或连接设置已变更，请读取当前报价。")

    def _update_quote_display(self, *_args) -> None:
        if not self._quote_snapshot:
            return
        country, offers, checked_at = self._quote_snapshot
        try:
            summary = price_summary(offers, country, self.max_price_var.get().strip())
        except ValueError as exc:
            summary = str(exc)
        if not self.auto_price_var.get():
            summary = "自动匹配已关闭；以下报价仅供参考。\n" + summary
        self.quote_status_var.set(f"{country_label(country)} · {checked_at}\n{summary}")

    def refresh_quotes(self) -> None:
        if self.closing or not self._quote_ready:
            return
        if self._quote_busy:
            self._quote_pending = True
            return
        key = self.api_key_var.get().strip()
        if not key:
            self.quote_status_var.set("请先填写 SMSBower API Key，再读取当前国家报价。")
            return
        try:
            country = parse_country_choice(self.country_var.get())
            proxy = self.current_proxy()
        except ValueError as exc:
            self.quote_status_var.set(str(exc))
            return
        self._quote_generation += 1
        generation = self._quote_generation
        self._quote_snapshot = None
        self._quote_busy = True
        self.refresh_quotes_btn.configure(state=tk.DISABLED)
        self.quote_status_var.set(f"正在读取 {country_label(country)} 的报价和库存…")
        self._quote_worker = threading.Thread(target=self._read_quotes_worker,
                                              args=(generation, country, key, proxy), daemon=True)
        try:
            self._quote_worker.start()
        except Exception:
            self._quote_busy = False
            self.refresh_quotes_btn.configure(state=tk.NORMAL)
            self.quote_status_var.set("报价查询未能启动，请重试。")

    def _read_quotes_worker(self, generation, country, key, proxy) -> None:
        # Read-only, bounded request. Worker never accesses Tk and can finish
        # harmlessly after this page closes. Credentials do not enter the queue.
        try:
            offers = SmsBowerClient(api_key=key, proxy=proxy or None).get_prices("dr", country, timeout=12)
            error = ""
        except (SmsBowerError, ValueError) as exc:
            offers, error = [], redact_diagnostic(str(exc), (key, proxy))
        except Exception as exc:
            offers, error = [], f"报价读取失败（{type(exc).__name__}），请稍后刷新"
        self.event_queue.put(("quotes", generation, country, offers, error))

    def _receive_quotes(self, generation, country, offers, error) -> None:
        self._quote_busy = False
        if self.closing or not self._quote_ready:
            return
        self.refresh_quotes_btn.configure(state=tk.NORMAL)
        if generation == self._quote_generation:
            if error:
                self.quote_status_var.set(error)
            else:
                self._quote_snapshot = (country, offers, datetime.now().strftime("%H:%M:%S"))
                self._update_quote_display()
        if self._quote_pending:
            self._quote_pending = False
            self.refresh_quotes()

    def _update_retry_hint(self, *_args) -> None:
        value = self.auto_retry_count_var.get().strip()
        switches = self.country_retry_count_var.get().strip()
        if value.isascii() and value.isdecimal() and switches.isascii() and switches.isdecimal():
            small, large = int(value), int(switches)
            inactive = "已添加备用国家，但大重试为 0，本轮不会换国。" if large == 0 and getattr(self, "_fallback_countries", []) else ""
            self.retry_hint_var.set(f"{inactive}每国首次尝试后重试 {small} 次，最多按已选列表顺序换国 {large} 次，共最多 {(small + 1) * (large + 1)} 次尝试。缺号、拒号、短信超时适用；风控或限流立即停止。全部尝试共用单账号超时。")
        else:
            self.retry_hint_var.set("大小重试次数均填写非负整数。备用国家不足时不能启动；次数或总时限耗尽后停止本批次。")

    def _refresh_fallback_countries(self, *_args) -> None:
        if not hasattr(self, "fallback_country_list"):
            return
        self.fallback_country_list.delete(0, tk.END)
        for code in self._fallback_countries:
            self.fallback_country_list.insert(tk.END, country_label(code))
        try:
            primary = parse_country_choice(self.country_var.get())
        except ValueError:
            primary = ""
        values = [value for value in country_dropdown_values()
                  if parse_country_choice(value) not in {primary, *self._fallback_countries}]
        self.fallback_country_combo.configure(values=values)
        if self.fallback_country_var.get() not in values:
            self.fallback_country_var.set(values[0] if values else "")
        self._update_retry_hint()

    def _add_fallback_country(self) -> None:
        try:
            code = parse_country_choice(self.fallback_country_var.get())
            primary = parse_country_choice(self.country_var.get())
        except ValueError as exc:
            messagebox.showerror(PHONE_TITLE, str(exc), parent=self.win)
            return
        if code == primary or code in self._fallback_countries:
            return
        self._fallback_countries.append(code)
        self._fallback_config_error = False
        self._refresh_fallback_countries()
        self.fallback_country_list.selection_set(tk.END)
        self.fallback_country_list.see(tk.END)

    def _remove_fallback_country(self) -> None:
        selected = self.fallback_country_list.curselection()
        if not selected:
            return
        self._fallback_countries.pop(selected[0])
        self._fallback_config_error = False
        self._refresh_fallback_countries()

    def _move_fallback_country(self, direction: int) -> None:
        selected = self.fallback_country_list.curselection()
        if not selected:
            return
        index = selected[0]
        target = index + direction
        if 0 <= target < len(self._fallback_countries):
            self._fallback_countries[index], self._fallback_countries[target] = self._fallback_countries[target], self._fallback_countries[index]
            self._refresh_fallback_countries()
            self.fallback_country_list.selection_set(target)
            self.fallback_country_list.see(target)

    def _set_placeholder(self) -> None:
        self.input_text.delete("1.0", tk.END)
        set_hint(self.input_text, "粘贴账号，或导入文件")
        self.placeholder_active = True

    def _clear_placeholder(self, _event=None) -> None:
        if self.placeholder_active:
            self.input_text.delete("1.0", tk.END)
            hide_hint(self.input_text)
            self.input_text.configure(fg=COLORS["text"])
            self.placeholder_active = False

    def _restore_placeholder(self, _event=None) -> None:
        if not self.input_text.get("1.0", "end-1c").strip():
            self._set_placeholder()

    def input_value(self) -> str:
        if self.placeholder_active:
            return ""
        return self.input_text.get("1.0", "end-1c")

    def set_input(self, content: str) -> None:
        self._input_sources = None
        self._imported_text = ""
        self.placeholder_active = False
        self.input_text.configure(fg=COLORS["text"])
        self.input_text.delete("1.0", tk.END)
        self.input_text.insert("1.0", content)
        hide_hint(self.input_text)

    def _append_log(self, line: str) -> None:
        line = redact_diagnostic(line, self._log_secrets)
        self.log_text.configure(state=tk.NORMAL)
        tag = "error" if any(word in line for word in ("失败", "熔断")) else "success" if "成功" in line else "warning" if any(word in line for word in ("等待", "重试")) else ""
        self.log_text.insert(tk.END, line.rstrip() + "\n", (tag,) if tag else ())
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)
        self.log_fn(line)

    def _load_settings(self) -> None:
        try:
            data = json.loads(PHONE_CONFIG_PATH.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return
        if not isinstance(data, dict):
            return
        self.api_key_var.set(_unprotect_setting(data.get("api_key") or ""))
        self.country_var.set(country_label(str(data.get("country") or "38")))
        self.max_reuse_var.set(str(data.get("max_reuse") or "3"))
        self.max_price_var.set(str(data.get("max_price", "0.06")))
        self.auto_price_var.set(data.get("auto_price_match", True) is True)
        self.timeout_var.set(str(data.get("timeout") or "180"))
        self.auto_retry_count_var.set(str(data.get("auto_retry_count", 2)))
        self.country_retry_count_var.set(str(data.get("country_retry_count", 0)))
        fallback = data.get("fallback_countries", [])
        self._fallback_config_error = not isinstance(fallback, list) or not all(isinstance(value, str) for value in fallback)
        self._fallback_countries = list(fallback) if not self._fallback_config_error else []
        self._refresh_fallback_countries()
        if self._fallback_config_error:
            self._append_log("已保存的备用国家配置无法识别，请重新添加备用国家后启动。")
        self.proxy_var.set(_unprotect_setting(data.get("proxy") or ""))
        self.proxy_scheme_var.set(str(data.get("proxy_scheme") or "HTTP").upper())
        mode = data.get("network_mode")
        if mode is None:
            mode = "custom" if data.get("use_proxy", bool(self.proxy_var.get().strip())) else "direct"
            if mode == "direct":
                self._append_log("旧接码配置已保留为「直连」。若手动 Chrome 使用 Windows 代理，请将网络模式改为「系统代理」。")
        self.network_mode_var.set(NETWORK_MODES.get(mode, "请选择网络模式") if isinstance(mode, str) else "请选择网络模式")
        # Existing configurations ran silently. New phone pages start visibly;
        # loading an old file keeps its historical mode until the user changes it.
        self.show_browser_var.set(bool(data.get("show_browser", False)))
        self.remember_key_var.set(bool(data.get("remember_key", True)))
        self.human_var.set(bool(data.get("human_pacing", True)))
        self.human_scale_var.set(str(data.get("human_scale") or "1.0"))
        if any(data.get(key) and not str(data[key]).startswith("dpapi:") for key in ("api_key", "proxy")):
            self._save_settings()

    def _save_settings(self) -> None:
        try:
            country = parse_country_choice(self.country_var.get())
        except ValueError:
            # Loading an old config must still migrate its credentials even if
            # its country is no longer supported. Preserve the invalid choice
            # so start() requires a deliberate selection instead of buying in
            # a silently substituted country.
            country = self.country_var.get()
            self._append_log("已保存的国家无法识别，请重新从列表选择后开始接码。")
        try:
            network_mode = self.current_network_mode()
        except ValueError:
            network_mode = "invalid"
        payload = {
            "api_key": _protect_setting(self.api_key_var.get().strip()) if self.remember_key_var.get() else "",
            "country": country,
            "max_reuse": self.max_reuse_var.get().strip() or "3",
            "max_price": self.max_price_var.get().strip(),
            "auto_price_match": self.auto_price_var.get(),
            "timeout": self.timeout_var.get().strip() or "180",
            "auto_retry_count": self.auto_retry_count_var.get().strip(),
            "country_retry_count": self.country_retry_count_var.get().strip(),
            "fallback_countries": list(self._fallback_countries),
            "proxy": _protect_setting(self.proxy_var.get().strip()) if self.remember_key_var.get() else "",
            "proxy_scheme": self.proxy_scheme_var.get().lower(),
            "network_mode": network_mode,
            "show_browser": self.show_browser_var.get(),
            "remember_key": self.remember_key_var.get(),
            "human_pacing": self.human_var.get(),
            "human_scale": self.human_scale_var.get().strip() or "1.0",
        }
        if self.remember_key_var.get() and self.api_key_var.get().strip() and not payload["api_key"]:
            self._append_log("Key 加密保存不可用，本次仅在内存中使用；下次启动需重新填写。")
        try:
            PHONE_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
            temporary = PHONE_CONFIG_PATH.with_suffix(PHONE_CONFIG_PATH.suffix + ".tmp")
            temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            temporary.replace(PHONE_CONFIG_PATH)
        except (OSError, UnicodeError) as exc:
            self._append_log(f"设置保存失败：{type(exc).__name__}")

    def _proxy_edited(self, *_args) -> None:
        if self.proxy_var.get().strip():
            self.network_mode_var.set(NETWORK_MODES["custom"])

    def current_network_mode(self) -> str:
        for mode, label in NETWORK_MODES.items():
            if self.network_mode_var.get() == label:
                return mode
        raise ValueError("请选择系统代理、直连或自定义代理。")

    def _human_options(self) -> dict:
        """Pacing options for the phone batch (JSON-serializable for reports)."""
        scale = validate_scale(self.human_scale_var.get().strip() or "1.0")
        return {"enabled": bool(self.human_var.get()), "scale": scale, "typing": True}

    def _network_mode_changed(self, *_args) -> None:
        try:
            mode = self.current_network_mode()
        except ValueError:
            mode = ""
        self.proxy_entry.configure(state=tk.NORMAL if mode == "custom" else tk.DISABLED)
        self.proxy_scheme_combo.configure(state="readonly" if mode == "custom" else tk.DISABLED)
        self.network_hint_var.set(NETWORK_HINTS.get(mode, "请选择有效的网络模式后再开始。"))
        self._quote_inputs_changed()

    def current_proxy(self) -> str:
        return resolve_phone_proxy(self.current_network_mode(), self.proxy_var.get(), self.proxy_scheme_var.get().lower())

    def current_settings(self) -> SmsbowerSettings:
        retry_count_text = self.auto_retry_count_var.get().strip()
        if not retry_count_text.isascii() or not retry_count_text.isdecimal():
            raise ValueError("自动重试次数必须是非负整数（0 表示不重试）")
        auto_retry_count = int(retry_count_text)
        country_retry_text = self.country_retry_count_var.get().strip()
        if not country_retry_text.isascii() or not country_retry_text.isdecimal():
            raise ValueError("大重试次数必须是非负整数（0 表示不换国家）")
        country_retry_count = int(country_retry_text)
        primary_country = parse_country_choice(self.country_var.get())
        if self._fallback_config_error:
            raise ValueError("备用国家配置无效，请重新添加备用国家")
        fallback_countries = []
        for value in self._fallback_countries:
            code = parse_country_choice(value)
            if code == primary_country or code in fallback_countries:
                raise ValueError("备用国家不能重复，也不能与接码国家相同，请从列表移除重复项")
            fallback_countries.append(code)
        if country_retry_count > len(fallback_countries):
            raise ValueError(f"大重试设为 {country_retry_count} 次，请至少添加 {country_retry_count} 个不同的备用国家")
        try:
            max_reuse = int(self.max_reuse_var.get().strip() or "3")
            timeout = int(self.timeout_var.get().strip() or "180")
        except ValueError as exc:
            raise ValueError("绑定数量和超时必须是整数") from exc
        if max_reuse < 1:
            raise ValueError("一号最多绑定账号数至少为 1")
        if timeout < 30:
            raise ValueError("超时时间必须不小于 30 秒")
        max_price = self.max_price_var.get().strip()
        if max_price:
            try:
                price = Decimal(max_price)
                if not price.is_finite() or price <= 0:
                    raise InvalidOperation
            except InvalidOperation as exc:
                raise ValueError("最高单价必须是大于 0 的数字，或留空不限制") from exc
        return SmsbowerSettings(
            api_key=self.api_key_var.get().strip(),
            country=primary_country,
            max_reuse=max_reuse,
            max_price=max_price,
            sms_timeout=timeout,
            number_attempts=auto_retry_count + 1,
            country_retry_count=country_retry_count,
            fallback_countries=fallback_countries,
            proxy=self.current_proxy(),
            network_source=self.current_network_mode(),
            auto_price_match=self.auto_price_var.get(),
        )

    def load_file(self) -> None:
        paths = filedialog.askopenfilenames(
            parent=self.win,
            title="选择账号文件",
            filetypes=[("JSON/文本", "*.json *.txt"), ("全部文件", "*.*")],
        )
        if not paths:
            return
        chunks: list[str] = []
        sources: list[tuple[str, str]] = []
        errors: list[str] = []
        for path in paths:
            try:
                content = Path(path).read_text(encoding="utf-8-sig")
                chunks.append(content)
                sources.append((Path(path).name, content))
            except (OSError, UnicodeError) as exc:
                errors.append(f"{Path(path).name}: {type(exc).__name__}")
        if not chunks:
            messagebox.showerror(PHONE_TITLE, "无法读取所选文件：\n" + "\n".join(errors), parent=self.win)
            return
        self.set_input("\n\n".join(chunks))
        self._input_sources = sources
        self._imported_text = self.input_value()
        if errors:
            messagebox.showwarning(PHONE_TITLE, "以下文件无法读取，已跳过：\n" + "\n".join(errors), parent=self.win)
        self.status_var.set(f"已载入 {len(chunks)}/{len(paths)} 个文件")

    def load_dir(self) -> None:
        folder = filedialog.askdirectory(parent=self.win, title="选择账号目录")
        if not folder:
            return
        files = sorted(Path(folder).glob("*.json")) + sorted(Path(folder).glob("*.txt"))
        if not files:
            messagebox.showerror(PHONE_TITLE, "目录里没有 JSON/TXT", parent=self.win)
            return
        chunks: list[str] = []
        sources: list[tuple[str, str]] = []
        errors: list[str] = []
        for path in files:
            try:
                content = path.read_text(encoding="utf-8-sig")
                chunks.append(content)
                sources.append((path.name, content))
            except (OSError, UnicodeError) as exc:
                errors.append(f"{path.name}: {type(exc).__name__}")
        if not chunks:
            messagebox.showerror(PHONE_TITLE, "目录文件均无法读取：\n" + "\n".join(errors), parent=self.win)
            return
        self.set_input("\n\n".join(chunks))
        self._input_sources = sources
        self._imported_text = self.input_value()
        if errors:
            messagebox.showwarning(PHONE_TITLE, "以下文件无法读取，已跳过：\n" + "\n".join(errors), parent=self.win)
        self.status_var.set(f"已载入目录 {len(chunks)}/{len(files)} 个文件")

    def start(self) -> None:
        if self.running or self.closing or (self.worker is not None and self.worker.is_alive()):
            return
        try:
            if self._input_sources is None or self._imported_text != self.input_value():
                jobs = parse_phone_jobs(self.input_value())
            else:
                jobs = []
                source_errors = []
                for name, content in self._input_sources:
                    try:
                        jobs.extend(parse_phone_jobs(content))
                    except ValueError as exc:
                        source_errors.append(f"{name}: {exc}")
                if not jobs:
                    detail = "\n  ".join(source_errors) if source_errors else "没有识别到账号"
                    raise ValueError(detail)
                if source_errors:
                    messagebox.showwarning(PHONE_TITLE, "以下文件无法识别，已跳过：\n  " + "\n  ".join(source_errors), parent=self.win)
            settings = self.current_settings()
            human_options = self._human_options()
        except ValueError as exc:
            messagebox.showerror(PHONE_TITLE, str(exc), parent=self.win)
            return
        if not settings.api_key:
            messagebox.showerror(PHONE_TITLE, "请填写 SMSBower API Key", parent=self.win)
            return
        missing = [job.email for job in jobs if not job.password and not job.mailbox_url]
        if missing:
            messagebox.showwarning(
                PHONE_TITLE,
                "这些账号没有登录密码，接码时可能无法过密码页：\n" + "\n".join(missing[:8]),
                parent=self.win,
            )
        if not _TASK_LOCK.acquire(blocking=False):
            messagebox.showwarning(PHONE_TITLE, "另一个授权或自动接码任务正在运行，请等待它完成后再启动。", parent=self.win)
            return
        self._task_lock_held = True
        self._log_secrets = (settings.api_key, settings.proxy) + tuple(value for job in jobs for value in (job.password, job.totp_secret, job.mailbox_url) if value)
        self._save_settings()
        self.stop_flag.clear()
        self.running = True
        present_running(self, "phone", True)
        self.start_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL)
        self.status_var.set(f"开始接码 {len(jobs)} 个账号")
        self._append_log(f"开始自动接码：{len(jobs)} 个账号，一号最多绑 {settings.max_reuse} 个；每国自动重试 {settings.number_attempts - 1} 次，大重试换国 {settings.country_retry_count} 次，全部耗尽则熔断停止本批次")
        countries = [settings.country] + settings.fallback_countries[:settings.country_retry_count]
        self._append_log("本轮国家顺序：" + " → ".join(country_label(code) for code in countries))
        self._append_log("已有有效号码优先复用，含备用国家号码；用尽后按国家顺序买号。")
        if settings.auto_price_match:
            self._append_log("价格匹配：每次买号读取当前国家报价，选择限价内最低价；报价缺号时在原重试预算内匹配下一档。")
        timeout = int(self.timeout_var.get().strip() or "180")
        silent = not self.show_browser_var.get()
        network = network_description(settings.network_source, settings.proxy)
        price = f"${settings.max_price}" if settings.max_price else "不限价"
        self._append_log(f"本轮条件：{country_label(settings.country)}；最高单价 {price}；{network}；{'静默' if silent else '可见'}浏览器（优先 {'Edge' if silent else 'Chrome'}，使用浏览器原生版本信息）")
        if human_options.get("enabled"):
            self._append_log(f"人工节奏：已启用（倍数 {human_options.get('scale')}），每步随机等待。")
        else:
            self._append_log("人工节奏：已关闭，按最快速度执行。")
        if settings.fallback_countries and settings.country_retry_count == 0:
            self._append_log("已配置备用国家，但大重试为 0，本轮只使用首选国家。")
        self.worker = threading.Thread(
            target=self._run_worker,
            args=(jobs, settings, timeout, silent, human_options),
            daemon=False,
        )
        try:
            self.worker.start()
        except Exception:
            self._task_lock_held = False
            _TASK_LOCK.release()
            self.running = False
            present_running(self, "phone", False)
            self.start_btn.configure(state=tk.NORMAL)
            self.stop_btn.configure(state=tk.DISABLED)
            raise

    def stop(self) -> None:
        self.stop_flag.set()
        self.status_var.set("正在停止…")
        self._append_log("已请求停止接码")

    def _run_worker(self, jobs, settings, timeout, silent, human_options=None) -> None:
        set_log_callback(lambda line: self.event_queue.put(("log", line)))
        try:
            results = run_batch_phone_verify(
                jobs,
                settings,
                timeout=float(timeout),
                headless=silent,
                should_stop=self.stop_flag.is_set,
                on_progress=lambda index, total, result: self.event_queue.put(("progress", index, total, result)),
                recovery_dir=TOOL_DIR / "recovery",
                human_options=human_options,
            )
            # Keep full results on the UI thread.  OAuth success and phone
            # binding success are separate states; counting ``result.ok`` here
            # used to report accounts that never went through add-phone.
            self.event_queue.put(("done", results, len(jobs)))
        except Exception as exc:
            self.event_queue.put(("fail", str(exc)))
        finally:
            set_log_callback(None)
            if self._task_lock_held:
                self._task_lock_held = False
                _TASK_LOCK.release()

    def _drain(self) -> None:
        self.price_catalog.drain()
        while True:
            try:
                event = self.event_queue.get_nowait()
            except queue.Empty:
                break
            if event[0] == "quotes":
                self._receive_quotes(*event[1:])
            elif event[0] == "log":
                self._append_log(event[1])
            elif event[0] == "progress":
                _, index, total, result = event
                status = getattr(result, "phone_status", None)
                if getattr(result, "category", "") == "circuit_open":
                    label = "接码失败，已熔断"
                elif getattr(result, "category", "") == "phone_fraud":
                    label = "服务端风控，已熔断"
                elif status in {"bound", "success", "verified"}:
                    label = "补绑成功"
                elif getattr(result, "ok", False):
                    label = "OAuth完成，未确认补绑"
                else:
                    label = "失败"
                self.status_var.set(f"{index}/{total} {getattr(result, 'email', '')} {label}")
            elif event[0] == "done":
                self.running = False
                present_running(self, "phone", False)
                self.start_btn.configure(state=tk.NORMAL)
                self.stop_btn.configure(state=tk.DISABLED)
                results, total = event[1], event[2]
                self.last_results = list(results)
                bound = 0
                oauth_only = 0
                failed = 0
                cancelled = 0
                circuit_reason = ""
                for result in results:
                    if getattr(result, "category", "") == "circuit_open":
                        circuit_reason = getattr(result, "error", "") or "重试次数或接码时限已耗尽"
                    elif getattr(result, "category", "") == "phone_fraud":
                        circuit_reason = "OpenAI 风控拒绝（fraud_guard），不再自动换号"
                    status = getattr(result, "phone_status", None)
                    if status in {"bound", "success", "verified", "completed"}:
                        bound += 1
                    elif status == "cancelled" or getattr(result, "category", "") == "cancelled":
                        cancelled += 1
                    elif getattr(result, "ok", False):
                        oauth_only += 1
                    else:
                        failed += 1
                pending = max(total - len(results), 0)
                self.status_var.set(
                    ("已熔断 · " if circuit_reason else "")
                    + f"补绑 {bound} · 未补绑 {oauth_only} · 失败 {failed} · 取消 {cancelled} · 未处理 {pending}"
                )
                if circuit_reason:
                    self._append_log(f"{circuit_reason}，已熔断并停止本批次；剩余 {pending} 个账号未处理。")
                if any(getattr(result, "category", "") == "phone_fraud" for result in results):
                    self._append_log("fraud_guard 是 OpenAI 拒绝手机验证请求，具体触发条件未确认。请对照手动成功时的网络模式、号码国家/价格和浏览器显示模式；手动收到短信不代表已完成绑定。错误中的发送/验证阶段及 HTTP 状态可用于定位。")
                self._append_log(f"接码结果：实际补绑成功 {bound} 个；OAuth完成未补绑 {oauth_only} 个；失败 {failed} 个；取消 {cancelled} 个；未处理 {pending} 个")
                if self.closing:
                    self.start_btn.configure(state=tk.DISABLED)
                    return
            elif event[0] == "fail":
                self.running = False
                present_running(self, "phone", False)
                self.start_btn.configure(state=tk.DISABLED if self.closing else tk.NORMAL)
                self.stop_btn.configure(state=tk.DISABLED)
                self.status_var.set("运行失败")
                message = redact_diagnostic(event[1], self._log_secrets)
                self._append_log(f"接码运行失败：{message}")
                if not self.closing:
                    messagebox.showerror(PHONE_TITLE, message, parent=self.win)
        self._schedule_drain()


def main() -> int:
    root = tk.Tk()
    ReauthApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        try:
            import tkinter as _tk
            from tkinter import messagebox as _mb
            fail = _tk.Tk()
            fail.withdraw()
            _mb.showerror("OpenAI 批量重新授权", f"窗口启动失败：\n{exc}\n\n{traceback.format_exc()}")
            fail.destroy()
        except Exception:
            Path(__file__).with_name("gui-error.log").write_text(traceback.format_exc(), encoding="utf-8")
        raise SystemExit(1)
