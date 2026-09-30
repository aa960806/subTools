"""In-window sub2api pool push UI. Workers only communicate through a queue."""

from __future__ import annotations

import json
import queue
import threading
import time
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
import tkinter as tk
from urllib.parse import unquote, urlsplit

from openai_reauth import TOOL_DIR, redact_diagnostic, set_log_callback
from pool_client import PoolClient, PoolError, PoolSettings, parse_model_whitelist, normalize_site
from pool_flow import load_push_files, parse_push_text, run_pool_push
from account_inputs import login_mapping
from pool_recovery import PoolJournal
from pool_inspection import inspect_pool, inspection_delta
from task_views import TableFilter
from pool_model_picker import ModelPicker
from reauth_formats import _atomic_write_json
from reauth_ui import COLORS, card, text_area, brand_mark, scroll_settings, page_header, SegmentedNotebook, AutoScrollbar, DataTable, secret_field, json_highlight, set_hint, hide_hint, present_running

TITLE = "自动推池"
CONFIG_PATH = TOOL_DIR / "pool_push.json"
MODEL_MODES = {"preserve": "沿用输入账号配置", "replace": "设置模型白名单", "clear": "清除模型限制"}
SCHEDULING_MODES = {"override": "使用本次优先级与并发", "preserve": "保留原优先级与并发"}
PROXY_DEFAULTS = ("保留后台代理", "直连（清除绑定）")
STATE_LABELS = {
    "ready": "待处理", "pushing": "推送中", "created": "已新增", "updated": "已更新",
    "phone_required": "待补手机", "needs_interaction": "需人工验证", "not_processed": "未处理",
    "uncertain": "结果待核对", "cancelled": "已停止", "rate_limited": "已限流", "expired": "已过期",
    "identity": "身份待核对", "pending": "需核对前次写入",
    "models": "模型设置冲突",
    "refreshing": "刷新中", "refresh_failed": "刷新失败待选择", "refresh_unknown": "刷新待核对",
    "refresh_unsent": "刷新尚未发送", "deferred": "已暂缓",
}


class PoolPushWindow:
    def __init__(self, master, *, on_back, task_lock, protect, unprotect, auth_options, config_path=None, on_phone_inputs=None):
        self.win = ttk.Frame(master, style="App.TFrame")
        self.on_back, self.task_lock = on_back, task_lock
        self.protect, self.unprotect, self.auth_options = protect, unprotect, auth_options
        self.config_path = Path(config_path) if config_path is not None else CONFIG_PATH
        self.on_phone_inputs = on_phone_inputs
        self._recovery_path = None
        self._restored_site = ""
        self._proxies = []
        self._saved_proxy_id = None
        self._saved_proxy_connection = ""
        self._inspection_report = None
        self._inspect_due = None
        self._inspect_interval = 0
        self._relogin_ids = ()
        self.worker = None
        self.stop_flag = threading.Event()
        self.events = queue.Queue()
        self.running = False
        self.closing = False
        self._busy = ""
        self._last_error = ""
        self._lock_held = False
        self._after_id = None
        self._connected_id = ""
        self._saved_group_connection = ""
        self._saved_group_ids = []
        self._groups = []
        self._model_sources = []
        self._saved_source_connection = ""
        self._saved_source_id = None
        self._parsed_text = None
        self.jobs = []
        self._build()
        self._load_settings()
        self._schedule()

    def _build(self):
        outer = ttk.Frame(self.win, style="App.TFrame", padding=(24, 20, 24, 16))
        outer.pack(fill=tk.BOTH, expand=True)
        outer.columnconfigure(0, weight=1)
        outer.columnconfigure(1, minsize=320)
        outer.rowconfigure(1, weight=2, minsize=230)
        outer.rowconfigure(2, weight=3, minsize=160)
        header = page_header(outer, "推送到池", "连接 sub2api，将账号导入指定分组。", "数据管理")
        header.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 16))
        if not hasattr(self.win.winfo_toplevel(), "_reauth_navigation"):
            ttk.Button(header, text="← 返回批量授权", command=self.on_back, style="Secondary.TButton").pack(side=tk.RIGHT)

        source = card(outer, padding=14)
        source.grid(row=1, column=0, sticky="nsew", padx=(0, 12), pady=(0, 10))
        source.columnconfigure(0, weight=1)
        source.rowconfigure(2, weight=1)
        toolbar = ttk.Frame(source, style="Card.TFrame")
        toolbar.grid(row=0, column=0, sticky="ew")
        ttk.Label(toolbar, text="账号输入", style="Section.TLabel").pack(side=tk.LEFT)
        self.file_btn = ttk.Button(toolbar, text="导入文件", command=self.load_files, style="Ghost.TButton")
        self.file_btn.pack(side=tk.RIGHT)
        self.dir_btn = ttk.Button(toolbar, text="导入目录", command=self.load_dir, style="Ghost.TButton")
        self.dir_btn.pack(side=tk.RIGHT, padx=4)
        ttk.Label(source, text="账号行 / sub2 / CPA / Session / 9router", style="Hint.TLabel", wraplength=560).grid(row=1, column=0, sticky="w", pady=(8, 8))
        holder, self.input_text = text_area(source, height=5)
        holder.grid(row=2, column=0, sticky="nsew")
        self.input_text.bind("<Control-a>", lambda e: (e.widget.tag_add("sel", "1.0", "end-1c"), "break")[1])
        actions = ttk.Frame(source, style="Card.TFrame")
        actions.grid(row=3, column=0, sticky="ew", pady=(10, 0))
        self.preview_btn = ttk.Button(actions, text="识别", command=self.preview, style="Secondary.TButton")
        self.preview_btn.pack(side=tk.LEFT)
        self.start_btn = ttk.Button(actions, text="开始推送", command=self.start, style="Primary.TButton")
        self.start_btn.pack(side=tk.LEFT, padx=12)
        self.stop_btn = ttk.Button(actions, text="停止", command=self.stop, state=tk.DISABLED, style="Danger.TButton")
        self.stop_btn.pack(side=tk.LEFT)
        self.restore_btn = ttk.Button(actions, text="恢复任务", command=self.restore_task, style="Ghost.TButton")
        self.restore_btn.pack(side=tk.RIGHT)

        self.result_tabs = SegmentedNotebook(outer)
        self.result_tabs.grid(row=2, column=0, sticky="nsew", padx=(0, 12))
        table = card(self.result_tabs, padding=12)
        self.result_tabs.add(table, text="处理结果")
        table.rowconfigure(2, weight=1)
        table.columnconfigure(0, weight=1)
        self.summary_var = tk.StringVar(master=self.win, value="等待录入账号")
        result_header = ttk.Frame(table, style="Card.TFrame")
        result_header.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ttk.Label(result_header, textvariable=self.summary_var, style="Hint.TLabel").pack(side=tk.LEFT)
        self.retry_btn = ttk.Button(result_header, text="重试失败", command=self.retry_failed, state=tk.DISABLED, style="Ghost.TButton")
        self.retry_btn.pack(side=tk.RIGHT)
        self.phone_btn = ttk.Button(result_header, text="转到接码", command=self.send_to_phone, style="Ghost.TButton", state=tk.DISABLED)
        self.phone_btn.pack(side=tk.RIGHT, padx=4)
        self.tree = DataTable(table, empty_text="识别账号后，处理结果将在这里显示", columns=("email", "state", "id", "message"), show="headings", height=5)
        for key, label, width in (("email", "账号", 200), ("state", "状态", 95), ("id", "后台 ID", 70), ("message", "处理结果", 300)):
            self.tree.heading(key, text=label)
            self.tree.column(key, width=width, minwidth=60)
        sy = AutoScrollbar(table, orient=tk.VERTICAL, command=self.tree.yview, content_widget=self.tree)
        sx = AutoScrollbar(table, orient=tk.HORIZONTAL, command=self.tree.xview, content_widget=self.tree)
        self.tree.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        self.tree.grid(row=2, column=0, sticky="nsew")
        sy.grid(row=2, column=1, sticky="ns")
        sx.grid(row=3, column=0, sticky="ew")
        self.result_filter = TableFilter(table, self.tree)
        self.result_filter.frame.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        selected_actions = ttk.Frame(table, style="Card.TFrame")
        selected_actions.grid(row=4, column=0, sticky="ew", pady=(6, 0))
        self.selected_retry_btn = ttk.Button(selected_actions, text="重试选中", command=self.retry_selected, style="Ghost.TButton")
        self.selected_retry_btn.pack(side=tk.LEFT)
        self.defer_btn = ttk.Button(selected_actions, text="暂缓 / 恢复选中", command=self.defer_selected, style="Ghost.TButton")
        self.defer_btn.pack(side=tk.LEFT, padx=8)
        logs = card(self.result_tabs, padding=10)
        self.result_tabs.add(logs, text="运行日志")
        holder, self.log_text = text_area(logs, height=3, wrap=tk.WORD, bg=COLORS["log"], fg=COLORS["log_text"], state=tk.DISABLED)
        holder.pack(fill=tk.BOTH, expand=True)

        self.inspection_tab = card(self.result_tabs, padding=12)
        self.result_tabs.add(self.inspection_tab, text="只读巡检")
        self.inspection_tab.columnconfigure(0, weight=1)
        self.inspection_tab.rowconfigure(3, weight=1)
        inspection_header = ttk.Frame(self.inspection_tab, style="Card.TFrame")
        inspection_header.grid(row=0, column=0, sticky="ew")
        self.inspect_btn = ttk.Button(inspection_header, text="读取号池状态", command=self.inspect, style="Secondary.TButton")
        self.inspect_btn.pack(side=tk.LEFT)
        self.inspect_export_btn = ttk.Button(inspection_header, text="导出巡检报告", command=self.export_inspection, style="Ghost.TButton", state=tk.DISABLED)
        self.inspect_export_btn.pack(side=tk.RIGHT)
        timer_bar = ttk.Frame(self.inspection_tab, style="Card.TFrame")
        timer_bar.grid(row=1, column=0, sticky="ew", pady=(6, 0))
        self.inspect_interval_var = tk.StringVar(master=self.win, value="15")
        ttk.Label(timer_bar, text="每", style="Hint.TLabel").pack(side=tk.LEFT)
        ttk.Entry(timer_bar, textvariable=self.inspect_interval_var, width=4).pack(side=tk.LEFT, padx=4)
        ttk.Label(timer_bar, text="分钟", style="Hint.TLabel").pack(side=tk.LEFT)
        self.inspect_timer_btn = ttk.Button(timer_bar, text="启用定时", command=self.toggle_inspection_timer, style="Ghost.TButton")
        self.inspect_timer_btn.pack(side=tk.LEFT, padx=6)
        self.inspect_timer_var = tk.StringVar(master=self.win, value="定时未启用")
        ttk.Label(timer_bar, textvariable=self.inspect_timer_var, style="Hint.TLabel").pack(side=tk.RIGHT)
        self.inspection_var = tk.StringVar(master=self.win, value="检查所选分组；未选分组时检查全部。仅读取状态，不重登、不刷新。")
        ttk.Label(self.inspection_tab, textvariable=self.inspection_var, style="Hint.TLabel", wraplength=550).grid(row=2, column=0, sticky="ew", pady=8)
        self.inspection_tree = DataTable(self.inspection_tab, columns=("id", "email", "issues"), show="headings", height=5,
                                         empty_text="连接后台后，点击读取号池状态")
        for key, title, width in (("id", "后台 ID", 65), ("email", "账号", 210), ("issues", "检查结果", 270)):
            self.inspection_tree.heading(key, text=title)
            self.inspection_tree.column(key, width=width, minwidth=55)
        self.inspection_tree.grid(row=3, column=0, sticky="nsew")
        sy = AutoScrollbar(self.inspection_tab, orient=tk.VERTICAL, command=self.inspection_tree.yview, content_widget=self.inspection_tree)
        sx = AutoScrollbar(self.inspection_tab, orient=tk.HORIZONTAL, command=self.inspection_tree.xview, content_widget=self.inspection_tree)
        self.inspection_tree.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        sy.grid(row=3, column=1, sticky="ns")
        sx.grid(row=4, column=0, sticky="ew")

        panel = card(outer, padding=0)
        panel.grid(row=1, column=1, rowspan=2, sticky="nsew")
        panel.columnconfigure(0, weight=1)
        panel.rowconfigure(0, weight=1)
        self.settings_tabs = SegmentedNotebook(panel)
        self.settings_tabs.grid(row=0, column=0, sticky="nsew")
        tab, settings, self.options_canvas = scroll_settings(self.settings_tabs, width=308)
        self.settings_tabs.add(tab, text="连接")
        tab, assignment_settings, self.assignment_canvas = scroll_settings(self.settings_tabs, width=308)
        self.settings_tabs.add(tab, text="分组")
        tab, model_settings, self.model_canvas = scroll_settings(self.settings_tabs, width=308)
        self.settings_tabs.add(tab, text="模型")
        ttk.Label(settings, text="sub2api 后台", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        self.site_var = tk.StringVar(master=self.win)
        self.auth_kind_var = tk.StringVar(master=self.win, value="管理员 API Key")
        self.secret_var = tk.StringVar(master=self.win)
        self.priority_var = tk.StringVar(master=self.win, value="50")
        self.concurrency_var = tk.StringVar(master=self.win, value="3")
        self.scheduling_var = tk.StringVar(master=self.win, value=SCHEDULING_MODES["override"])
        self.backend_proxy_var = tk.StringVar(master=self.win, value=PROXY_DEFAULTS[0])
        self.load_factor_var = tk.StringVar(master=self.win)
        self.timeout_var = tk.StringVar(master=self.win, value="180")
        self.remember_var = tk.BooleanVar(master=self.win, value=True)
        self.show_browser_var = tk.BooleanVar(master=self.win, value=False)
        self.model_mode_var = tk.StringVar(master=self.win, value=MODEL_MODES["preserve"])
        self._controls = []
        def entry(row, label, variable, **kwargs):
            ttk.Label(settings, text=label, style="Card.TLabel").grid(row=row, column=0, sticky="w", pady=(10, 4))
            widget = ttk.Entry(settings, textvariable=variable, **kwargs)
            widget.grid(row=row+1, column=0, sticky="ew")
            self._controls.append((widget, "normal"))
            return widget
        entry(1, "站点地址", self.site_var)
        self.auth_combo = ttk.Combobox(settings, textvariable=self.auth_kind_var, values=("管理员 API Key", "管理员访问令牌"), state="readonly")
        self.auth_combo.grid(row=3, column=0, sticky="ew", pady=(10, 4))
        self._controls.append((self.auth_combo, "readonly"))
        self.secret_entry = entry(4, "管理员凭据", self.secret_var, show="•")
        remember = ttk.Checkbutton(settings, text="在本机加密记住凭据", variable=self.remember_var)
        remember.grid(row=6, column=0, sticky="w", pady=6)
        self._controls.append((remember, "normal"))
        self.connect_btn = ttk.Button(settings, text="连接并加载分组", command=self.connect, style="Secondary.TButton")
        self.connect_btn.grid(row=7, column=0, sticky="ew")
        self.connection_var = tk.StringVar(master=self.win, value="尚未连接")
        ttk.Label(settings, textvariable=self.connection_var, style="Hint.TLabel", wraplength=270).grid(row=8, column=0, sticky="w", pady=(6, 0))
        settings = assignment_settings
        ttk.Label(settings, text="分组与账号配置", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(settings, text="目标分组（可多选）", style="Card.TLabel").grid(row=9, column=0, sticky="w", pady=(10, 5))
        group_frame = ttk.Frame(settings, style="Card.TFrame")
        group_frame.grid(row=10, column=0, sticky="ew")
        self.group_list = tk.Listbox(group_frame, selectmode=tk.MULTIPLE, exportselection=False, height=5,
                                     bg=COLORS["soft"], fg=COLORS["text"], highlightthickness=0,
                                     selectbackground=COLORS["selected"], selectforeground=COLORS["text"], relief="flat", borderwidth=0)
        groups_scroll = AutoScrollbar(group_frame, orient=tk.VERTICAL, command=self.group_list.yview)
        self.group_list.configure(yscrollcommand=groups_scroll.set)
        groups_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.group_list.pack(fill=tk.BOTH, expand=True)
        self._controls.append((self.group_list, "normal"))
        entry(11, "优先级（数值越小越优先）", self.priority_var)
        entry(13, "每个后台账号的并发数", self.concurrency_var)
        schedule = ttk.Combobox(settings, textvariable=self.scheduling_var, values=tuple(SCHEDULING_MODES.values()), state="readonly")
        schedule.grid(row=15, column=0, sticky="ew", pady=(8, 4))
        self._controls.append((schedule, "readonly"))
        ttk.Label(settings, text="保留模式：更新时沿用后台值；新增时沿用输入值，缺失则用上方设置。", style="Hint.TLabel", wraplength=265).grid(row=16, column=0, sticky="w")
        ttk.Label(settings, text="后台账号代理（模型请求出口）", style="Card.TLabel").grid(row=17, column=0, sticky="w", pady=(12, 4))
        self.backend_proxy_combo = ttk.Combobox(settings, textvariable=self.backend_proxy_var, values=PROXY_DEFAULTS, state="readonly")
        self.backend_proxy_combo.grid(row=18, column=0, sticky="ew")
        self._controls.append((self.backend_proxy_combo, "readonly"))
        self.proxy_load_btn = ttk.Button(settings, text="加载后台代理", command=self.load_proxies, style="Ghost.TButton")
        self.proxy_load_btn.grid(row=19, column=0, sticky="ew", pady=4)
        entry(20, "负载系数（留空保留，0 恢复默认）", self.load_factor_var)
        settings = model_settings
        ttk.Label(settings, text="模型访问范围", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(settings, text="账号模型限制", style="Card.TLabel").grid(row=15, column=0, sticky="w", pady=(10, 4))
        model_combo = ttk.Combobox(settings, textvariable=self.model_mode_var, values=tuple(MODEL_MODES.values()), state="readonly")
        model_combo.grid(row=16, column=0, sticky="ew")
        self._controls.append((model_combo, "readonly"))
        self.model_holder = ttk.Frame(settings, style="Card.TFrame")
        self.model_holder.columnconfigure(0, weight=1)
        self.model_holder.grid(row=17, column=0, sticky="ew", pady=(6, 0))
        ttk.Label(self.model_holder, text="同步来源（后台 OpenAI OAuth 账号）", style="Hint.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 4))
        self.model_source_var = tk.StringVar(master=self.win)
        self.model_source_combo = ttk.Combobox(self.model_holder, textvariable=self.model_source_var, state="readonly")
        self.model_source_combo.grid(row=1, column=0, sticky="ew")
        self.model_source_combo.bind("<<ComboboxSelected>>", self._model_source_changed)
        sync_actions = ttk.Frame(self.model_holder, style="Card.TFrame")
        sync_actions.grid(row=2, column=0, sticky="ew", pady=5)
        self.model_load_btn = ttk.Button(sync_actions, text="加载来源账号", style="Ghost.TButton", command=self.load_model_sources)
        self.model_load_btn.pack(side=tk.LEFT)
        self.model_sync_btn = ttk.Button(sync_actions, text="同步上游模型", style="Ghost.TButton", command=self.sync_upstream_models)
        self.model_sync_btn.pack(side=tk.RIGHT)
        self.model_sync_var = tk.StringVar(master=self.win, value="连接后台后加载来源账号；也可手动添加模型。")
        ttk.Label(self.model_holder, textvariable=self.model_sync_var, style="Hint.TLabel", wraplength=265).grid(row=3, column=0, sticky="w", pady=(0, 5))
        self.model_picker = ModelPicker(self.model_holder)
        self.model_picker.grid(row=4, column=0, sticky="ew")
        self.model_hint_var = tk.StringVar(master=self.win)
        ttk.Label(settings, textvariable=self.model_hint_var, style="Hint.TLabel", wraplength=265).grid(row=19, column=0, sticky="w", pady=(6, 0))
        self.model_mode_var.trace_add("write", self._model_mode_changed)
        self._model_mode_changed()
        settings = assignment_settings
        entry(22, "每个账号登录超时（秒）", self.timeout_var)
        show = ttk.Checkbutton(settings, text="显示登录浏览器", variable=self.show_browser_var)
        show.grid(row=24, column=0, sticky="w", pady=(10, 6))
        self._controls.append((show, "normal"))
        ttk.Label(settings, text="登录代理沿用授权页设置。\n重复账号更新凭据及本次配置。\n手机验证跳过并标记待补手机。", style="Hint.TLabel", wraplength=270).grid(row=25, column=0, sticky="w", pady=(5, 8))
        self.status_var = tk.StringVar(master=self.win, value="填写站点并加载分组，然后录入账号开始推送")
        status = ttk.Label(outer, textvariable=self.status_var, style="Subtitle.TLabel", wraplength=950)
        status.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        outer.bind("<Configure>", lambda e: status.configure(wraplength=max(300, e.width - 45)))
        for variable in (self.site_var, self.secret_var, self.auth_kind_var):
            variable.trace_add("write", self._connection_changed)

    def _scroll_settings(self, event):
        if event.delta:
            self.options_canvas.yview_scroll(-1 if event.delta > 0 else 1, "units")
        return "break"

    def _model_mode_changed(self, *_):
        mode = self.model_mode_var.get()
        replace = mode == MODEL_MODES["replace"]
        self.model_holder.grid() if replace else self.model_holder.grid_remove()
        editable = replace and not self._busy and not self.closing
        self.model_picker.set_enabled(editable)
        self.model_load_btn.configure(state=tk.NORMAL if editable else tk.DISABLED)
        self.model_source_combo.configure(state="readonly" if editable and self._model_sources else tk.DISABLED)
        self.model_sync_btn.configure(state=tk.NORMAL if editable and self._model_source_id() else tk.DISABLED)
        if replace:
            hint = "仅推送勾选模型，替换原白名单和模型映射。同步会保留移除状态；不同账号可用模型可能不同。"
        elif mode == MODEL_MODES["clear"]:
            hint = "推送时清除账号原白名单和模型映射，按后台默认规则调度。"
        else:
            hint = "沿用输入 JSON 的模型配置；输入未提供时保留后台原配置。"
        self.model_hint_var.set(hint)

    def _model_source_id(self):
        index = self.model_source_combo.current()
        return self._model_sources[index]["id"] if 0 <= index < len(self._model_sources) else None

    def _model_source_changed(self, *_):
        self.model_picker.mark_unsynced()
        self.model_sync_var.set("来源已选择，点击同步读取模型；原勾选结果保留。")
        self._model_mode_changed()

    def _connection_changed(self, *_):
        self._stop_inspection_timer()
        self._connected_id = ""
        self.connection_var.set("连接信息已改变，请重新加载分组")
        self._groups = []
        self.group_list.delete(0, tk.END)
        self._model_sources = []
        self.model_source_var.set("")
        self.model_source_combo.configure(values=())
        self.model_picker.mark_unsynced()
        self.model_sync_var.set("连接信息已改变，请重新连接并加载来源账号。")
        self._model_mode_changed()
        self._proxies = []
        self.backend_proxy_combo.configure(values=PROXY_DEFAULTS)
        self.backend_proxy_var.set(PROXY_DEFAULTS[0])
        self._inspection_report = None
        self.inspection_tree.delete(*self.inspection_tree.get_children())
        self.inspection_var.set("连接已改变，请重新读取号池状态")
        self.inspect_export_btn.configure(state=tk.DISABLED)

    def _settings(self, require_groups=True):
        try:
            priority, concurrency = ((int(self.priority_var.get()), int(self.concurrency_var.get()))
                                     if require_groups else (50, 3))
        except ValueError:
            raise ValueError("优先级和并发数必须是整数") from None
        secret = self.secret_var.get().strip()
        if self.auth_kind_var.get() == "管理员访问令牌" and secret.lower().startswith("bearer "):
            secret = secret[7:].strip()
        models = None
        if require_groups:
            if self.model_mode_var.get() == MODEL_MODES["replace"]:
                if self.model_picker.custom_text.get("1.0", "end-1c").strip():
                    raise ValueError("自定义模型尚未加入列表，请先点击「添加自定义模型」")
                models = self.model_picker.selected_models()
                if not models:
                    raise ValueError("请至少保留一个模型；解除限制请明确选择「清除模型限制」")
            elif self.model_mode_var.get() == MODEL_MODES["clear"]:
                models = ()
        load_factor = None
        if require_groups and self.load_factor_var.get().strip():
            try:
                load_factor = int(self.load_factor_var.get())
            except ValueError:
                raise ValueError("负载系数必须为整数，或留空保留") from None
        config = PoolSettings(self.site_var.get(), "api_key" if self.auth_kind_var.get() == "管理员 API Key" else "bearer",
                              secret, tuple(self._groups[i]["id"] for i in self.group_list.curselection()), priority, concurrency, models,
                              next((key for key, label in SCHEDULING_MODES.items() if label == self.scheduling_var.get()), "override"),
                              self._proxy_id() if require_groups else None, load_factor)
        config.validate(require_groups=require_groups)
        if require_groups and self._connected_id != config.connection_id():
            raise ValueError("请先连接当前站点并加载分组")
        return config

    def _load_settings(self):
        try:
            data = json.loads(self.config_path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError
            self.site_var.set(str(data.get("site") or ""))
            self.auth_kind_var.set("管理员访问令牌" if data.get("auth_kind") == "bearer" else "管理员 API Key")
            self.remember_var.set(data.get("remember", True) is True)
            encrypted = data.get("credential", "")
            if self.remember_var.get() and isinstance(encrypted, str) and encrypted.startswith("dpapi:"):
                self.secret_var.set(self.unprotect(encrypted))
            self.priority_var.set(str(data.get("priority", 50)))
            self.concurrency_var.set(str(data.get("concurrency", 3)))
            self.scheduling_var.set(SCHEDULING_MODES.get(data.get("scheduling_mode"), SCHEDULING_MODES["override"]))
            self.load_factor_var.set(str(data.get("load_factor") or ""))
            if data.get("load_factor") in (0, "0"):
                self.load_factor_var.set("0")
            self._saved_proxy_id = data.get("proxy_id")
            self._saved_proxy_connection = data.get("group_connection", "")
            if self._saved_proxy_id == 0:
                self.backend_proxy_var.set(PROXY_DEFAULTS[1])
            elif self._saved_proxy_id:
                self.backend_proxy_var.set(f"待加载代理 ID {self._saved_proxy_id}")
            self.timeout_var.set(str(data.get("timeout", 180)))
            self.inspect_interval_var.set(str(data.get("inspection_interval_minutes", 15)))
            self.show_browser_var.set(data.get("show_browser") is True)
            model_text = data.get("model_whitelist_text", "")
            choices = data.get("model_choices")
            if choices is None:
                choices = dict.fromkeys(parse_model_whitelist(model_text), True) if isinstance(model_text, str) and model_text.strip() else {}
            self.model_picker.restore(choices)
            self.model_mode_var.set(MODEL_MODES.get(data.get("model_mode"), MODEL_MODES["preserve"]))
            self._saved_group_connection = data.get("group_connection", "")
            self._saved_group_ids = data.get("group_ids", [])
            self._saved_source_connection = data.get("model_source_connection", "")
            self._saved_source_id = data.get("model_source_id")
        except FileNotFoundError:
            pass
        except (OSError, ValueError, TypeError):
            self._log("推池配置无法读取，请重新填写")

    def _save_settings(self):
        secret = self.secret_var.get().strip()
        try:
            encrypted = self.protect(secret) if self.remember_var.get() else ""
        except Exception:
            encrypted = ""
        if not isinstance(encrypted, str) or encrypted and not encrypted.startswith("dpapi:"):
            encrypted = ""
        if secret and self.remember_var.get() and not encrypted:
            self._log("凭据加密失败；本次仅在内存使用，未保存明文")
        data = {"site": self.site_var.get().strip(), "auth_kind": "api_key" if self.auth_kind_var.get() == "管理员 API Key" else "bearer",
                "credential": encrypted, "remember": self.remember_var.get(), "priority": self.priority_var.get(),
                "concurrency": self.concurrency_var.get(), "timeout": self.timeout_var.get(), "show_browser": self.show_browser_var.get(),
                "model_mode": next((key for key, label in MODEL_MODES.items() if label == self.model_mode_var.get()), "preserve"),
                "model_whitelist_text": "\n".join(self.model_picker.selected_models()),
                "model_choices": self.model_picker.snapshot(),
                "model_source_connection": self._connected_id, "model_source_id": self._model_source_id(),
                "group_connection": self._connected_id, "group_ids": [self._groups[i]["id"] for i in self.group_list.curselection()]}
        data.update(inspection_interval_minutes=self.inspect_interval_var.get(),
                    scheduling_mode=next((key for key, label in SCHEDULING_MODES.items() if label == self.scheduling_var.get()), "override"),
                    load_factor=self.load_factor_var.get().strip(), proxy_id=self._selected_proxy_or_saved())
        try:
            _atomic_write_json(self.config_path, data, overwrite=True)
        except OSError:
            self._log("配置保存失败；本次设置仍可使用")

    def _set_busy(self, mode):
        if mode and not self._busy:
            self._last_error = ""
        self._busy = mode
        self.running = mode == "push"
        present_running(self, "pool", self.running)
        for widget, normal in self._controls:
            widget.configure(state=tk.DISABLED if mode else normal)
        self._model_mode_changed()
        for widget in (self.file_btn, self.dir_btn, self.preview_btn, self.start_btn, self.connect_btn, self.restore_btn, self.proxy_load_btn, self.inspect_btn, self.selected_retry_btn, self.defer_btn):
            widget.configure(state=tk.DISABLED if mode or self.closing else tk.NORMAL)
        self.inspect_export_btn.configure(state=tk.NORMAL if self._inspection_report and not mode and not self.closing else tk.DISABLED)
        self.input_text.configure(state=tk.DISABLED if mode else tk.NORMAL)
        self.stop_btn.configure(state=tk.NORMAL if mode and not self.closing else tk.DISABLED)
        retryable = any(job.state not in ("ready", "created", "updated") for job in self.jobs)
        self.retry_btn.configure(state=tk.NORMAL if retryable and not mode and not self.closing else tk.DISABLED)
        self.phone_btn.configure(state=tk.NORMAL if self.on_phone_inputs and not mode and not self.closing and
                                 any(job.state == "phone_required" for job in self.jobs) else tk.DISABLED)

    def connect(self):
        if self._busy or self.closing:
            return
        try:
            config = self._settings(require_groups=False)
        except ValueError as exc:
            messagebox.showerror(TITLE, str(exc), parent=self.win)
            return
        self._connected_id = ""
        self.stop_flag.clear()
        self._set_busy("connect")
        self.connection_var.set("正在连接并读取分组…")
        def work():
            try:
                with PoolClient(config, self.stop_flag) as client:
                    groups = client.groups()
                self.events.put(("connected", config.connection_id(), groups))
            except Exception as exc:
                self.events.put(("error", str(exc) if isinstance(exc, PoolError) else "连接失败，请核对站点和网络"))
            finally:
                self.events.put(("done",))
        self._launch(work)

    def _model_connection(self):
        config = self._settings(require_groups=False)
        if self._connected_id != config.connection_id():
            raise ValueError("请先连接当前站点并加载分组，再同步模型")
        return config

    def _proxy_id(self):
        value = self.backend_proxy_var.get()
        if value == PROXY_DEFAULTS[0]:
            return None
        if value == PROXY_DEFAULTS[1]:
            return 0
        index = self.backend_proxy_combo.current() - len(PROXY_DEFAULTS)
        if 0 <= index < len(self._proxies):
            return self._proxies[index]["id"]
        raise ValueError("请加载后台代理并重新选择，原代理可能已失效")

    def _selected_proxy_or_saved(self):
        try:
            return self._proxy_id()
        except ValueError:
            return self._saved_proxy_id

    def load_proxies(self):
        if self._busy or self.closing:
            return
        try:
            config = self._model_connection()
        except ValueError as exc:
            messagebox.showerror(TITLE, str(exc), parent=self.win)
            return
        selected = self._selected_proxy_or_saved()
        self.stop_flag.clear()
        self._set_busy("proxies")
        self.status_var.set("正在读取后台代理…")
        def work():
            try:
                with PoolClient(config, self.stop_flag) as client:
                    proxies = client.proxies()
                self.events.put(("proxies", config.connection_id(), proxies, selected))
            except Exception as exc:
                self.events.put(("error", str(exc) if isinstance(exc, PoolError) else "后台代理读取失败，保留原选择"))
            finally:
                self.events.put(("done",))
        self._launch(work)

    def load_model_sources(self):
        if self._busy or self.closing:
            return
        try:
            config = self._model_connection()
        except ValueError as exc:
            messagebox.showerror(TITLE, str(exc), parent=self.win)
            return
        selected = self._model_source_id()
        if selected is None and self._saved_source_connection == config.connection_id():
            selected = self._saved_source_id
        self.stop_flag.clear()
        self._set_busy("model_sources")
        self.model_sync_var.set("正在读取后台 OpenAI OAuth 账号…")
        def work():
            try:
                with PoolClient(config, self.stop_flag) as client:
                    sources = client.model_sources()
                self.events.put(("model_sources", config.connection_id(), sources, selected))
            except Exception as exc:
                self.events.put(("error", str(exc) if isinstance(exc, PoolError) else "来源账号读取失败，保留原模型选择"))
            finally:
                self.events.put(("done",))
        self._launch(work)

    def sync_upstream_models(self):
        if self._busy or self.closing:
            return
        try:
            config = self._model_connection()
            account_id = self._model_source_id()
            if account_id is None:
                raise ValueError("请先加载并选择一个后台已有的 OpenAI OAuth 账号作为同步来源")
        except ValueError as exc:
            messagebox.showerror(TITLE, str(exc), parent=self.win)
            return
        self.stop_flag.clear()
        self._set_busy("model_sync")
        self.model_sync_var.set(f"正在同步账号 ID {account_id} 的上游模型…")
        self.status_var.set("模型同步中；后台可能更新能力缓存，白名单将在开始推送时应用")
        def work():
            try:
                with PoolClient(config, self.stop_flag) as client:
                    models, notices = client.sync_models(account_id)
                self.events.put(("model_synced", config.connection_id(), account_id, models, notices))
            except Exception as exc:
                self.events.put(("error", str(exc) if isinstance(exc, PoolError) else "模型同步失败，保留原模型选择"))
            finally:
                self.events.put(("done",))
        self._launch(work)

    def _launch(self, target):
        self.worker = threading.Thread(target=target, daemon=False)
        try:
            self.worker.start()
        except Exception:
            if self._lock_held:
                self._lock_held = False
                self.task_lock.release()
            self._set_busy("")
            messagebox.showerror(TITLE, "无法启动后台任务", parent=self.win)

    def _input_value(self):
        return self.input_text.get("1.0", "end-1c")

    def restore_task(self, path=None):
        if self._busy or self.closing:
            return
        if any(job.pending for job in self.jobs):
            messagebox.showerror(TITLE, "请先核对当前待确认写入，再恢复其他任务", parent=self.win)
            return
        path = path or filedialog.askopenfilename(parent=self.win, title="恢复加密推池任务",
                                                initialdir=TOOL_DIR / "recovery", filetypes=[("推池恢复文件", "queue.dpapi.json")])
        if not path:
            return
        try:
            config, jobs = PoolJournal(path, protect=self.protect, unprotect=self.unprotect).load()
            current_site = normalize_site(self.site_var.get()) if self.site_var.get().strip() else ""
        except (PoolError, ValueError) as exc:
            messagebox.showerror(TITLE, str(exc), parent=self.win)
            return
        if current_site != normalize_site(config["site"]):
            self.secret_var.set("")
        self.site_var.set(config["site"])
        self.auth_kind_var.set("管理员 API Key" if config["auth_kind"] == "api_key" else "管理员访问令牌")
        self.priority_var.set(str(config["priority"]))
        self.concurrency_var.set(str(config["concurrency"]))
        self.scheduling_var.set(SCHEDULING_MODES[config["scheduling_mode"]])
        self.load_factor_var.set("" if config["load_factor"] is None else str(config["load_factor"]))
        models = config["model_whitelist"]
        self.model_mode_var.set(MODEL_MODES["preserve" if models is None else "replace" if models else "clear"])
        self.model_picker.restore(dict.fromkeys(models or (), True))
        self._restored_site = normalize_site(config["site"])
        self._saved_group_ids = list(config["group_ids"])
        self._saved_proxy_id = config["proxy_id"]
        if self._saved_proxy_id is not None:
            self.backend_proxy_var.set(PROXY_DEFAULTS[1] if self._saved_proxy_id == 0 else f"待加载代理 ID {self._saved_proxy_id}")
        self.jobs = jobs
        self._recovery_path = Path(path)
        self.input_text.delete("1.0", tk.END)
        self.input_text.insert("1.0", json.dumps([job.account or login_mapping(job.login) for job in jobs], ensure_ascii=False, indent=2))
        self._parsed_text = self._input_value()
        self.result_filter.clear()
        for job in jobs:
            self._row(job.uid, job.email, job.state, job.account_id, job.message)
        self._set_busy("")
        self.status_var.set(f"已恢复 {len(jobs)} 个账号；请连接原站点，核对配置后点击开始推送。成功项会跳过。")

    def receive_accounts(self, accounts):
        if self._busy or self.closing or any(job.pending for job in self.jobs):
            messagebox.showerror(TITLE, "当前推池任务正在运行或有待核对写入，请处理后再接收账号", parent=self.win)
            return False
        if not accounts:
            return False
        text = json.dumps(accounts, ensure_ascii=False, indent=2)
        try:
            parse_push_text(text)
        except ValueError as exc:
            messagebox.showerror(TITLE, str(exc), parent=self.win)
            return False
        if self._input_value().strip():
            self.input_text.insert(tk.END, "\n\n")
        self.input_text.insert(tk.END, text)
        if self.preview():
            self.status_var.set(f"已接收 {len(accounts)} 个成功账号；核对目标分组后点击开始推送")
            return True
        return False

    def send_to_phone(self):
        if self._busy or self.closing or not self.on_phone_inputs:
            return
        selected = set(self.tree.selection())
        inputs = [job.login for job in self.jobs if job.state == "phone_required" and job.login
                  and (not selected or job.uid in selected)]
        if not inputs:
            self.status_var.set("请选择待补手机的账号；未选择时传递全部待补手机账号")
            return
        self.on_phone_inputs(inputs)

    def preview(self):
        if self._busy or self.closing:
            return False
        if self._input_value() != self._parsed_text and any(job.pending for job in self.jobs):
            messagebox.showerror(TITLE, "有写入结果尚未确认，请保持原输入并重试核对后再录入新账号", parent=self.win)
            return False
        try:
            text = self._input_value()
            if text != self._parsed_text:
                self.jobs = parse_push_text(text)
                self._recovery_path = None
                self._parsed_text = text
                self.result_filter.clear()
            for job in self.jobs:
                self._row(job.uid, job.email, job.state, job.account_id, job.message)
            self.status_var.set(f"已识别 {len(self.jobs)} 个账号；有 token 的直接推送，账号密码先完成 OAuth")
            self._set_busy("")
            return True
        except ValueError as exc:
            self.jobs = []
            self._parsed_text = None
            self.result_filter.clear()
            self._set_busy("")
            messagebox.showerror(TITLE, str(exc), parent=self.win)
            return False

    def load_files(self):
        if self._busy:
            return
        paths = filedialog.askopenfilenames(parent=self.win, title="导入账号（可多选）", filetypes=[("账号文件", "*.json *.txt"), ("所有文件", "*.*")])
        if paths:
            self._load_paths(paths)

    def load_dir(self):
        if self._busy:
            return
        folder = filedialog.askdirectory(parent=self.win, title="导入 JSON / TXT 目录")
        if not folder:
            return
        try:
            paths = sorted((p for p in Path(folder).iterdir() if p.is_file() and p.suffix.lower() in (".json", ".txt")), key=lambda p: p.name.casefold())
        except OSError:
            messagebox.showerror(TITLE, "无法读取目录", parent=self.win)
            return
        self._load_paths(paths)

    def _load_paths(self, paths):
        text, report = load_push_files(paths)
        for index, name, count, reason in report:
            self._log(f"文件 {index} {name}：" + (f"跳过，{reason}" if reason else f"载入 {count} 个账号"))
        if not text:
            messagebox.showerror(TITLE, "没有可导入的账号，保留原输入", parent=self.win)
            return
        if self._input_value().strip():
            self.input_text.insert(tk.END, "\n\n")
        self.input_text.insert(tk.END, text)
        self.preview()

    def start(self):
        self._relogin_ids = ()
        if not self.preview():
            return
        self._start_jobs(self.jobs)

    def retry_failed(self):
        self._retry_jobs([job for job in self.jobs if job.state not in ("created", "updated", "deferred")])

    def retry_selected(self):
        selected = set(self.tree.selection())
        self._retry_jobs([job for job in self.jobs if job.uid in selected and job.state not in ("created", "updated", "deferred")])

    def defer_selected(self):
        if self._busy or self.closing:
            return
        selected = set(self.tree.selection())
        for job in self.jobs:
            if job.uid in selected and not job.pending and job.state not in ("created", "updated"):
                job.state = "ready" if job.state == "deferred" else "deferred"
                job.message = "等待处理" if job.state == "ready" else "本次暂不处理；可选中恢复"
                self._row(job.uid, job.email, job.state, job.account_id, job.message)
        self.status_var.set("已更新选中账号；待核对写入和成功项不受此操作影响")
        self._set_busy("")

    def _retry_jobs(self, jobs):
        if self._busy or self.closing:
            return
        if self._input_value() != self._parsed_text:
            messagebox.showerror(TITLE, "输入已修改，请识别后重新开始推送", parent=self.win)
            return
        self._relogin_ids = ()
        choices = [job for job in jobs if job.refresh_state in ("refresh_failed", "refresh_unknown", "refreshing") and not job.pending]
        if choices:
            if not messagebox.askyesno(TITLE, f"有 {len(choices)} 个账号刷新失败或结果不明确。是否用浏览器重新登录并继续推送？\n选择否保留当前结果，不会自动重登。", parent=self.win):
                jobs = [job for job in jobs if job not in choices]
            else:
                self._relogin_ids = tuple(job.uid for job in choices)
        if jobs:
            self._start_jobs(jobs)

    def _start_jobs(self, jobs):
        jobs = [job for job in jobs if job.state != "deferred"]
        if self._busy or self.closing or not jobs:
            return
        try:
            config = self._settings()
            if any(job.pending and job.pending.destination != config.destination_id() for job in self.jobs):
                raise ValueError("有待核对写入，请保持原站点、分组和配置后重试")
            jobs = [job for job in jobs if job.state not in ("created", "updated") or
                    job.completed_destination != config.destination_id()]
            if not jobs:
                self.status_var.set("这些账号已按当前配置推送成功；修改分组或配置后可再次推送")
                return
            timeout = int(self.timeout_var.get())
            if timeout < 30:
                raise ValueError("登录超时不能小于 30 秒")
            proxy = self.auth_options() if any(job.login or (job.account or {}).get("credentials", {}).get("refresh_token") for job in jobs) else None
        except ValueError as exc:
            messagebox.showerror(TITLE, str(exc), parent=self.win)
            return
        if not self.task_lock.acquire(blocking=False):
            messagebox.showwarning(TITLE, "其他授权、接码或推池任务正在运行，请等待完成", parent=self.win)
            return
        self._lock_held = True
        self._save_settings()
        self.stop_flag.clear()
        headless = not self.show_browser_var.get()
        self._set_busy("push")
        self.status_var.set(f"准备推送 {len(jobs)} 个账号；重复账号更新配置，手机验证跳过")
        self._launch(lambda: self._run_worker(jobs, config, timeout, proxy, headless))

    def _run_worker(self, jobs, config, timeout, proxy, headless):
        sensitive = [config.credential]
        if proxy:
            sensitive.extend((proxy, unquote(urlsplit(proxy).password or "")))
        for job in jobs:
            if job.login:
                sensitive.extend((job.login.password, job.login.totp_secret, job.login.mailbox_url))
        def logger(message):
            self.events.put(("log", redact_diagnostic(message, tuple(sensitive))))
        def progress(job):
            self.events.put(("row", job.uid, job.email, job.state, job.account_id, job.message))
        set_log_callback(logger)
        try:
            journal = PoolJournal(self._recovery_path, protect=self.protect, unprotect=self.unprotect) if self._recovery_path else PoolJournal.create(TOOL_DIR / "recovery")
            self._recovery_path = journal.path
            logger(f"推池任务加密保存到：{journal.path}")
            run_pool_push(jobs, config, stop=self.stop_flag, on_progress=progress, timeout=timeout, proxy=proxy,
                          headless=headless, recovery_dir=TOOL_DIR / "recovery", client_factory=PoolClient,
                          journal=journal, journal_jobs=self.jobs, relogin_ids=self._relogin_ids)
        except Exception as exc:
            message = str(exc) if isinstance(exc, PoolError) else "批次中断，已保留处理结果；请检查网络或本地存储后重试"
            self.events.put(("error", redact_diagnostic(message, tuple(sensitive))))
        finally:
            set_log_callback(None)
            if self._lock_held:
                self._lock_held = False
                self.task_lock.release()
            self.events.put(("done",))

    def _row(self, uid, email, state, account_id, message):
        values = (email, STATE_LABELS.get(state, "失败"), account_id or "", message)
        self.result_filter.put(uid, values)
        self._summary()

    def _stop_inspection_timer(self):
        self._inspect_due = None
        self._inspect_interval = 0
        self.inspect_timer_btn.configure(text="启用定时")
        self.inspect_timer_var.set("定时未启用")

    def toggle_inspection_timer(self):
        if self._inspect_interval:
            self._stop_inspection_timer()
            return
        if self.closing or self._busy:
            return
        try:
            self._model_connection()
            minutes = int(self.inspect_interval_var.get())
            if not 1 <= minutes <= 1440:
                raise ValueError("巡检间隔必须为 1–1440 分钟")
        except ValueError as exc:
            messagebox.showerror(TITLE, str(exc), parent=self.win)
            return
        self._inspect_interval = minutes * 60
        self.inspect_timer_btn.configure(text="停止定时")
        self._inspect_due = time.monotonic()
        self._save_settings()
        self._tick_inspection()

    def _tick_inspection(self):
        if self.closing or self._inspect_due is None:
            return
        remaining = max(0, int(self._inspect_due - time.monotonic()))
        self.inspect_timer_var.set(f"下次 {remaining // 60:02d}:{remaining % 60:02d}" if remaining else "等待空闲巡检")
        if not self._busy and remaining == 0 and not (self.worker and self.worker.is_alive()):
            self._inspect_due = None
            self.inspect(scheduled=True)

    def inspect(self, *, scheduled=False):
        if self._busy or self.closing:
            return
        try:
            config = self._model_connection()
        except ValueError as exc:
            if scheduled:
                self._stop_inspection_timer()
                self.inspection_var.set("定时已停止：" + str(exc))
                return
            messagebox.showerror(TITLE, str(exc), parent=self.win)
            return
        groups = tuple(self._groups[i]["id"] for i in self.group_list.curselection())
        self.stop_flag.clear()
        self._set_busy("inspect")
        if not scheduled:
            self.result_tabs.select(self.inspection_tab)
        self.inspection_var.set("正在只读巡检；不测试上游，不刷新或重登")
        def work():
            try:
                report = inspect_pool(config, self.stop_flag, group_ids=groups)
                self.events.put(("inspection", config.connection_id(), report))
            except Exception as exc:
                self.events.put(("error", str(exc) if isinstance(exc, PoolError) else "巡检失败，保留上次结果"))
            finally:
                self.events.put(("done",))
        self._launch(work)

    def export_inspection(self):
        if not self._inspection_report or self._busy or self.closing:
            return
        path = filedialog.asksaveasfilename(parent=self.win, title="导出只读巡检报告", defaultextension=".json",
                                          initialfile="pool-inspection.json", filetypes=[("JSON", "*.json")])
        if path:
            try:
                _atomic_write_json(Path(path), self._inspection_report, overwrite=True)
            except OSError:
                messagebox.showerror(TITLE, "巡检报告保存失败", parent=self.win)

    def _summary(self):
        success = sum(job.state in ("created", "updated") for job in self.jobs)
        phone = sum(job.state == "phone_required" for job in self.jobs)
        self.summary_var.set(f"共 {len(self.jobs)} 个 · 成功 {success} · 待补手机 {phone} · 其余 {len(self.jobs)-success-phone}")

    def _log(self, message):
        self.log_text.configure(state=tk.NORMAL)
        tag = "error" if any(word in str(message) for word in ("失败", "错误")) else "success" if "成功" in str(message) else "warning" if "等待" in str(message) else ""
        self.log_text.insert(tk.END, str(message) + "\n", (tag,) if tag else ())
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def _schedule(self):
        self._after_id = self.win.after(80, self._drain)

    def _drain(self):
        if self._after_id is not None:
            self.win.after_cancel(self._after_id)
        self._after_id = None
        while True:
            try:
                kind, *args = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == "inspection":
                connection, report = args
                groups = sorted(self._groups[i]["id"] for i in self.group_list.curselection())
                if self.stop_flag.is_set() or self.closing or connection != self._connected_id or groups != sorted(report["group_ids"]):
                    continue
                report["changes"] = inspection_delta(self._inspection_report, report)
                self._inspection_report = report
                self.inspection_tree.delete(*self.inspection_tree.get_children())
                for row in report["accounts"]:
                    self.inspection_tree.insert("", tk.END, values=(row["id"], row["email"], "；".join(row["issues"]) or "未发现已存状态异常（未测上游）"))
                delta = report["changes"]
                difference = "首次建立基线" if delta["baseline"] else f"新增异常 {len(delta['new'])} · 已消除 {len(delta['resolved'])} · 离开范围 {len(delta['removed_ids'])}"
                self.inspection_var.set(f"已检查 {report['total']} 个 · 需关注 {report['attention']} 个 · {report['checked_at']}\n{difference}；仅后台状态，不代表实时可用性")
                self.status_var.set("只读巡检完成，没有修改后台账号")
            elif kind == "connected":
                self._connected_id, self._groups = args
                self.group_list.configure(state=tk.NORMAL)
                self.group_list.delete(0, tk.END)
                for index, group in enumerate(self._groups):
                    self.group_list.insert(tk.END, f"{group.get('name') or '未命名'}  (ID {group['id']})")
                    if (self._connected_id == self._saved_group_connection or self._restored_site == normalize_site(self.site_var.get())) and group["id"] in self._saved_group_ids:
                        self.group_list.selection_set(index)
                if self._saved_proxy_id is not None and (self._connected_id == self._saved_proxy_connection or self._restored_site == normalize_site(self.site_var.get())):
                    self.backend_proxy_var.set(PROXY_DEFAULTS[1] if self._saved_proxy_id == 0 else f"待加载代理 ID {self._saved_proxy_id}")
                self.connection_var.set(f"连接成功 · {len(self._groups)} 个可用 OpenAI 分组")
            elif kind == "proxies":
                connection, proxies, selected = args
                if self.stop_flag.is_set() or self.closing or connection != self._connected_id:
                    continue
                self._proxies = proxies
                self.backend_proxy_combo.configure(values=PROXY_DEFAULTS + tuple(f"ID {item['id']} · {item['name']}" for item in proxies))
                index = next((i + 2 for i, item in enumerate(proxies) if item["id"] == selected), None)
                if index is not None:
                    self.backend_proxy_combo.current(index)
                elif selected:
                    self.backend_proxy_var.set(f"原代理 ID {selected} 已失效，请重新选择")
                else:
                    self.backend_proxy_combo.current(1 if selected == 0 else 0)
                self.status_var.set(f"已加载 {len(proxies)} 个后台代理；仅用于后台模型请求")
            elif kind in ("model_sources", "model_synced"):
                if self.stop_flag.is_set() or self.closing or args[0] != self._connected_id:
                    self.model_sync_var.set("已停止或连接已变化，保留原模型选择。")
                    self.status_var.set(self.model_sync_var.get())
                    continue
                if kind == "model_sources":
                    _, self._model_sources, selected = args
                    self.model_source_combo.configure(values=tuple(f"ID {item['id']} · {item['name']}" for item in self._model_sources))
                    self.model_source_var.set("")
                    if self._model_sources:
                        index = next((i for i, item in enumerate(self._model_sources) if item["id"] == selected), 0)
                        self.model_source_combo.current(index)
                        self.model_sync_var.set(f"已加载 {len(self._model_sources)} 个账号，选择来源后点击同步。")
                    else:
                        self.model_sync_var.set("后台还没有 OpenAI OAuth 账号；先推送一个账号，或手动添加模型。")
                    self.model_picker.mark_unsynced()
                else:
                    _, account_id, models, notices = args
                    if account_id != self._model_source_id():
                        self.model_sync_var.set("同步来源已变化，保留原模型选择。")
                        continue
                    self.model_picker.merge_upstream(models)
                    message = f"来源 ID {account_id} 返回 {len(models)} 个模型；原移除状态保留。" if models else "上游返回空列表，保留原模型选择。"
                    if notices:
                        message += " " + "；".join(notices)
                    self.model_sync_var.set(message)
                    self._log(message)
                self.status_var.set(self.model_sync_var.get())
            elif kind == "row":
                self._row(*args)
                self._log(f"{args[1]}：{args[4]}" + (f"（后台 ID {args[3]}）" if args[3] else ""))
            elif kind == "log":
                self._log(args[0])
            elif kind == "error":
                self._last_error = args[0]
                self.status_var.set(args[0])
                if self._busy == "connect":
                    self.connection_var.set(args[0])
                elif self._busy in ("model_sources", "model_sync"):
                    self.model_sync_var.set(args[0])
                elif self._busy == "inspect":
                    self.inspection_var.set(args[0] + "；保留上次结果")
                self._log(args[0])
            elif kind == "done":
                was_push = self._busy == "push"
                if self._busy == "inspect" and self._inspect_interval:
                    self._inspect_due = time.monotonic() + self._inspect_interval
                self._set_busy("")
                self._save_settings()
                if was_push:
                    self._summary()
                    self.status_var.set(("本轮中断：" + self._last_error) if self._last_error else
                                        "本轮结束 · " + self.summary_var.get() + "；可查看结果并重试未成功账号")
        if not self.closing:
            self._tick_inspection()
            self._schedule()

    def stop(self):
        self._stop_inspection_timer()
        self.stop_flag.set()
        self.status_var.set("正在停止，等待当前请求或浏览器收尾…")

    def begin_close(self):
        self._stop_inspection_timer()
        self._save_settings()
        self.closing = True
        self.stop_flag.set()
        self._set_busy(self._busy)

    def dispose(self):
        if self._after_id is not None:
            self.win.after_cancel(self._after_id)
            self._after_id = None
        self.secret_var.set("")
        self.input_text.configure(state=tk.NORMAL)
        self.input_text.delete("1.0", tk.END)
        self.jobs.clear()
