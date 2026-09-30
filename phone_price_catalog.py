"""Country price catalogue adapted from toSub2/src/smsbower.mjs (MIT).

See THIRD_PARTY_NOTICES.md. Quotes are read-only and never change the price cap.
"""
from decimal import Decimal
import queue
import re
import threading
import tkinter as tk
from tkinter import ttk
from datetime import datetime

from phone_smsbower import (SmsBowerClient, SmsBowerError, COUNTRY_CATALOG, COUNTRY_PINYIN,
                           country_label, validate_price)
from reauth_ui import card, DataTable, AutoScrollbar


from phone_price_data import normalize_price_options


class PriceCatalogView:
    def __init__(self, parent, connection, apply_country, price_cap):
        self.frame = card(parent, padding=8)
        self.connection, self.apply_country, self.price_cap = connection, apply_country, price_cap
        self.rows, self.worker, self.snapshot = [], None, None
        self.events = queue.Queue()
        bar = ttk.Frame(self.frame, style="Card.TFrame")
        bar.pack(fill=tk.X, pady=(0, 6))
        ttk.Button(bar, text="查询各国报价", command=self.refresh, style="Secondary.TButton").pack(side=tk.LEFT)
        self.query = tk.StringVar(master=parent)
        ttk.Entry(bar, textvariable=self.query, width=14).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6)
        self.order = tk.StringVar(master=parent, value="价格升序")
        ttk.Combobox(bar, textvariable=self.order, state="readonly", values=("价格升序", "库存降序", "国家 A–Z"), width=11).pack(side=tk.RIGHT)
        self.status = tk.StringVar(master=parent, value="只查询，不买号、不调整限价；输入国家名或拼音筛选")
        ttk.Label(self.frame, textvariable=self.status, style="Hint.TLabel", wraplength=570).pack(fill=tk.X, pady=(0, 6))
        actions = ttk.Frame(self.frame, style="Card.TFrame")
        actions.pack(side=tk.BOTTOM, fill=tk.X)
        ttk.Button(actions, text="设为主国家", command=lambda: self.apply(False), style="Ghost.TButton").pack(side=tk.LEFT)
        ttk.Button(actions, text="加入备用国家", command=lambda: self.apply(True), style="Ghost.TButton").pack(side=tk.LEFT, padx=8)
        self.tree = DataTable(self.frame, columns=("country", "price", "stock", "eligible"), show="headings", height=4, selectmode="extended", empty_text="查询后可按价格、库存或国家排序")
        for key, title, width in (("country", "国家", 195), ("price", "最低报价", 85), ("stock", "库存", 70), ("eligible", "限价", 135)):
            self.tree.heading(key, text=title)
            self.tree.column(key, width=width, minwidth=60)
        sy = AutoScrollbar(self.frame, orient=tk.VERTICAL, command=self.tree.yview, content_widget=self.tree)
        sy.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=sy.set)
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.query.trace_add("write", self.render)
        self.order.trace_add("write", self.render)

    def refresh(self):
        if self.worker and self.worker.is_alive():
            return
        try:
            key, proxy = self.connection()
            if not key:
                raise ValueError("请先填写 SMSBower API Key")
        except ValueError as exc:
            self.status.set(str(exc))
            return
        self.status.set("正在读取各国报价与国家列表…")
        self.snapshot = (key, proxy)
        def work():
            try:
                self.events.put((SmsBowerClient(api_key=key, proxy=proxy).get_price_options(), ""))
            except Exception:
                self.events.put(([], "国家比价读取失败，请检查 API Key 和网络后重试"))
        self.worker = threading.Thread(target=work, daemon=True)
        self.worker.start()

    def drain(self):
        try:
            rows, error = self.events.get_nowait()
        except queue.Empty:
            return
        try:
            unchanged = self.snapshot == self.connection()
        except ValueError:
            unchanged = False
        self.snapshot = None
        if not unchanged:
            self.rows = []
            self.render()
            self.status.set("连接设置已变化，请重新查询各国报价")
            return
        if not error:
            self.rows = rows
            self.render()
        self.status.set(error or f"{datetime.now():%H:%M:%S} · {len(rows)} 个国家；库存以分配为准，买号前会重新读 V3 报价")

    def render(self, *_):
        query = self.query.get().strip().casefold()
        try:
            cap = Decimal(validate_price(self.price_cap()) or "Infinity")
        except ValueError:
            cap = None
        key = {"价格升序": lambda row: Decimal(row["price"]), "库存降序": lambda row: -row["count"],
               "国家 A–Z": lambda row: COUNTRY_PINYIN.get(row["country"], row["title"].casefold())}[self.order.get()]
        selected = set(self.tree.selection())
        self.tree.delete(*self.tree.get_children())
        for row in sorted(self.rows, key=key):
            if query and query not in (row["title"] + " " + COUNTRY_PINYIN.get(row["country"], "") + " " + row["country"]).casefold():
                continue
            eligibility = "限价无效" if cap is None else "限价内" if Decimal(row["price"]) <= cap else "超过限价"
            if not row["supported"]:
                eligibility += " · 仅查看"
            self.tree.insert("", tk.END, iid=row["country"], values=(row["title"], "$" + row["price"], row["count"], eligibility))
            if row["country"] in selected:
                self.tree.selection_add(row["country"])

    def apply(self, fallback):
        selected = set(self.tree.selection())
        codes = [code for code in self.tree.get_children() if code in selected]
        if not codes or (not fallback and len(codes) != 1):
            self.status.set("主国家请选择一项；备用国家可多选")
            return
        if any(code not in COUNTRY_PINYIN for code in codes):
            self.status.set("选中项包含尚未核对的国家代码，仅供查看；请使用已支持国家")
            return
        self.apply_country(codes, fallback)
