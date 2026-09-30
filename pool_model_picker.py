"""Selectable model catalog; deselection survives subsequent upstream syncs."""

import tkinter as tk
from tkinter import ttk

from pool_client import parse_model_whitelist, validate_model_names
from reauth_ui import text_area


class ModelPicker(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, style="Card.TFrame")
        self.choices = {}
        self.upstream = set()
        self.editable = True
        self.columnconfigure(0, weight=1)
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(self, textvariable=self.search_var)
        self.search_entry.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 4))
        ttk.Label(self, text="搜索名称；点击方框保留／移除", style="Hint.TLabel").grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 4))
        self.tree = ttk.Treeview(self, columns=("keep", "model", "source"), show="headings", height=6, selectmode="extended")
        for key, title, width in (("keep", "保留", 36), ("model", "模型", 168), ("source", "来源", 55)):
            self.tree.heading(key, text=title)
            self.tree.column(key, width=width, minwidth=width, stretch=key == "model")
        scroll = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.tree.yview)
        horizontal = ttk.Scrollbar(self, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=scroll.set, xscrollcommand=horizontal.set)
        self.tree.grid(row=2, column=0, sticky="nsew")
        scroll.grid(row=2, column=1, sticky="ns")
        horizontal.grid(row=3, column=0, sticky="ew")
        self.tree.bind("<Button-1>", self._click)
        self.tree.bind("<space>", self._toggle_selected)
        self.tree.bind("<Delete>", self._remove_selected)
        self.summary_var = tk.StringVar()
        ttk.Label(self, textvariable=self.summary_var, style="Hint.TLabel").grid(row=4, column=0, columnspan=2, sticky="w", pady=(4, 2))
        actions = ttk.Frame(self, style="Card.TFrame")
        actions.grid(row=5, column=0, columnspan=2, sticky="ew")
        self.keep_btn = ttk.Button(actions, text="全部保留", style="Ghost.TButton", command=lambda: self.select_all(True))
        self.keep_btn.pack(side=tk.LEFT)
        self.remove_btn = ttk.Button(actions, text="全部移除", style="Ghost.TButton", command=lambda: self.select_all(False))
        self.remove_btn.pack(side=tk.RIGHT)
        ttk.Label(self, text="自定义模型（多行或逗号分隔）", style="Hint.TLabel").grid(row=6, column=0, columnspan=2, sticky="w", pady=(8, 4))
        holder, self.custom_text = text_area(self, height=2)
        holder.grid(row=7, column=0, columnspan=2, sticky="ew")
        self.add_btn = ttk.Button(self, text="添加自定义模型", style="Secondary.TButton", command=self.add_custom)
        self.add_btn.grid(row=8, column=0, columnspan=2, sticky="ew", pady=(5, 0))
        self.error_var = tk.StringVar()
        ttk.Label(self, textvariable=self.error_var, style="Hint.TLabel", wraplength=260).grid(row=9, column=0, columnspan=2, sticky="w", pady=(4, 0))
        self.search_var.trace_add("write", lambda *_: self.render())
        self.render()

    def selected_models(self):
        return tuple(model for model, kept in self.choices.items() if kept)

    def snapshot(self):
        return dict(self.choices)

    def restore(self, choices):
        if not isinstance(choices, dict) or any(type(kept) is not bool for kept in choices.values()):
            raise ValueError("模型选择配置无效")
        validate_model_names(tuple(choices))
        self.choices = dict(choices)
        self.upstream.clear()
        self.render()

    def merge_upstream(self, models):
        validate_model_names(tuple(models))
        if not models:
            return
        for model in models:
            self.choices.setdefault(model, True)
        self.upstream = set(models)
        self.render()

    def mark_unsynced(self):
        self.upstream.clear()
        self.render()

    def add_custom(self):
        if not self.editable:
            return False
        try:
            models = parse_model_whitelist(self.custom_text.get("1.0", "end-1c"))
        except ValueError as exc:
            self.error_var.set(str(exc))
            return False
        for model in models:
            self.choices[model] = True
        self.custom_text.delete("1.0", tk.END)
        self.error_var.set("")
        self.render()
        return True

    def select_all(self, keep):
        if self.editable:
            self.choices = dict.fromkeys(self.choices, keep)
            self.render()

    def set_enabled(self, enabled):
        self.editable = enabled
        for widget in (self.search_entry, self.keep_btn, self.remove_btn, self.add_btn, self.custom_text):
            widget.configure(state=tk.NORMAL if enabled else tk.DISABLED)

    def _click(self, event):
        if self.editable and self.tree.identify_column(event.x) == "#1":
            row = self.tree.identify_row(event.y)
            if row:
                model = self.tree.set(row, "model")
                self.choices[model] = not self.choices[model]
                self.render()
                return "break"

    def _toggle_selected(self, _event=None):
        if self.editable:
            for row in self.tree.selection():
                model = self.tree.set(row, "model")
                self.choices[model] = not self.choices[model]
            self.render()
        return "break"

    def _remove_selected(self, _event=None):
        if self.editable:
            for row in self.tree.selection():
                self.choices[self.tree.set(row, "model")] = False
            self.render()
        return "break"

    def render(self):
        position = self.tree.yview()[0]
        self.tree.delete(*self.tree.get_children())
        query = self.search_var.get().strip().casefold()
        for index, (model, kept) in enumerate(self.choices.items()):
            if query in model.casefold():
                self.tree.insert("", tk.END, iid=str(index), values=("☑" if kept else "☐", model, "同步" if model in self.upstream else "未返回"))
        self.tree.yview_moveto(position)
        self.summary_var.set(f"保留 {len(self.selected_models())} / {len(self.choices)} 个模型")
