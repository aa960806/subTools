"""Reusable, local-only account filtering for Tk result tables."""
import tkinter as tk
from tkinter import ttk


class TableFilter:
    """Filter presentation only; stable row ids remain owned by the caller."""
    def __init__(self, parent, tree):
        self.tree, self.rows = tree, {}
        self.frame = ttk.Frame(parent, style="Card.TFrame")
        self.query = tk.StringVar(master=parent)
        self.status = tk.StringVar(master=parent, value="全部状态")
        ttk.Label(self.frame, text="筛选", style="Hint.TLabel").pack(side=tk.LEFT, padx=(0, 6))
        ttk.Entry(self.frame, textvariable=self.query, width=18).pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.combo = ttk.Combobox(self.frame, textvariable=self.status, values=("全部状态",), state="readonly", width=14)
        self.combo.pack(side=tk.LEFT, padx=6)
        self.count = tk.StringVar(master=parent)
        ttk.Label(self.frame, textvariable=self.count, style="Hint.TLabel").pack(side=tk.RIGHT)
        self.query.trace_add("write", self.render)
        self.status.trace_add("write", self.render)

    def put(self, uid, values):
        self.rows[uid] = tuple(values)
        query, status = self.query.get().strip().casefold(), self.status.get()
        visible = (status == "全部状态" or values[1] == status) and (not query or query in " ".join(map(str, values)).casefold())
        if visible:
            if self.tree.exists(uid):
                self.tree.item(uid, values=values)
            else:
                self.tree.insert("", tk.END, iid=uid, values=values)
        elif self.tree.exists(uid):
            self.tree.delete(uid)
        self.combo.configure(values=("全部状态",) + tuple(sorted({row[1] for row in self.rows.values()})))
        self.count.set(f"{len(self.tree.get_children())} / {len(self.rows)}")

    def clear(self):
        self.rows.clear()
        self.render()

    def render(self, *_):
        query, status = self.query.get().strip().casefold(), self.status.get()
        selected = set(self.tree.selection())
        self.tree.delete(*self.tree.get_children())
        for uid, values in self.rows.items():
            if (status == "全部状态" or values[1] == status) and (not query or query in " ".join(map(str, values)).casefold()):
                self.tree.insert("", tk.END, iid=uid, values=values)
                if uid in selected:
                    self.tree.selection_add(uid)
        self.combo.configure(values=("全部状态",) + tuple(sorted({row[1] for row in self.rows.values()})))
        self.count.set(f"{len(self.tree.get_children())} / {len(self.rows)}")
