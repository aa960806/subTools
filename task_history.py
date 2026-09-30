"""Local history index. Listing never decrypts credentials or resumes work."""
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import json
import queue
import threading
import tkinter as tk
from tkinter import ttk, messagebox

from reauth_ui import card, DataTable, AutoScrollbar


@dataclass(frozen=True)
class HistoryRecord:
    path: Path
    kind: str
    modified: float


def scan_history(directory, limit=200):
    root = Path(directory).resolve()
    if not root.is_dir():
        return []
    records = []
    for entry in root.iterdir():
        if entry.is_symlink() or entry.resolve().parent != root:
            continue
        candidates = []
        if entry.is_dir():
            candidates = [(entry / "queue.dpapi.json", "推池任务"), (entry / "accounts.json", "授权结果")]
        elif entry.name.startswith("phone-results-") and entry.suffix == ".json":
            candidates = [(entry, "接码报告")]
        for path, kind in candidates:
            try:
                if path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(root):
                    records.append(HistoryRecord(path, kind, path.stat().st_mtime))
            except OSError:
                continue
    return sorted(records, key=lambda row: (row.modified, str(row.path)), reverse=True)[:limit]


class HistoryView:
    def __init__(self, parent, directory, on_open):
        self.frame = card(parent, padding=6)
        self.directory, self.on_open = directory, on_open
        self.records, self.worker = [], None
        self.events = queue.Queue()
        bar = ttk.Frame(self.frame, style="Card.TFrame")
        bar.pack(fill=tk.X, pady=(0, 6))
        ttk.Button(bar, text="读取历史", command=self.refresh, style="Ghost.TButton").pack(side=tk.LEFT)
        ttk.Button(bar, text="打开选中记录", command=self.open_selected, style="Secondary.TButton").pack(side=tk.RIGHT)
        self.status = tk.StringVar(master=parent, value="读取最近 200 条本地记录；打开后不会自动运行")
        ttk.Label(self.frame, textvariable=self.status, style="Hint.TLabel").pack(fill=tk.X)
        self.tree = DataTable(self.frame, columns=("time", "kind", "name"), show="headings", height=3, selectmode="browse", empty_text="点击读取历史，查看已保存任务与结果")
        for key, title, width in (("time", "时间", 155), ("kind", "类型", 95), ("name", "记录", 245)):
            self.tree.heading(key, text=title)
            self.tree.column(key, width=width, minwidth=70)
        sy = AutoScrollbar(self.frame, orient=tk.VERTICAL, command=self.tree.yview, content_widget=self.tree)
        sy.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=sy.set)
        self.tree.pack(fill=tk.BOTH, expand=True)

    def refresh(self):
        if self.worker and self.worker.is_alive():
            return
        self.status.set("正在读取本地记录…")
        def work():
            try:
                self.events.put((scan_history(self.directory), ""))
            except OSError:
                self.events.put(([], "无法读取恢复目录，请检查权限"))
        self.worker = threading.Thread(target=work, daemon=True)
        self.worker.start()

    def drain(self):
        try:
            records, error = self.events.get_nowait()
        except queue.Empty:
            return
        self.records = records
        self.tree.delete(*self.tree.get_children())
        for index, row in enumerate(records):
            name = row.path.parent.name if row.kind != "接码报告" else row.path.stem
            self.tree.insert("", tk.END, iid=str(index), values=(datetime.fromtimestamp(row.modified).strftime("%m-%d %H:%M:%S"), row.kind, name))
        self.status.set(error or f"已读取 {len(records)} 条；推池任务需在原 Windows 用户下解密，损坏记录会保留并提示")

    def open_selected(self):
        selected = self.tree.selection()
        if selected:
            self.on_open(self.records[int(selected[0])])


def read_history_json(record, directory):
    path, root = record.path.resolve(), Path(directory).resolve()
    if not path.is_relative_to(root) or path.stat().st_size > 64 * 1024 * 1024:
        raise ValueError("历史记录路径或大小无效")
    return path.read_text(encoding="utf-8-sig")
