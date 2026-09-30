"""Manual visual QA with no network calls or real credentials."""
import argparse
import sys
import tempfile
from pathlib import Path
import tkinter as tk
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import openai_reauth_gui as gui
import pool_gui


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--size", default="1140x850")
    parser.add_argument("--converter", action="store_true")
    parser.add_argument("--page", choices=("auth", "phone", "convert", "pool"), default="auth")
    parser.add_argument("--sample", action="store_true", help="Show synthetic conversion data only")
    parser.add_argument("--tab", default="")
    parser.add_argument("--scale", type=int, default=100)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as folder, \
         patch.object(gui, "AUTH_CONFIG_PATH", Path(folder) / "auth.json"), \
         patch.object(gui, "PHONE_CONFIG_PATH", Path(folder) / "phone.json"), \
         patch.object(pool_gui, "CONFIG_PATH", Path(folder) / "pool.json"):
        root = tk.Tk()
        root.tk.call('tk', 'scaling', 96 * args.scale / 100 / 72)
        app = gui.ReauthApp(root)
        root.title("OpenAI Reauth - UI Preview")
        root.geometry(args.size)
        if args.converter:
            app.open_converter()
            root.title("JSON Converter - UI Preview")
        elif args.page != 'auth':
            {'phone': app.open_phone, 'convert': app.open_converter, 'pool': app.open_pool}[args.page]()
            root.title("OpenAI Reauth - UI Preview")
        if args.sample and app.converter is not None:
            app.converter.set_input('{"type":"codex","email":"demo@example.com",'
                                    '"account_id":"demo-account","access_token":"demo-access",'
                                    '"refresh_token":"demo-refresh","expired":"2026-12-31T12:00:00+08:00"}')
            app.converter.preview()
        if args.sample and app.pool_page is not None:
            page = app.pool_page
            page._connected_id = "offline-preview"
            page._groups = [{"id": 7, "name": "演示分组"}]
            page.group_list.insert(tk.END, "演示分组 (ID 7)")
            page.events.put(("proxies", "offline-preview", [{"id": 42, "name": "演示后台代理"}], 42))
            page.events.put(("inspection", "offline-preview", {
                "site": "https://fixture.test", "group_ids": [],
                "total": 2, "attention": 1, "checked_at": "2026-09-22T12:00:00+08:00",
                "accounts": [{"id": 1, "email": "demo@example.com", "issues": ["access token 已过期", "限流冷却"]},
                             {"id": 2, "email": "sample@example.com", "issues": []}]}))
            page.events.put(("done",))
            page._drain()
            page.result_tabs.select(page.inspection_tab)
        if args.page == 'phone' and args.sample:
            page = app.phone_page
            page.price_catalog.rows = [
                {"country": "4", "title": "菲律宾（Philippines）", "price": "0.018", "count": 1527, "supported": True},
                {"country": "38", "title": "加纳（Ghana）", "price": "0.025", "count": 230, "supported": True},
                {"country": "187", "title": "美国（USA）", "price": "0.126", "count": 2905, "supported": True}]
            page.price_catalog.render()
            page.phone_activity_tabs.select(page.price_catalog.frame)
        if args.tab:
            tabs = app.activity_tabs if args.page == 'auth' else app.phone_page.phone_activity_tabs if args.page == 'phone' else app.pool_page.result_tabs
            tabs.select(int(args.tab))
        root.mainloop()


if __name__ == "__main__":
    main()
