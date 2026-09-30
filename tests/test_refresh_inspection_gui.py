import json
import tkinter as tk
from pathlib import Path
from unittest.mock import Mock, patch

import openai_reauth_gui as gui
import pool_gui
from account_inputs import account_input_from_mapping
from pool_flow import parse_push_text
from test_gui import TkCase
from test_pool import AdminBackend, account
from test_pool_inspection import reader
from pool_inspection import inspect_pool


class RefreshInspectionGuiTests(TkCase):
    def page(self):
        config_patch = patch.object(pool_gui, "CONFIG_PATH", Path(self.folder.name) / "pool.json")
        config_patch.start()
        self.addCleanup(config_patch.stop)
        app = gui.ReauthApp(self.root)
        app.open_pool()
        page = app.pool_page
        page.site_var.set("https://sub2.test")
        page.secret_var.set("fixture-admin-key")
        backend = AdminBackend([{**account(), "id": 1, "group_ids": [7], "status": "error"}])
        with patch.object(pool_gui, "PoolClient", backend.client):
            page.connect()
            page.worker.join(3)
        page._drain()
        return app, page, backend

    def test_authorization_requires_choice_before_browser_fallback(self):
        app = gui.ReauthApp(self.root)
        item = account_input_from_mapping(account())
        item.refresh_state = "refresh_unknown"
        app.retry_accounts = [item]
        with patch.object(app, "_start_batch") as start:
            self.dialogs[-1].return_value = False
            app.retry_failed()
            start.assert_not_called()
            self.dialogs[-1].return_value = True
            app.retry_failed()
        selected = start.call_args.args[0][0]
        self.assertIsNone(selected.oauth_account)
        self.assertIsNotNone(item.oauth_account)

    def test_pool_relogin_approval_is_explicit_and_not_saved(self):
        _, page, _ = self.page()
        page.input_text.insert("1.0", json.dumps(account()))
        self.assertTrue(page.preview())
        page.jobs[0].refresh_state = "refresh_failed"
        page.jobs[0].state = "refresh_failed"
        with patch.object(page, "_start_jobs") as start:
            self.dialogs[-1].return_value = False
            page.retry_failed()
            start.assert_not_called()
            self.dialogs[-1].return_value = True
            page.retry_failed()
        self.assertEqual(page._relogin_ids, (page.jobs[0].uid,))
        page._save_settings()
        self.assertNotIn("relogin", page.config_path.read_text(encoding="utf-8"))

    def test_inspection_runs_in_same_page_without_touching_push_jobs(self):
        _, page, backend = self.page()
        page.jobs = parse_push_text("fixture@example.com----fixture-password")
        original = list(page.jobs)
        with patch.object(pool_gui, "inspect_pool", side_effect=lambda config, stop, **kw:
                          inspect_pool(config, stop, client_factory=reader(backend), **kw)):
            page.inspect()
            page.worker.join(3)
        self.assertFalse(page.worker.is_alive())
        page._drain()
        self.assertEqual(page.jobs, original)
        self.assertEqual(page.jobs[0].state, "ready")
        self.assertEqual(len(page.inspection_tree.get_children()), 1)
        self.assertTrue(all(row[0] == "GET" for row in backend.requests))
        output = Path(self.folder.name) / "inspection.json"
        with patch.object(pool_gui.filedialog, "asksaveasfilename", return_value=str(output)):
            page.export_inspection()
        self.assertTrue(json.loads(output.read_text(encoding="utf-8"))["read_only"])
        self.assertNotIn("fixture-password", output.read_text(encoding="utf-8"))
        page.site_var.set("https://other.test")
        self.assertIsNone(page._inspection_report)
        self.assertFalse(page.inspection_tree.get_children())

    def test_inspection_ignores_unfinished_write_settings(self):
        _, page, backend = self.page()
        page.priority_var.set("unfinished")
        page.load_factor_var.set("unfinished")
        page.timeout_var.set("unfinished")
        with patch.object(pool_gui, "inspect_pool", side_effect=lambda config, stop, **kw:
                          inspect_pool(config, stop, client_factory=reader(backend), **kw)):
            page.inspect()
            page.worker.join(3)
        page._drain()
        self.assertIsNotNone(page._inspection_report)

    def test_proxy_explicit_preserve_is_not_overridden_by_old_saved_binding(self):
        _, page, backend = self.page()
        page._saved_proxy_id = 42
        page._saved_proxy_connection = page._connected_id
        page.backend_proxy_var.set(pool_gui.PROXY_DEFAULTS[0])
        with patch.object(pool_gui, "PoolClient", backend.client):
            page.load_proxies()
            page.worker.join(3)
        page._drain()
        self.assertIsNone(page._proxy_id())
        page.backend_proxy_combo.current(2)
        self.assertEqual(page._proxy_id(), 42)
        page.backend_proxy_combo.current(1)
        self.assertEqual(page._proxy_id(), 0)

    def test_stopped_or_obsolete_inspection_does_not_replace_report(self):
        _, page, _ = self.page()
        report = {"accounts": [], "total": 0, "attention": 0, "checked_at": "fixture"}
        page.stop_flag.set()
        page.events.put(("inspection", page._connected_id, report))
        page._drain()
        self.assertIsNone(page._inspection_report)
        page.stop_flag.clear()
        page.events.put(("inspection", "obsolete-connection", report))
        page._drain()
        self.assertIsNone(page._inspection_report)
