"""Tk integration with a synthetic in-memory sub2api admin server."""

import json
import threading
import tkinter as tk
from pathlib import Path
from unittest.mock import patch

import openai_reauth_gui as gui
import pool_gui
import pool_flow
from test_gui import TkCase
from test_pool import AdminBackend, account
from pool_flow import PendingWrite, PushJob
from account_inputs import AccountInput


class PoolGuiTests(TkCase):
    def setUp(self):
        super().setUp()
        config_patch = patch.object(pool_gui, "CONFIG_PATH", Path(self.folder.name) / "pool.json")
        config_patch.start()
        self.addCleanup(config_patch.stop)
        refresh_patch = patch.object(pool_flow, "refresh_account", side_effect=lambda account, **_: account)
        refresh_patch.start()
        self.addCleanup(refresh_patch.stop)

    def page(self):
        app = gui.ReauthApp(self.root)
        app.open_pool()
        return app, app.pool_page

    def connect_page(self, page, backend):
        page.site_var.set("https://sub2.test")
        page.secret_var.set("fixture-admin-key")
        with patch.object(pool_gui, "PoolClient", backend.client):
            page.connect()
            page.worker.join(3)
        self.assertFalse(page.worker.is_alive())
        page._drain()
        page.group_list.selection_set(0, 1)

    def test_same_window_navigation_preserves_inputs(self):
        app, page = self.page()
        page.input_text.insert("1.0", "fixture@example.com----password-fixture")
        self.assertTrue(page.preview())
        self.assertIs(page.win.winfo_toplevel(), self.root)
        app.open_converter()
        self.assertFalse(page.win.winfo_manager())
        app.open_pool()
        self.assertIs(page, app.pool_page)
        self.assertIn("password-fixture", page._input_value())
        self.assertFalse(any(isinstance(widget, tk.Toplevel) for widget in self.root.winfo_children()))

    def test_authorization_successes_are_handed_to_pool_without_auto_push(self):
        app = gui.ReauthApp(self.root)
        app.last_payload_accounts = [account()]
        app.push_success_results()
        self.assertIsNotNone(app.pool_page)
        self.assertEqual(len(app.pool_page.jobs), 1)
        self.assertEqual(app.pool_page.jobs[0].state, "ready")
        self.assertFalse(app.pool_page.running)

    def test_phone_required_job_moves_to_phone_page_without_starting_it(self):
        app, page = self.page()
        login = AccountInput("fixture@example.com", "password-fixture", "", 1)
        page.jobs = [PushJob(login.email, login=login, state="phone_required", message="待补手机")]
        page._set_busy("")
        page.send_to_phone()
        self.assertIsNotNone(app.phone_page)
        self.assertIn("fixture@example.com", app.phone_page.input_value())
        self.assertIn("password-fixture", app.phone_page.input_value())
        self.assertFalse(app.phone_page.running)

    def test_connect_loads_groups_and_never_writes_accounts(self):
        _, page = self.page()
        backend = AdminBackend()
        self.connect_page(page, backend)
        self.assertEqual(page.group_list.size(), 2)
        self.assertEqual(page._settings().group_ids, (7, 8))
        self.assertTrue(all(row[0] == "GET" for row in backend.requests))
        self.assertTrue(page.secret_entry.cget("show"))

    def test_changed_connection_invalidates_old_group_selection(self):
        _, page = self.page()
        self.connect_page(page, AdminBackend())
        page.site_var.set("https://different.test")
        self.assertEqual(page.group_list.size(), 0)
        self.assertFalse(page._connected_id)
        with self.assertRaises(ValueError):
            page._settings()

    def test_input_edits_cannot_retry_old_credentials(self):
        _, page = self.page()
        page.input_text.insert("1.0", json.dumps(account()))
        self.assertTrue(page.preview())
        page.jobs[0].state = "failed"
        page.input_text.insert(tk.END, "\n# changed")
        with patch.object(page, "_start_jobs") as start:
            page.retry_failed()
        start.assert_not_called()
        self.dialogs[1].assert_called()

    def test_account_password_secrets_not_displayed_in_preview_or_log(self):
        _, page = self.page()
        page.input_text.insert("1.0", "fixture@example.com----password-fixture----JBSWY3DPEHPK3PXP")
        self.assertTrue(page.preview())
        displayed = str([page.tree.item(i) for i in page.tree.get_children()]) + page.log_text.get("1.0", "end-1c")
        self.assertNotIn("password-fixture", displayed)
        self.assertNotIn("JBSWY3DPEHPK3PXP", displayed)

    def test_backend_settings_and_tokens_reach_worker_without_tk_calls(self):
        _, page = self.page()
        backend = AdminBackend()
        self.connect_page(page, backend)
        page.input_text.insert("1.0", json.dumps(account()))
        self.assertTrue(page.preview())
        settings = page._settings()
        page._lock_held = page.task_lock.acquire(blocking=False)
        with patch.object(pool_gui, "PoolClient", backend.client), \
             patch.object(pool_gui, "TOOL_DIR", Path(self.folder.name)), \
             patch.object(page, "_row", side_effect=AssertionError("worker touched Tk")), \
             patch.object(page, "_log", side_effect=AssertionError("worker touched Tk")):
            page._run_worker(page.jobs, settings, 180, None, True)
        self.assertFalse(page.task_lock.locked())
        page._drain()
        self.assertEqual(len(backend.records), 1)
        self.assertEqual(page.jobs[0].state, "created")
        self.assertIn("成功 1", page.summary_var.get())
        self.assertNotIn("fixture-admin-key", page.log_text.get("1.0", "end-1c"))

    def test_shared_task_lock_prevents_push_during_authorization(self):
        _, page = self.page()
        self.connect_page(page, AdminBackend())
        page.input_text.insert("1.0", json.dumps(account()))
        page.task_lock.acquire()
        with patch.object(page, "_launch") as launch:
            page.start()
        launch.assert_not_called()
        self.assertTrue(page.task_lock.locked())
        page.task_lock.release()

    def test_saved_credential_is_encrypted_and_forget_clears_disk(self):
        _, page = self.page()
        page.secret_var.set("fixture-admin-key")
        with patch.object(page, "protect", return_value="dpapi:fixture-cipher"):
            page._save_settings()
        saved = json.loads(page.config_path.read_text(encoding="utf-8"))
        self.assertEqual(saved["credential"], "dpapi:fixture-cipher")
        self.assertNotIn("fixture-admin-key", page.config_path.read_text(encoding="utf-8"))
        page.remember_var.set(False)
        page._save_settings()
        self.assertEqual(json.loads(page.config_path.read_text(encoding="utf-8"))["credential"], "")
        self.assertEqual(page.secret_var.get(), "fixture-admin-key")

    def test_encryption_failure_never_falls_back_to_plaintext(self):
        _, page = self.page()
        page.secret_var.set("fixture-admin-key")
        with patch.object(page, "protect", return_value=""):
            page._save_settings()
        self.assertNotIn("fixture-admin-key", page.config_path.read_text(encoding="utf-8"))
        self.assertIn("未保存明文", page.log_text.get("1.0", "end-1c"))

    def test_encryption_exception_keeps_ui_usable_without_saving_secret(self):
        _, page = self.page()
        page.secret_var.set("fixture-admin-key")
        with patch.object(page, "protect", side_effect=RuntimeError("fixture-failure")):
            page._save_settings()
        self.assertNotIn("fixture-admin-key", page.config_path.read_text(encoding="utf-8"))

    def test_batch_failure_reason_survives_completion_event(self):
        _, page = self.page()
        page._set_busy("push")
        page.events.put(("error", "管理员凭据无效或已过期，请重新连接"))
        page.events.put(("done",))
        page._drain()
        self.assertIn("管理员凭据无效", page.status_var.get())
        self.assertFalse(page.running)

    def test_changed_input_cannot_discard_unconfirmed_write(self):
        _, page = self.page()
        page.input_text.insert("1.0", json.dumps(account()))
        self.assertTrue(page.preview())
        job = page.jobs[0]
        job.pending = PendingWrite(("fixture",), "POST", "/accounts", {}, "fixture-key")
        page.input_text.insert(tk.END, "\n# changed")
        self.assertFalse(page.preview())
        self.assertIs(page.jobs[0], job)
        self.assertIsNotNone(job.pending)

    def test_changing_target_configuration_can_repush_successful_accounts(self):
        _, page = self.page()
        self.connect_page(page, AdminBackend())
        page.input_text.insert("1.0", json.dumps(account()))
        self.assertTrue(page.preview())
        job = page.jobs[0]
        job.state = "created"
        job.completed_destination = page._settings().destination_id()
        with patch.object(page, "_launch") as launch:
            page.start()
            launch.assert_not_called()
            page.priority_var.set("8")
            page.start()
            launch.assert_called_once()
        page._lock_held = False
        page.task_lock.release()

    def test_close_waits_for_pool_worker_and_requests_cancellation(self):
        app, page = self.page()
        event = threading.Event()
        worker = threading.Thread(target=lambda: event.wait(2))
        worker.start()
        page.worker = worker
        with patch.object(app, "_schedule") as scheduled:
            app.on_close()
        self.assertTrue(page.stop_flag.is_set())
        self.assertTrue(page.closing)
        scheduled.assert_called_with(100, app._wait_for_worker_close)
        event.set()
        worker.join(3)

    def test_small_window_keeps_buttons_and_scrollable_settings_accessible(self):
        _, page = self.page()
        self.root.geometry("980x740")
        self.root.deiconify()
        self.root.update()
        for widget in (page.input_text, page.start_btn, page.stop_btn, page.retry_btn, page.tree, page.options_canvas):
            with self.subTest(widget=widget.winfo_class()):
                self.assertGreater(widget.winfo_height(), 10)
                self.assertLessEqual(widget.winfo_rootx()+widget.winfo_width(), self.root.winfo_rootx()+self.root.winfo_width())
                self.assertLessEqual(widget.winfo_rooty()+widget.winfo_height(), self.root.winfo_rooty()+self.root.winfo_height())
