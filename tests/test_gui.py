"""Offline Tk regressions using synthetic credentials only."""

import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import tkinter as tk
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import openai_reauth_gui as gui
from openai_reauth import AccountInput, ReauthResult


def cpa(email="first@example.com"):
    return {
        "type": "codex", "email": email,
        "expired": "2027-01-15T00:00:00.123+08:00", "id_token": "synthetic-id",
        "account_id": "synthetic-account", "disabled": False,
        "access_token": "synthetic-access", "last_refresh": "2026-09-17T09:00:00.456+08:00",
        "refresh_token": "synthetic-refresh",
    }


class TkCase(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.auth_config = Path(self.folder.name) / "auth.json"
        for config_patch in (patch.object(gui, "AUTH_CONFIG_PATH", self.auth_config),
                             patch.object(gui, "PHONE_CONFIG_PATH", Path(self.folder.name) / "phone.json")):
            config_patch.start()
            self.addCleanup(config_patch.stop)
        # Thread.start is mocked by worker tests, so those workers never reach
        # their finally/release. Each test owns an isolated real task lock.
        lock_patch = patch.object(gui, "_TASK_LOCK", threading.Lock())
        lock_patch.start()
        self.addCleanup(lock_patch.stop)
        self.root = tk.Tk()
        self.root.withdraw()
        self.dialog_patches = [patch.object(gui.messagebox, name) for name in
                               ("showinfo", "showerror", "showwarning", "askyesno")]
        self.dialogs = [item.start() for item in self.dialog_patches]
        self.dialogs[-1].return_value = False
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        try:
            for handle in self.root.tk.splitlist(self.root.tk.call("after", "info")):
                self.root.after_cancel(handle)
            self.root.destroy()
        except tk.TclError:
            pass
        for item in reversed(self.dialog_patches):
            item.stop()

    def converter(self):
        win = gui.ConvertWindow(self.root, Mock())
        return win


class ConverterTests(TkCase):
    def test_mixed_file_import_skips_bad_file_and_reports_name(self):
        win = self.converter()
        folder = Path(self.folder.name)
        good = folder / "valid.json"
        bad = folder / "broken.json"
        session = folder / "session.json"
        good.write_text(json.dumps(cpa()), encoding="utf-8")
        bad.write_text("{broken", encoding="utf-8")
        session.write_text(json.dumps({"user": {"email": "session@example.com"},
                                       "accessToken": "fixture-access", "sessionToken": "fixture-session-secret"}), encoding="utf-8")
        with patch.object(gui.filedialog, "askopenfilenames", return_value=[str(good), str(bad), str(session)]):
            win.load_json_files()
        self.assertEqual(len(win.accounts), 2)
        self.assertEqual(win.source_kind, "mixed")
        preview = win.preview_text.get("1.0", "end-1c")
        self.assertIn("broken.json", preview)
        self.assertIn("成功 2，失败 1", preview)
        self.assertNotIn("fixture-session-secret", preview)
        self.assertEqual(len(win.account_tree.get_children()), 2)
        self.assertFalse(self.dialogs[1].called)

    def test_preview_target_can_switch_and_stays_after_refresh(self):
        win = self.converter()
        win.set_input(json.dumps(cpa()))
        self.assertTrue(win.preview())
        self.assertEqual(win.target_var.get(), "sub2")
        win.target_var.set("cpa")
        self.assertTrue(win.preview())
        self.assertIn('"type": "codex"', win.preview_text.get("1.0", "end-1c"))
        self.assertTrue(win.preview())
        self.assertEqual(win.target_var.get(), "cpa")
        win.clear_input()
        self.assertFalse(win.account_tree.get_children())

    def test_invalid_edits_clear_account_summary(self):
        win = self.converter()
        win.set_input(json.dumps(cpa()))
        self.assertTrue(win.preview())
        self.assertEqual(len(win.account_tree.get_children()), 1)
        win.input_text.insert(tk.END, "{broken")
        self.assertFalse(win.preview())
        self.assertFalse(win.account_tree.get_children())

    def test_summary_does_not_call_refresh_token_presence_verified(self):
        win = self.converter()
        win.set_input(json.dumps(cpa()))
        self.assertTrue(win.preview())
        item = win.account_tree.item(win.account_tree.get_children()[0])
        self.assertIn("未验证", str(item["values"]))
        self.assertNotIn("synthetic-refresh", str(item["values"]))

    def test_layout_keeps_conversion_controls_inside_small_window(self):
        self.root.geometry("980x740")
        win = self.converter()
        win.win.pack(fill=tk.BOTH, expand=True)
        self.root.deiconify()
        self.root.update()
        self.root.update_idletasks()
        buttons = []
        def visit(widget):
            if isinstance(widget, gui.ttk.Button):
                buttons.append(widget)
            for child in widget.winfo_children():
                visit(child)
        visit(win.win)
        for widget in [win.input_text, win.preview_text, win.account_tree, *buttons]:
            with self.subTest(widget=widget.winfo_class()):
                self.assertGreater(widget.winfo_height(), 10)
                self.assertLessEqual(widget.winfo_rooty() + widget.winfo_height(), self.root.winfo_rooty() + self.root.winfo_height())
                self.assertLessEqual(widget.winfo_rootx() + widget.winfo_width(), self.root.winfo_rootx() + self.root.winfo_width())

    def test_sub2_without_email_can_save_sub2_when_cpa_preview_is_unavailable(self):
        win = self.converter()
        source = {"exported_at": "2026-09-17T00:00:00Z", "custom_wrapper": {"keep": 1}, "accounts": [
            {"name": "Display name", "platform": "openai", "type": "oauth",
             "credentials": {"access_token": "synthetic-access", "refresh_token": "synthetic-refresh"},
             "extra": {"custom": "keep"}},
        ]}
        win.set_input(json.dumps(source))
        self.assertTrue(win.preview())
        self.assertEqual(len(win.accounts), 1)
        self.assertIn("无法生成 cpa 预览", win.preview_text.get("1.0", "end-1c"))
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "sub2.json"
            with patch.object(gui.filedialog, "asksaveasfilename", return_value=str(output)):
                win.save_as_sub2()
            saved = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(saved["accounts"], source["accounts"])
        self.assertEqual(saved["custom_wrapper"], source["custom_wrapper"])
        with patch.object(gui, "write_cpa_files") as writer:
            win.save_as_cpa()
        writer.assert_not_called()
        self.assertEqual(len(win.accounts), 1)

    def test_save_reparses_user_edits_after_preview(self):
        win = self.converter()
        win.set_input(json.dumps(cpa()))
        self.assertTrue(win.preview())
        win.input_text.delete("1.0", tk.END)
        win.input_text.insert("1.0", json.dumps(cpa("edited@example.com")))
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "out.json"
            with patch.object(gui.filedialog, "asksaveasfilename", return_value=str(output)):
                win.save_as_sub2()
            data = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(data["accounts"][0]["credentials"]["email"], "edited@example.com")

    def test_invalid_edits_cannot_export_cached_accounts(self):
        win = self.converter()
        win.set_input(json.dumps(cpa()))
        self.assertTrue(win.preview())
        win.input_text.insert(tk.END, " broken")
        with patch.object(gui, "write_export_file") as writer:
            win.save_as_sub2()
        writer.assert_not_called()
        self.assertFalse(win.accounts)

    def test_directory_keeps_all_sources_bom_unknown_fields_and_skip_warning(self):
        win = self.converter()
        with tempfile.TemporaryDirectory() as folder:
            for number in range(25):
                payload = cpa(f"user{number}@example.com")
                payload["custom"] = f"source-{number}"
                (Path(folder) / f"{number:02}.json").write_text(json.dumps(payload), encoding="utf-8-sig")
            (Path(folder) / "bad.json").write_text("not json", encoding="utf-8")
            with patch.object(gui.filedialog, "askdirectory", return_value=folder):
                win.load_cpa_dir()
            self.assertEqual(len(win.accounts), 25)
            self.assertIn("source-24", win.input_value())
            self.assertTrue(any("已跳过" in message for message in win.accounts.warnings))
            self.assertTrue(win.preview())
            self.assertEqual(len(win.accounts), 25)
            self.assertTrue(any("已跳过" in message for message in win.accounts.warnings))
            win.input_text.insert(tk.END, "\n")
            self.assertTrue(win.preview())
            self.assertEqual(sum("已跳过" in message for message in win.accounts.warnings), 1)
            win.input_text.insert(tk.END, "\n")
            self.assertTrue(win.preview())
            self.assertEqual(sum("已跳过" in message for message in win.accounts.warnings), 1)
            output = Path(folder) / "all-sub2.json"
            with patch.object(gui.filedialog, "asksaveasfilename", return_value=str(output)):
                win.save_as_sub2()
            self.assertEqual(len(json.loads(output.read_text(encoding="utf-8"))["accounts"]), 25)
        win.set_input(json.dumps(cpa()))
        self.assertTrue(win.preview())
        self.assertFalse(any("已跳过" in message for message in win.accounts.warnings))
        self.assertEqual(win._import_warnings, [])
        win._import_warnings = ["旧目录跳过提示"]
        win.clear_input()
        self.assertEqual(win._import_warnings, [])

    def test_preview_masks_secrets_but_save_keeps_them(self):
        win = self.converter()
        win.set_input(json.dumps(cpa()))
        self.assertTrue(win.preview())
        preview = win.preview_text.get("1.0", "end-1c")
        self.assertNotIn("synthetic-access", preview)
        self.assertNotIn("synthetic-refresh", preview)
        self.assertNotIn("synthetic-id", preview)
        self.assertEqual(win.accounts[0]["credentials"]["access_token"], "synthetic-access")

    def test_save_shows_loss_warnings_before_writing(self):
        win = self.converter()
        _, accounts = gui.parse_accounts_from_text(json.dumps(cpa()))
        accounts[0]["credentials"]["custom_setting"] = 42
        win.set_input(json.dumps(gui.build_export_payload(accounts)))
        events = []
        with patch.object(gui.messagebox, "showwarning", side_effect=lambda *a, **k: events.append("warning")), \
             patch.object(gui.filedialog, "askdirectory", return_value="ignored"), \
             patch.object(gui, "write_cpa_files", side_effect=lambda *a: events.append("write") or ["out"]):
            win.save_as_cpa()
        self.assertEqual(events, ["warning", "write"])

    def test_file_read_and_save_errors_are_shown_without_discarding_input(self):
        win = self.converter()
        source = json.dumps(cpa())
        win.set_input(source)
        with patch.object(gui.filedialog, "askopenfilename", return_value="missing.json"), \
             patch.object(Path, "read_text", side_effect=PermissionError("denied")):
            win.load_sub2_file()
        self.assertEqual(win.input_value(), source)
        with patch.object(gui.filedialog, "asksaveasfilename", return_value="out.json"), \
             patch.object(gui, "write_export_file", side_effect=OSError("disk full")):
            win.save_as_sub2()
        self.assertTrue(win.accounts)
        self.assertEqual(self.dialogs[1].call_count, 2)


class WorkerTests(TkCase):
    def app(self):
        return gui.ReauthApp(self.root)

    def test_conversion_navigation_stays_in_same_window_and_retains_input(self):
        app = self.app()
        app._clear_placeholder()
        app.accounts_text.insert("1.0", "draft account input")
        app.open_converter()
        converter = app.converter
        converter.set_input(json.dumps(cpa()))
        self.assertTrue(converter.preview())
        self.assertIs(converter.win.winfo_toplevel(), self.root)
        self.assertFalse(any(isinstance(child, tk.Toplevel) for child in self.root.winfo_children()))
        app.show_authorization()
        self.assertEqual(app.account_text(), "draft account input")
        app.open_converter()
        self.assertIs(app.converter, converter)
        self.assertEqual(len(converter.accounts), 1)

    def test_start_parses_current_input_and_defaults_to_headless(self):
        app = self.app()
        app._clear_placeholder()
        app.accounts_text.insert("1.0", "first@example.com----dummy----JBSWY3DPEHPK3PXP")
        with patch.object(gui.threading, "Thread") as thread_factory:
            app.start()
            args = thread_factory.call_args.kwargs["args"]
        self.assertEqual(args[0][0].email, "first@example.com")
        self.assertTrue(args[3])
        self.assertTrue(app.running)

    def test_worker_uses_queue_without_any_tk_calls_and_keeps_exception_text(self):
        app = self.app()
        account = AccountInput("first@example.com", "dummy", "dummy", 1)
        result = ReauthResult(account.email, False, error="interactive", category="needs_interaction")

        def fake_run(accounts, **kwargs):
            kwargs["on_progress"](1, 1, result)
            raise RuntimeError("synthetic worker failure")

        with patch.object(gui, "run_batch_reauth", side_effect=fake_run), \
             patch.object(app.root, "after", side_effect=AssertionError("worker touched Tk")):
            worker = threading.Thread(target=app._run_worker, args=([account], 30, None, True))
            worker.start()
            worker.join(5)
            self.assertFalse(worker.is_alive())
        events = []
        while not app.event_queue.empty():
            events.append(app.event_queue.get_nowait())
        self.assertIn(("progress", 1, 1, result), events)
        self.assertIn(("failed", "synthetic worker failure"), events)

    def test_partial_success_retained_and_only_failed_unattempted_retried_visibly(self):
        app = self.app()
        inputs = [AccountInput(f"u{i}@example.com", f"dummy{i}", "dummy", i + 1) for i in range(3)]
        app._active_accounts = inputs
        _, accounts = gui.parse_accounts_from_text(json.dumps(cpa(inputs[0].email)))
        success = accounts[0]
        app._on_progress(1, 3, ReauthResult(inputs[0].email, True, success, category="success"))
        app._on_progress(2, 3, ReauthResult(inputs[1].email, False, error="captcha", category="needs_interaction"))
        app._on_finished(2, 3)
        self.assertEqual(app.last_payload_accounts, [success])
        self.assertEqual(app.retry_accounts, inputs[1:])
        # Edit the visible input: retries must still use the original in-memory records.
        app._clear_placeholder()
        app.accounts_text.insert("1.0", "unrelated malformed text")
        with patch.object(gui.threading, "Thread") as thread_factory:
            app.retry_failed()
            args = thread_factory.call_args.kwargs["args"]
        self.assertEqual(args[0], inputs[1:])
        self.assertFalse(args[3])
        self.assertEqual(app.last_payload_accounts, [success])

    def test_fatal_worker_failure_preserves_success_and_unprocessed_inputs(self):
        app = self.app()
        inputs = [AccountInput(f"u{i}@example.com", "dummy", "dummy", i + 1) for i in range(2)]
        app._active_accounts = inputs
        _, accounts = gui.parse_accounts_from_text(json.dumps(cpa(inputs[0].email)))
        app._on_progress(1, 2, ReauthResult(inputs[0].email, True, accounts[0], category="success"))
        app._on_failed("network unavailable")
        self.assertEqual(app.last_payload_accounts, list(accounts))
        self.assertEqual(app.retry_accounts, inputs[1:])
        self.assertFalse(app.save_btn.instate(["disabled"]))

    def test_close_requests_stop_and_waits_for_worker_exit(self):
        app = self.app()
        app.running = True
        app.worker = SimpleNamespace(is_alive=Mock(return_value=True))
        with patch.object(self.root, "destroy") as destroy:
            app.on_close()
            self.assertTrue(app.stop_flag.is_set())
            self.assertTrue(app.closing)
            destroy.assert_not_called()
            app.worker.is_alive.return_value = False
            app._wait_for_worker_close()
            destroy.assert_called_once()

    def test_main_account_file_accepts_utf8_bom(self):
        app = self.app()
        with tempfile.TemporaryDirectory() as folder:
            file_path = Path(folder) / "accounts.txt"
            content = "first@example.com----dummy----JBSWY3DPEHPK3PXP"
            file_path.write_text(content, encoding="utf-8-sig")
            with patch.object(gui.filedialog, "askopenfilename", return_value=str(file_path)):
                app.load_file()
        self.assertEqual(app.account_text(), content)


class AuthProxyTests(TkCase):
    def test_proxy_protocol_applies_to_raw_input_but_explicit_url_wins(self):
        app = gui.ReauthApp(self.root)
        self.assertEqual(app.proxy_scheme_var.get(), "HTTP")
        app.proxy_var.set("127.0.0.1:8080:synthetic-user:synthetic-password")
        for protocol in ("HTTP", "HTTPS", "SOCKS5"):
            with self.subTest(protocol=protocol):
                app.proxy_scheme_var.set(protocol)
                self.assertEqual(app.current_proxy(), f"{protocol.lower()}://synthetic-user:synthetic-password@127.0.0.1:8080")
        app.proxy_var.set("https://synthetic-user:synthetic-password@127.0.0.1:8080")
        self.assertTrue(app.current_proxy().startswith("https://"))
        app.proxy_scheme_var.set("HTTP")
        app.proxy_var.set("socks5://synthetic-user:synthetic-password@127.0.0.1:8080")
        with patch.object(gui.threading, "Thread") as thread:
            app._start_batch([], retry=False)
        self.assertTrue(thread.call_args.kwargs["args"][2].startswith("socks5://"))

    def test_proxy_protocol_saved_and_legacy_defaults_to_http(self):
        app = gui.ReauthApp(self.root)
        app.proxy_scheme_var.set("SOCKS5")
        app._save_auth_settings()
        self.assertEqual(json.loads(self.auth_config.read_text(encoding="utf-8"))["proxy_scheme"], "socks5")
        app.proxy_scheme_var.set("HTTPS")
        app._load_auth_settings()
        self.assertEqual(app.proxy_scheme_var.get(), "SOCKS5")
        self.auth_config.write_text("{}", encoding="utf-8")
        app._load_auth_settings()
        self.assertEqual(app.proxy_scheme_var.get(), "HTTP")

    def test_proxy_input_auto_enables_and_is_masked(self):
        app = gui.ReauthApp(self.root)
        self.assertFalse(app.use_proxy_var.get())
        self.assertIsNone(app.current_proxy())
        self.assertTrue(app.proxy_entry.cget("show"))
        app.proxy_var.set("127.0.0.1:8080:synthetic-user:synthetic-password")
        self.assertTrue(app.use_proxy_var.get())
        self.assertEqual(app.current_proxy(), "http://synthetic-user:synthetic-password@127.0.0.1:8080")
        app.use_proxy_var.set(False)
        self.assertIsNone(app.current_proxy())
        self.assertTrue(app.proxy_var.get())

    def test_worker_receives_normalized_proxy(self):
        app = gui.ReauthApp(self.root)
        app.proxy_var.set("127.0.0.1:8080:synthetic-user:synthetic-password")
        inputs = [AccountInput("first@example.com", "dummy", "dummy", 1)]
        with patch.object(gui.threading, "Thread") as thread_factory:
            app._start_batch(inputs, retry=False)
        self.assertEqual(thread_factory.call_args.kwargs["args"][2], "http://synthetic-user:synthetic-password@127.0.0.1:8080")
        self.assertNotIn("synthetic-password", app.log_text.get("1.0", "end-1c"))

    def test_invalid_proxy_is_rejected_before_worker_or_task_lock(self):
        app = gui.ReauthApp(self.root)
        app.proxy_var.set("not-a-proxy:synthetic-password")
        inputs = [AccountInput("first@example.com", "dummy", "dummy", 1)]
        with patch.object(gui.threading, "Thread") as thread_factory:
            app._start_batch(inputs, retry=False)
        thread_factory.assert_not_called()
        self.assertFalse(gui._TASK_LOCK.locked())
        self.assertFalse(app.running)
        self.dialogs[1].assert_called_once()
        self.assertNotIn("synthetic-password", str(self.dialogs[1].call_args))

    def test_enabled_empty_proxy_requires_input(self):
        app = gui.ReauthApp(self.root)
        app.use_proxy_var.set(True)
        with self.assertRaises(ValueError):
            app.current_proxy()

    def test_proxy_failure_and_worker_logs_mask_credentials(self):
        app = gui.ReauthApp(self.root)
        proxy = "http://synthetic-user:synthetic-password@127.0.0.1:8080"
        with patch.object(gui, "run_batch_reauth", side_effect=RuntimeError(f"proxy {proxy}, password synthetic-password")):
            app._run_worker([], 30, proxy, True)
        events = []
        while not app.event_queue.empty():
            events.append(app.event_queue.get_nowait())
        self.assertTrue(any(event[0] == "failed" for event in events))
        self.assertNotIn("synthetic-password", str(events))

    @unittest.skipUnless(os.name == "nt", "Windows DPAPI")
    def test_saved_proxy_is_encrypted_and_disabled_choice_survives_load(self):
        app = gui.ReauthApp(self.root)
        proxy = "127.0.0.1:8080:synthetic-user:synthetic-password"
        app.proxy_var.set(proxy)
        app.use_proxy_var.set(False)
        app._save_auth_settings()
        saved = json.loads(self.auth_config.read_text(encoding="utf-8"))
        self.assertTrue(saved["proxy"].startswith("dpapi:"))
        self.assertNotIn("synthetic-password", self.auth_config.read_text(encoding="utf-8"))
        app.proxy_var.set("")
        app._load_auth_settings()
        self.assertEqual(app.proxy_var.get(), proxy)
        self.assertFalse(app.use_proxy_var.get())

    def test_forget_proxy_removes_saved_secret_without_discarding_session_value(self):
        app = gui.ReauthApp(self.root)
        app.proxy_var.set("127.0.0.1:8080:synthetic-user:synthetic-password")
        app.remember_proxy_var.set(False)
        app._save_auth_settings()
        saved = json.loads(self.auth_config.read_text(encoding="utf-8"))
        self.assertEqual(saved["proxy"], "")
        self.assertFalse(saved["remember_proxy"])
        self.assertIn("synthetic-password", app.proxy_var.get())

    def test_encryption_failure_never_saves_plaintext(self):
        app = gui.ReauthApp(self.root)
        app.proxy_var.set("127.0.0.1:8080:synthetic-user:synthetic-password")
        with patch.object(gui, "_protect_setting", return_value=""):
            app._save_auth_settings()
        saved = json.loads(self.auth_config.read_text(encoding="utf-8"))
        self.assertEqual(saved["proxy"], "")
        self.assertNotIn("synthetic-password", self.auth_config.read_text(encoding="utf-8"))
        self.assertIn("仅在内存中使用", app.log_text.get("1.0", "end-1c"))


if __name__ == "__main__":
    unittest.main()
