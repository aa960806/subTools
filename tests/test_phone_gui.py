"""Phone UI regressions. All configuration and batch work stays in fixtures."""

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
from openai_reauth import ReauthResult


class PhoneGuiTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.config = Path(self.folder.name) / "phone.json"
        for change in (patch.object(gui, "PHONE_CONFIG_PATH", self.config),
                       patch.object(gui, "AUTH_CONFIG_PATH", Path(self.folder.name) / "auth.json"),
                       patch("phone_network.system_proxy", return_value=""),
                       patch.object(gui, "_TASK_LOCK", threading.Lock())):
            change.start()
            self.addCleanup(change.stop)
        self.root = tk.Tk()
        self.root.withdraw()
        self.addCleanup(self.cleanup_tk)
        self.app = gui.ReauthApp(self.root)
        self.app.open_phone()
        self.page = self.app.phone_page

    def cleanup_tk(self):
        try:
            for handle in self.root.tk.splitlist(self.root.tk.call("after", "info")):
                self.root.after_cancel(handle)
            self.root.destroy()
        except tk.TclError:
            pass

    def test_import_mixed_files_keeps_parser_boundaries(self):
        text = Path(self.folder.name) / "rows.txt"
        obj = Path(self.folder.name) / "account.json"
        text.write_text("line@example.com----line-password", encoding="utf-8")
        obj.write_text(json.dumps({"email": "json@example.com", "password": "json-password"}), encoding="utf-8")
        with patch.object(gui.filedialog, "askopenfilenames", return_value=[str(text), str(obj)]):
            self.page.load_file()
        self.page.api_key_var.set("test-key")
        with patch.object(gui.threading, "Thread") as thread:
            self.page.start()
        jobs = thread.call_args.kwargs["args"][0]
        self.assertEqual([job.email for job in jobs], ["line@example.com", "json@example.com"])

    def test_bad_file_does_not_discard_valid_files(self):
        good = Path(self.folder.name) / "good.txt"
        missing = Path(self.folder.name) / "missing.txt"
        good.write_text("valid@example.com----pw", encoding="utf-8")
        with patch.object(gui.filedialog, "askopenfilenames", return_value=[str(good), str(missing)]), patch.object(gui.messagebox, "showwarning") as warning:
            self.page.load_file()
        self.assertIn("valid@example.com", self.page.input_value())
        self.assertIn("missing.txt", warning.call_args.args[1])

    def test_start_cannot_overlap_other_page(self):
        self.page.set_input("example@example.com----pw")
        self.page.api_key_var.set("test-key")
        gui._TASK_LOCK.acquire()
        with patch.object(gui.threading, "Thread") as thread, patch.object(gui.messagebox, "showwarning") as warning:
            self.page.start()
            self.app._start_batch([], retry=False)
        thread.assert_not_called()
        self.assertEqual(warning.call_count, 2)
        self.assertFalse(self.page.running)

    def test_close_waits_for_phone_worker_and_requests_stop(self):
        self.page.worker = Mock()
        self.page.worker.is_alive.return_value = True
        self.app.on_close()
        self.assertTrue(self.page.stop_flag.is_set())
        self.assertTrue(self.page.closing)
        self.assertTrue(self.root.winfo_exists())
        self.assertTrue(self.app._after_ids)

    def test_results_keep_binding_oauth_cancel_and_pending_separate(self):
        results = [
            ReauthResult("bound@example.com", False, phone_status="verified", error="token exchange failed"),
            ReauthResult("oauth@example.com", True, phone_status="not_triggered"),
            ReauthResult("failed@example.com", False, phone_status="failed"),
            ReauthResult("cancel@example.com", False, phone_status="cancelled", category="cancelled"),
        ]
        self.page.event_queue.put(("done", results, 5))
        self.page._drain()
        status = self.page.status_var.get()
        for value in ("补绑 1", "未补绑 1", "失败 1", "取消 1", "未处理 1"):
            self.assertIn(value, status)

    def test_retry_default_and_zero_map_to_total_attempts(self):
        self.assertEqual(self.page.auto_retry_count_var.get(), "2")
        self.assertEqual(self.page.current_settings().number_attempts, 3)
        for retries in (0, 1, 4):
            with self.subTest(retries=retries):
                self.page.auto_retry_count_var.set(str(retries))
                self.assertEqual(self.page.current_settings().number_attempts, retries + 1)
                self.assertIn(f"重试 {retries} 次", self.page.retry_hint_var.get())

    def test_retry_config_roundtrip_preserves_zero_and_defaults_legacy(self):
        self.page.auto_retry_count_var.set("0")
        self.page._save_settings()
        self.assertEqual(json.loads(self.config.read_text(encoding="utf-8"))["auto_retry_count"], "0")
        self.page.auto_retry_count_var.set("8")
        self.page._load_settings()
        self.assertEqual(self.page.current_settings().number_attempts, 1)
        self.config.write_text(json.dumps({"country": "38"}), encoding="utf-8")
        self.page._load_settings()
        self.assertEqual(self.page.auto_retry_count_var.get(), "2")

    def test_invalid_retry_count_cannot_start_or_save(self):
        self.page.set_input("example@example.com----pw")
        self.page.api_key_var.set("test-key")
        for invalid in ("-1", "1.5", "NaN", "", "many", "1e2"):
            with self.subTest(retries=invalid):
                self.page.auto_retry_count_var.set(invalid)
                with patch.object(gui.threading, "Thread") as thread, patch.object(self.page, "_save_settings") as save, patch.object(gui.messagebox, "showerror") as error:
                    self.page.start()
                thread.assert_not_called()
                save.assert_not_called()
                self.assertIn("自动重试次数", error.call_args.args[1])
                self.assertFalse(self.page.running)
                self.assertFalse(gui._TASK_LOCK.locked())

    def test_selected_retry_count_is_passed_to_worker(self):
        self.page.set_input("example@example.com----pw")
        self.page.api_key_var.set("test-key")
        self.page.auto_retry_count_var.set("4")
        with patch.object(gui.threading, "Thread") as thread:
            self.page.start()
        settings = thread.call_args.kwargs["args"][1]
        self.assertEqual(settings.number_attempts, 5)
        self.assertIn("自动重试 4 次", self.page.log_text.get("1.0", "end"))

    def test_circuit_stop_preserves_results_and_unprocessed_counts(self):
        for category, reason in (("circuit_open", "重试次数或接码时限已耗尽"), ("phone_fraud", "fraud_guard")):
            with self.subTest(category=category):
                results = [
                    ReauthResult("bound@example.com", True, phone_status="verified"),
                    ReauthResult("stop@example.com", False, phone_status="failed", category=category),
                ]
                self.page.event_queue.put(("progress", 2, 4, results[-1]))
                self.page._drain()
                self.assertIn("已熔断", self.page.status_var.get())
                self.page.event_queue.put(("done", results, 4))
                self.page._drain()
                status = self.page.status_var.get()
                for value in ("已熔断", "补绑 1", "失败 1", "未处理 2"):
                    self.assertIn(value, status)
                self.assertEqual(self.page.last_results, results)
                self.assertIn(reason, self.page.log_text.get("1.0", "end"))
                self.assertFalse(self.page.running)

    def test_country_retry_defaults_preserve_existing_small_retry_behavior(self):
        self.assertEqual(self.page.country_retry_count_var.get(), "0")
        self.assertEqual(self.page.current_settings().country_retry_count, 0)
        self.assertEqual(self.page.current_settings().fallback_countries, [])

    def add_country(self, code):
        self.page.fallback_country_var.set(gui.country_label(code))
        self.page._add_fallback_country()

    def test_custom_countries_order_remove_and_no_duplicate_selection(self):
        self.add_country("16")
        self.add_country("36")
        self.add_country("16")
        self.add_country("38")
        self.assertEqual(self.page._fallback_countries, ["16", "36"])
        self.page.fallback_country_list.selection_clear(0, tk.END)
        self.page.fallback_country_list.selection_set(1)
        self.page._move_fallback_country(-1)
        self.assertEqual(self.page._fallback_countries, ["36", "16"])
        self.page.country_retry_count_var.set("2")
        settings = self.page.current_settings()
        self.assertEqual(settings.fallback_countries, ["36", "16"])
        self.assertEqual(settings.country_retry_count, 2)
        self.assertIn("9 次尝试", self.page.retry_hint_var.get())
        self.page._remove_fallback_country()
        self.assertEqual(self.page._fallback_countries, ["16"])

    def test_large_retries_need_enough_distinct_countries_before_any_worker(self):
        self.page.set_input("example@example.com----pw")
        self.page.api_key_var.set("test-key")
        self.page.country_retry_count_var.set("2")
        self.add_country("16")
        with patch.object(gui.threading, "Thread") as thread, patch.object(gui.messagebox, "showerror") as error:
            self.page.start()
        thread.assert_not_called()
        self.assertIn("至少添加 2 个", error.call_args.args[1])
        self.assertFalse(gui._TASK_LOCK.locked())

    def test_two_tier_configuration_persists_and_passes_to_worker(self):
        self.page.set_input("example@example.com----pw")
        self.page.api_key_var.set("test-key")
        self.page.auto_retry_count_var.set("1")
        self.page.country_retry_count_var.set("2")
        self.add_country("16")
        self.add_country("36")
        self.page._save_settings()
        saved = json.loads(self.config.read_text(encoding="utf-8"))
        self.assertEqual(saved["country_retry_count"], "2")
        self.assertEqual(saved["fallback_countries"], ["16", "36"])
        self.page.country_retry_count_var.set("0")
        self.page._fallback_countries = []
        self.page._load_settings()
        with patch.object(gui.threading, "Thread") as thread:
            self.page.start()
        settings = thread.call_args.kwargs["args"][1]
        self.assertEqual(settings.country_retry_count, 2)
        self.assertEqual(settings.fallback_countries, ["16", "36"])
        self.assertEqual(settings.number_attempts, 2)
        self.assertIn("6 次尝试", self.page.retry_hint_var.get())

    def test_invalid_large_count_and_changed_primary_require_correction(self):
        for value in ("-1", "", "1.5", "bad"):
            with self.subTest(value=value):
                self.page.country_retry_count_var.set(value)
                with self.assertRaisesRegex(ValueError, "大重试"):
                    self.page.current_settings()
        self.page.country_retry_count_var.set("1")
        self.add_country("16")
        self.page.country_var.set(gui.country_label("16"))
        with self.assertRaisesRegex(ValueError, "相同"):
            self.page.current_settings()

    def test_legacy_credentials_migrate_without_plaintext(self):
        self.config.write_text(json.dumps({"api_key": "test-key-secret", "proxy": "http://name:pass@example.test:8080", "max_price": ""}), encoding="utf-8")
        self.page._load_settings()
        saved = self.config.read_text(encoding="utf-8")
        self.assertNotIn("test-key-secret", saved)
        self.assertNotIn("name:pass", saved)
        self.assertEqual(self.page.api_key_var.get(), "test-key-secret")
        self.assertEqual(self.page.max_price_var.get(), "")
        if os.name == "nt":
            protected = json.loads(saved)["api_key"]
            self.assertTrue(protected.startswith("dpapi:"))
            self.assertEqual(gui._unprotect_setting(protected), "test-key-secret")

    def test_circuit_log_keeps_timeout_reason_and_redacts_secret(self):
        self.page._log_secrets = ("test-key-secret",)
        result = ReauthResult("stop@example.com", False, phone_status="failed", category="circuit_open", error="接码总时限耗尽 test-key-secret")
        self.page.event_queue.put(("done", [result], 2))
        self.page._drain()
        output = self.page.log_text.get("1.0", "end")
        self.assertIn("接码总时限耗尽", output)
        self.assertNotIn("test-key-secret", output)

    def test_proxy_protocol_applies_to_raw_address_and_url_takes_priority(self):
        self.assertEqual(self.page.proxy_scheme_var.get(), "HTTP")
        self.page.proxy_var.set("127.0.0.1:8080:synthetic-user:synthetic-password")
        for protocol in ("HTTP", "HTTPS", "SOCKS5"):
            with self.subTest(protocol=protocol):
                self.page.proxy_scheme_var.set(protocol)
                self.assertEqual(self.page.current_settings().proxy, f"{protocol.lower()}://synthetic-user:synthetic-password@127.0.0.1:8080")
        self.page.proxy_var.set("https://synthetic-user:synthetic-password@127.0.0.1:8080")
        self.assertTrue(self.page.current_settings().proxy.startswith("https://"))
        self.page.proxy_scheme_var.set("HTTP")
        self.page.proxy_var.set("socks5://synthetic-user:synthetic-password@127.0.0.1:8080")
        self.assertTrue(self.page.current_settings().proxy.startswith("socks5://"))

    def test_proxy_protocol_roundtrip_and_legacy_default(self):
        self.page.proxy_scheme_var.set("SOCKS5")
        self.page._save_settings()
        self.assertEqual(json.loads(self.config.read_text(encoding="utf-8"))["proxy_scheme"], "socks5")
        self.page.proxy_scheme_var.set("HTTPS")
        self.page._load_settings()
        self.assertEqual(self.page.proxy_scheme_var.get(), "SOCKS5")
        self.config.write_text("{}", encoding="utf-8")
        self.page._load_settings()
        self.assertEqual(self.page.proxy_scheme_var.get(), "HTTP")

    def test_session_only_does_not_store_credentials(self):
        self.page.api_key_var.set("test-key-secret")
        self.page.proxy_var.set("http://name:pass@example.test:8080")
        self.page.remember_key_var.set(False)
        self.page._save_settings()
        saved = json.loads(self.config.read_text(encoding="utf-8"))
        self.assertEqual(saved["api_key"], "")
        self.assertEqual(saved["proxy"], "")

    def test_legacy_invalid_country_still_migrates_credentials(self):
        self.config.write_text(json.dumps({"api_key": "legacy-secret", "country": "not-a-country"}), encoding="utf-8")
        self.page._load_settings()
        saved = self.config.read_text(encoding="utf-8")
        self.assertNotIn("legacy-secret", saved)
        self.assertEqual(self.page.country_var.get(), "not-a-country")
        with self.assertRaises(ValueError):
            self.page.current_settings()

    def test_price_validation_and_no_hidden_sms_timeout_cap(self):
        for price in ("NaN", "Infinity", "-1", "0", "no-price"):
            self.page.max_price_var.set(price)
            with self.assertRaises(ValueError):
                self.page.current_settings()
        self.page.max_price_var.set("")
        self.page.timeout_var.set("300")
        self.assertEqual(self.page.current_settings().sms_timeout, 300)

    def test_error_and_log_redact_key(self):
        self.page._log_secrets = ("test-key-secret",)
        self.page.event_queue.put(("fail", "failed with test-key-secret"))
        with patch.object(gui.messagebox, "showerror") as error:
            self.page._drain()
        self.assertNotIn("test-key-secret", error.call_args.args[1])
        self.assertNotIn("test-key-secret", self.page.log_text.get("1.0", "end"))

    def test_settings_panel_can_scroll_at_small_height(self):
        # Map a fully transparent window: withdrawn Tk windows keep stale
        # geometry, so they cannot establish that the controls fit the screen.
        self.root.attributes("-alpha", 0)
        self.root.minsize(980, 620)
        self.root.geometry("1140x678+0+0")
        self.root.deiconify()
        for percent in (125, 150):
            with self.subTest(scale=percent):
                self.root.tk.call("tk", "scaling", 96 * percent / 100 / 72)
                gui.setup_theme(self.root)
                self.page.settings_tabs.select(0)
                self.root.update()
                self.root.update_idletasks()
                self.assertEqual(self.root.winfo_height(), 678)
                self.assertGreater(self.page.input_text.winfo_height(), 50)
                self.assertGreater(self.page.log_text.winfo_height(), 20)
                bottom = (self.page.log_text.winfo_rooty() - self.root.winfo_rooty()
                          + self.page.log_text.winfo_height())
                self.assertLess(bottom, self.root.winfo_height())
                self.assertTrue(self.page.options_canvas.cget("yscrollcommand"))
                scroll = list(map(float, self.page.options_canvas.cget("scrollregion").split()))
                self.assertGreater(scroll[3], self.page.options_canvas.winfo_height())
                fixed_positions = [(control.winfo_rootx(), control.winfo_rooty()) for control in
                                   (self.page.network_mode_combo, self.page.show_browser_check)]
                self.page.options_canvas.yview_moveto(1)
                self.root.update_idletasks()
                canvas = self.page.options_canvas
                for control, position in zip((self.page.network_mode_combo, self.page.show_browser_check), fixed_positions):
                    self.assertEqual((control.winfo_rootx(), control.winfo_rooty()), position)
                    self.assertGreaterEqual(control.winfo_rooty(), self.root.winfo_rooty())
                    self.assertLessEqual(control.winfo_rooty() + control.winfo_height(), canvas.winfo_rooty())
                self.page.settings_tabs.select(2)
                self.root.update_idletasks()
                canvas = self.page.runtime_canvas
                canvas.yview_moveto(1)
                self.root.update_idletasks()
                last = self.page.remember_key_check
                self.assertGreaterEqual(last.winfo_rooty(), canvas.winfo_rooty())
                self.assertLessEqual(last.winfo_rooty() + last.winfo_height(), canvas.winfo_rooty() + canvas.winfo_height())


if __name__ == "__main__":
    unittest.main()
