from pathlib import Path
import json
import sys
import unittest
import tempfile
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from phone_flow import account_input_from_mapping, parse_phone_jobs
from phone_pool import PhonePool, PhoneSlot, SmsbowerSettings
from phone_smsbower import country_dropdown_values, country_label, parse_country_choice
import openai_reauth_gui as gui


def cpa(email="first@example.com"):
    return {
        "type": "codex", "email": email, "expired": "2027-01-15T00:00:00.000+08:00",
        "id_token": "id", "account_id": "acc", "disabled": False,
        "access_token": "at", "last_refresh": "2026-09-17T09:00:00.000+08:00",
        "refresh_token": "rt", "password": "secret-pass",
    }


class ParseJobsTests(unittest.TestCase):
    def test_cpa_and_sub2_and_text_lines(self):
        jobs = parse_phone_jobs(json.dumps(cpa()))
        self.assertEqual(jobs[0].email, "first@example.com")
        self.assertEqual(jobs[0].password, "secret-pass")
        sub2 = {"exported_at": "2026-09-17T00:00:00Z", "accounts": [{
            "name": "second@example.com", "platform": "openai", "type": "oauth",
            "credentials": {"access_token": "at", "refresh_token": "rt", "email": "second@example.com"},
            "extra": {"password": "pw2", "totp_secret": "JBSWY3DPEHPK3PXP"},
        }]}
        jobs = parse_phone_jobs(json.dumps(sub2))
        self.assertEqual(jobs[0].email, "second@example.com")
        self.assertEqual(jobs[0].password, "pw2")
        jobs = parse_phone_jobs("third@example.com----pw3----JBSWY3DPEHPK3PXP")
        self.assertEqual(jobs[0].email, "third@example.com")
        jobs = parse_phone_jobs("fourth@example.com----pw4")
        self.assertEqual(jobs[0].password, "pw4")

    def test_mapping_reads_nested_secrets(self):
        job = account_input_from_mapping({
            "name": "a@b.com",
            "credentials": {"email": "a@b.com", "access_token": "at"},
            "extra": {"login_password": "hidden", "2fa": "JBSWY3DPEHPK3PXP"},
        })
        self.assertEqual(job.password, "hidden")
        self.assertTrue(job.totp_secret)


class CountryChoiceTests(unittest.TestCase):
    def test_dropdown_shows_readable_names_and_maps_back_to_code(self):
        self.assertEqual(country_label("38"), "加纳（Ghana）")
        self.assertEqual(parse_country_choice("加纳（Ghana）"), "38")
        self.assertEqual(parse_country_choice("加纳"), "38")
        self.assertEqual(parse_country_choice("38"), "38")
        self.assertIn("加纳（Ghana）", country_dropdown_values())
        self.assertIn("美国（USA）", country_dropdown_values())


class PoolTests(unittest.TestCase):
    def test_mark_used_exhausts_and_completes(self):
        settings = SmsbowerSettings(api_key="k", max_reuse=1)
        pool = PhonePool(settings)
        pool.slot = PhoneSlot(settings=settings, phone="+2331", activation_id="act1")
        pool.client = Mock()
        pool.client.complete.return_value = True
        info = pool.mark_used()
        self.assertEqual(info["reuse_count"], 1)
        self.assertEqual(info["remaining"], 0)
        pool.client.complete.assert_called_once_with("act1")
        self.assertEqual(pool.slot.activation_id, "")


class PhonePageTests(unittest.TestCase):
    def setUp(self):
        import tkinter as tk
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        config = patch.object(gui, "PHONE_CONFIG_PATH", Path(folder.name) / "phone.json")
        config.start()
        self.addCleanup(config.stop)
        auth_config = patch.object(gui, "AUTH_CONFIG_PATH", Path(folder.name) / "auth.json")
        auth_config.start()
        self.addCleanup(auth_config.stop)
        self.root = tk.Tk()
        self.root.withdraw()
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        import tkinter as tk
        try:
            for handle in self.root.tk.splitlist(self.root.tk.call("after", "info")):
                self.root.after_cancel(handle)
            self.root.destroy()
        except tk.TclError:
            pass

    def test_navigation_keeps_reauth_input(self):
        app = gui.ReauthApp(self.root)
        app._clear_placeholder()
        app.accounts_text.insert("1.0", "draft")
        app.open_phone()
        self.assertIs(app.phone_page.win.winfo_toplevel(), self.root)
        app.show_authorization()
        self.assertEqual(app.account_text(), "draft")
        app.open_converter()
        app.open_phone()
        self.assertIsNotNone(app.phone_page)

    def test_start_requires_api_key(self):
        app = gui.ReauthApp(self.root)
        app.open_phone()
        page = app.phone_page
        page.set_input(json.dumps(cpa()))
        with patch.object(gui.messagebox, "showerror") as error:
            page.start()
        error.assert_called()
        self.assertFalse(page.running)

    def test_country_dropdown_defaults_to_ghana_name(self):
        app = gui.ReauthApp(self.root)
        app.open_phone()
        page = app.phone_page
        self.assertEqual(page.country_var.get(), "加纳（Ghana）")
        self.assertEqual(page.current_settings().country, "38")


if __name__ == "__main__":
    unittest.main()
