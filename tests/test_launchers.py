"""Static entry-point checks and startup-error reporting without opening a GUI."""

import importlib.util
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("reauth_launcher", ROOT / "launch_gui.py")
launcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launcher)


class LauncherTests(unittest.TestCase):
    def test_entry_points_do_not_embed_installation_paths(self):
        for name in ("start.bat", "OpenAI-Reauth.vbs", "make_shortcut.ps1"):
            with self.subTest(name=name):
                text = (ROOT / name).read_text(encoding="utf-8")
                self.assertIsNone(re.search(r"[A-Za-z]:\\", text))
        self.assertIn("%~dp0", (ROOT / "start.bat").read_text())
        self.assertIn("WScript.ScriptFullName", (ROOT / "OpenAI-Reauth.vbs").read_text())
        self.assertIn("$PSScriptRoot", (ROOT / "make_shortcut.ps1").read_text())

    def test_startup_exception_is_saved_and_reported(self):
        with tempfile.TemporaryDirectory(prefix="reauth launcher ") as directory:
            root = Path(directory)
            stdout, stderr = sys.stdout, sys.stderr
            with patch.object(launcher, "__file__", str(root / "launch_gui.py")), \
                 patch.object(launcher.os, "chdir"), \
                 patch.object(launcher.runpy, "run_path", side_effect=ImportError("missing test dependency")), \
                 patch.object(launcher, "_show_error") as show:
                self.assertEqual(launcher.main(), 1)
            log_path = root / "gui-error.log"
            self.assertIn("missing test dependency", log_path.read_text(encoding="utf-8"))
            self.assertIn(str(log_path), show.call_args.args[0])
            self.assertIs(sys.stdout, stdout)
            self.assertIs(sys.stderr, stderr)

    def test_normal_exit_does_not_report_error(self):
        with tempfile.TemporaryDirectory(prefix="reauth launcher ") as directory:
            with patch.object(launcher, "__file__", str(Path(directory) / "launch_gui.py")), \
                 patch.object(launcher.os, "chdir"), \
                 patch.object(launcher.runpy, "run_path", side_effect=SystemExit(0)), \
                 patch.object(launcher, "_show_error") as show:
                self.assertEqual(launcher.main(), 0)
            show.assert_not_called()


if __name__ == "__main__":
    unittest.main()
