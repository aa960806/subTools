"""Human-like pacing regressions: ranges, typing, cancellation and cost."""

import time
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from human_pacing import (
    AuthFlowError,
    STEP_RANGES,
    HumanSettings,
    human_delay,
    human_settings_from_options,
    type_like_human,
)


class SettingsTests(unittest.TestCase):
    def test_disabled_settings_never_wait(self):
        settings = HumanSettings(enabled=False)
        started = time.monotonic()
        slept = human_delay(settings, "open_page")
        self.assertEqual(slept, 0.0)
        self.assertLess(time.monotonic() - started, 0.05)

    def test_missing_options_disable_pacing(self):
        self.assertFalse(human_settings_from_options(None).enabled)
        self.assertFalse(human_settings_from_options({}).enabled)

    def test_scale_multiplies_range_and_rejects_invalid_values(self):
        for value in (0, 999, 'nan', 'inf', '-inf', 'invalid'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                human_settings_from_options({"scale": value})
        scaled = HumanSettings(enabled=True, scale=2.0).range_for("open_page")
        self.assertEqual(scaled, (2.0, 4.0))

    def test_every_flow_step_has_a_positive_range(self):
        for step in ("open_page", "type_email", "type_password", "type_otp", "between_accounts",
                     "phone_form", "phone_send", "phone_type_code"):
            low, high = STEP_RANGES[step]
            self.assertGreater(low, 0, step)
            self.assertGreaterEqual(high, low, step)

    def test_wait_stays_inside_range(self):
        settings = HumanSettings(enabled=True, seed=7)
        low, high = STEP_RANGES["open_page"]
        with patch("human_pacing.time.sleep"):
            slept = human_delay(settings, "open_page", log_fn=lambda _line: None)
        self.assertGreaterEqual(round(slept, 6), low)
        self.assertLessEqual(round(slept, 6), high)

    def test_cancellation_stops_the_wait_early(self):
        settings = HumanSettings(enabled=True, seed=1)
        with patch("human_pacing.time.sleep") as sleeper:
            with self.assertRaises(AuthFlowError) as caught:
                human_delay(settings, "between_accounts", should_stop=lambda: True)
        self.assertEqual(caught.exception.category, 'cancelled')
        sleeper.assert_not_called()

    def test_deadline_truncates_the_wait(self):
        settings = HumanSettings(enabled=True, overrides={"open_page": (5.0, 5.0)})
        with self.assertRaises(AuthFlowError) as caught:
            human_delay(settings, "open_page", deadline=time.monotonic() + 0.2)
        self.assertEqual(caught.exception.category, 'timeout')

    def test_log_is_emitted_once_and_names_the_step(self):
        settings = HumanSettings(enabled=True, seed=3, overrides={"type_email": (0.2, 0.2)})
        lines = []
        human_delay(settings, "type_email", log_fn=lines.append)
        self.assertEqual(len(lines), 1)
        self.assertIn("输入邮箱", lines[0])
        self.assertIn("模拟人工", lines[0])


class TypingTests(unittest.TestCase):
    def test_typing_falls_back_when_disabled(self):
        locator = Mock()
        self.assertFalse(type_like_human(locator, "abc", HumanSettings(enabled=False)))
        locator.fill.assert_not_called()
        locator.type.assert_not_called()

    def test_typing_uses_the_locator_and_not_fill(self):
        locator = Mock()
        settings = HumanSettings(enabled=True, scale=0.1, seed=5)
        self.assertTrue(type_like_human(locator, "user@example.com", settings))
        locator.type.assert_called()
        locator.fill.assert_not_called()

    def test_empty_text_is_not_typed(self):
        locator = Mock()
        self.assertFalse(type_like_human(locator, "", HumanSettings(enabled=True)))


if __name__ == "__main__":
    unittest.main()
