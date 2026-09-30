"""Offline provider protocol checks. No live key/config is ever loaded."""
import unittest
from unittest.mock import patch

import httpx

from phone_smsbower import SmsBowerClient, SmsBowerError, parse_country_choice, validate_price


class PhoneClientTests(unittest.TestCase):
    def setUp(self):
        self.client = SmsBowerClient(api_key="fixture-secret")

    def test_provider_credentials_and_balance_errors_are_fatal(self):
        for response in ("BAD_KEY", "NO_BALANCE", '{"error":"BAD_KEY"}'):
            with self.subTest(response=response), patch.object(self.client, "_do", return_value=response):
                with self.assertRaises(SmsBowerError) as caught:
                    self.client.get_number()
                self.assertEqual(caught.exception.category, "sms_fatal")

    def test_query_errors_do_not_expose_key_or_request_url(self):
        request = httpx.Request("GET", "https://sms.example/?api_key=fixture-secret")
        with patch("phone_smsbower.httpx.Client") as client:
            client.return_value.__enter__.return_value.get.side_effect = httpx.ConnectError("fixture-secret", request=request)
            with self.assertRaises(SmsBowerError) as caught:
                self.client.get_number()
        self.assertEqual(caught.exception.category, "sms_fatal")
        self.assertNotIn("fixture-secret", str(caught.exception))
        self.assertNotIn("https://", str(caught.exception))
        self.assertNotIn("fixture-secret", repr(self.client))

    def test_proxy_applies_and_redirects_are_disabled(self):
        self.client.proxy = "http://127.0.0.1:1234"
        with patch("phone_smsbower.httpx.Client") as client:
            response = client.return_value.__enter__.return_value.get.return_value
            response.text = "ACCESS_BALANCE:9.02"
            self.assertEqual(self.client.get_balance(), "9.02")
        self.assertEqual(client.call_args.kwargs["proxy"], self.client.proxy)
        self.assertFalse(client.call_args.kwargs["follow_redirects"])

    def test_poll_fatal_error_is_not_hidden_as_timeout(self):
        error = SmsBowerError("sms_fatal", "BAD_KEY")
        with patch.object(self.client, "get_status", side_effect=error) as poll:
            with self.assertRaises(SmsBowerError) as caught:
                self.client.wait_for_code("fixture", timeout=60)
        self.assertEqual(caught.exception.category, "sms_fatal")
        poll.assert_called_once()

    def test_poll_cancellation_does_not_query_provider(self):
        with patch.object(self.client, "get_status") as poll:
            with self.assertRaises(SmsBowerError) as caught:
                self.client.wait_for_code("fixture", should_stop=lambda: True)
        self.assertEqual(caught.exception.category, "cancelled")
        poll.assert_not_called()

    def test_malformed_buy_response_is_ambiguous_and_fatal(self):
        for response in ('<html>unavailable</html>', '{"activationId":"allocated-but-no-phone"}', 'ACCESS_NUMBER::233'):
            with self.subTest(response=response), patch.object(self.client, "_do", return_value=response):
                with self.assertRaises(SmsBowerError) as caught:
                    self.client.get_number()
                self.assertEqual(caught.exception.category, "sms_fatal")
                self.assertEqual(caught.exception.code, "UNKNOWN_PURCHASE")

    def test_reuse_ignores_old_code_and_wait_retry(self):
        statuses = [dict(status="OK", code="111111"), dict(status="WAIT_RETRY", code="111111"), dict(status="OK", code="222222")]
        with patch.object(self.client, "get_status", side_effect=statuses):
            self.assertEqual(self.client.wait_for_code("fixture", previous_code="111111", poll_interval=0), "222222")

    def test_unknown_country_is_rejected_instead_of_buying_in_ghana(self):
        with self.assertRaises(ValueError):
            parse_country_choice("unsupported-country")

    def test_invalid_prices_are_rejected_before_network(self):
        for value in ("-1", "NaN", "inf", "abc", "0"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_price(value)
        self.assertEqual(validate_price(""), "")
        self.assertEqual(validate_price("0.06"), "0.06")


if __name__ == "__main__":
    unittest.main()
