"""Prevent additional paid purchases after cancellation, timeout, or ambiguity."""
import json
import unittest
from unittest.mock import Mock, patch

from phone_flow import parse_phone_jobs
from phone_pool import PhonePool, PhonePoolError, SmsbowerSettings
from phone_smsbower import SmsBowerError


class PurchaseLimitsTests(unittest.TestCase):
    def test_no_second_purchase_after_deadline(self):
        pool = PhonePool(SmsbowerSettings(api_key="fixture", number_attempts=3))
        pool.client = Mock()
        clock = [179.0]

        def unavailable(**kwargs):
            self.assertLessEqual(kwargs['timeout'], 1.0)
            clock[0] = 181.0
            raise SmsBowerError('sms_unavailable', 'NO_NUMBERS', 'NO_NUMBERS')

        pool.client.get_number.side_effect = unavailable
        with patch('phone_pool.time.monotonic', side_effect=lambda: clock[0]):
            with self.assertRaises(PhonePoolError) as caught:
                pool.prepare_for_send(deadline=180)
        self.assertEqual(caught.exception.category, 'timeout')
        pool.client.get_number.assert_called_once()

    def test_unknown_typed_error_does_not_retry_purchase(self):
        pool = PhonePool(SmsbowerSettings(api_key='fixture', number_attempts=3))
        pool.client = Mock()
        pool.client.get_number.side_effect = SmsBowerError('sms_provider', 'Unknown', 'UNKNOWN')
        with self.assertRaises(PhonePoolError) as caught:
            pool.prepare_for_send()
        self.assertEqual(caught.exception.category, 'sms_fatal')
        pool.client.get_number.assert_called_once()


class LoginInputTests(unittest.TestCase):
    def test_standard_token_only_cpa_is_accepted_without_inventing_password(self):
        account = parse_phone_jobs(json.dumps({'type': 'codex', 'email': 'test@example.com', 'access_token': 'fixture'}))[0]
        self.assertEqual(account.password, '')
        self.assertEqual(account.totp_secret, '')

    def test_json_totp_is_normalized_and_validated(self):
        raw = {'name': 'test@example.com', 'extra': {'password': 'fixture', '2fa': 'jbsw y3dp\nehpk3pxp'}}
        self.assertEqual(parse_phone_jobs(json.dumps(raw))[0].totp_secret, 'JBSWY3DPEHPK3PXP')
        raw['extra']['2fa'] = 'INVALID!'
        with self.assertRaisesRegex(ValueError, 'Base32'):
            parse_phone_jobs(json.dumps(raw))

    def test_invalid_json_entries_are_not_silently_dropped(self):
        with self.assertRaisesRegex(ValueError, 'JSON'):
            parse_phone_jobs('[{"email":"test@example.com"}, null]')

    def test_mixed_wrappers_and_standalone_documents(self):
        raw = json.dumps({'accounts': [{'name': 'first@example.com', 'extra': {'password': 'fixture'}}]})
        raw += '\n' + json.dumps({'email': 'second@example.com', 'password': 'fixture'})
        self.assertEqual(len(parse_phone_jobs(raw)), 2)


if __name__ == '__main__':
    unittest.main()
