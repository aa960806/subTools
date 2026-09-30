import base64
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import openai_reauth as core


class OAuthTests(unittest.TestCase):
    def test_pkce_is_independent_and_matches_challenge(self):
        first, second = core.generate_oauth_session(), core.generate_oauth_session()
        params = parse_qs(urlparse(first.auth_url).query)
        expected = base64.urlsafe_b64encode(hashlib.sha256(first.code_verifier.encode()).digest()).decode().rstrip('=')
        self.assertEqual(params['code_challenge'], [expected])
        self.assertEqual(len(first.code_verifier), 128)
        self.assertNotEqual(first.state, second.state)
        self.assertNotEqual(first.code_verifier, second.code_verifier)

    def test_real_callback_rejects_stale_and_duplicate_state_without_poisoning(self):
        server = core.CallbackServer(0)
        server.start()
        try:
            server.reset('active-state')
            base = f'http://127.0.0.1:{server.port}/auth/callback'
            with httpx.Client(trust_env=False) as client:
                self.assertEqual(client.get(base, params={'state': 'stale', 'code': 'old'}).status_code, 400)
                self.assertEqual(client.get(base, params={'state': '非ASCII', 'code': 'old'}).status_code, 400)
                self.assertIsNone(server.wait(0))
                self.assertEqual(client.get(base + '?state=active-state&state=other&code=c').status_code, 400)
                self.assertEqual(client.get(base, params={'state': 'active-state'}).status_code, 400)
                self.assertIsNone(server.wait(0))
                self.assertEqual(client.get(base, params={'state': 'active-state', 'code': 'valid'}).status_code, 200)
                self.assertEqual(server.wait(0).code, 'valid')
                self.assertEqual(client.get(base, params={'state': 'active-state', 'code': 'again'}).status_code, 400)
        finally:
            server.stop()

    def test_response_errors_do_not_include_secret_body(self):
        secret = 'sensitive-response-value'
        response = httpx.Response(400, json={'error_description': secret})
        with patch.object(core.httpx, 'Client') as factory:
            factory.return_value.__enter__.return_value.post.return_value = response
            with self.assertRaises(core.AuthFlowError) as caught:
                core.exchange_code('code', 'verifier', core.DEFAULT_REDIRECT_URI, None)
            self.assertNotIn(secret, str(caught.exception))
            self.assertFalse(factory.call_args.kwargs['follow_redirects'])

    def test_incomplete_token_cannot_count_as_success(self):
        for key in ('access_token', 'refresh_token', 'id_token'):
            data = {'access_token': 'a', 'refresh_token': 'r', 'id_token': 'i'}
            data.pop(key)
            with patch.object(core.httpx, 'Client') as factory:
                factory.return_value.__enter__.return_value.post.return_value = httpx.Response(200, json=data)
                with self.assertRaises(core.AuthFlowError):
                    core.exchange_code('code', 'verifier', core.DEFAULT_REDIRECT_URI, None)

    def test_generic_authentication_error_is_not_deactivation(self):
        self.assertIsNone(core.fatal_login_error('Authentication Error: a temporary issue occurred'))
        self.assertIsNone(core.fatal_login_error('Your ChatGPT rate limits apply'))
        self.assertEqual(core.fatal_login_error('account_deactivated'), 'account deactivated')

    def test_cancellation_checked_before_navigation(self):
        account = core.AccountInput('u@example.com', 'secret', 'JBSWY3DPEHPK3PXP', 1)
        page = MagicMock()
        with self.assertRaises(core.AuthFlowError) as caught:
            core.login_with_browser(page, account, core.generate_oauth_session(), MagicMock(), 30, lambda: True)
        self.assertEqual(caught.exception.category, 'cancelled')
        page.goto.assert_not_called()
        self.assertNotIn('secret', repr(account))

    def test_rate_limit_stops_batch_and_success_was_checkpointed(self):
        account = core.AccountInput('u@example.com', 'password', 'JBSWY3DPEHPK3PXP', 1)
        export = {'name': account.email, 'platform': 'openai', 'type': 'oauth', 'credentials': {'access_token': 'dummy', 'email': account.email}}
        results = [core.ReauthResult(account.email, True, export, category='success'),
                   core.ReauthResult(account.email, False, error='limited', category='rate_limited')]
        with tempfile.TemporaryDirectory() as folder, \
             patch('playwright.sync_api.sync_playwright'), \
             patch.object(core, 'CallbackServer'), \
             patch.object(core, 'launch_browser'), \
             patch.object(core, 'reauth_account', side_effect=results) as run, \
             patch.object(core, 'log'):
            got = core.run_batch_reauth([account, account, account], recovery_dir=folder)
            self.assertEqual(len(got), 2)
            self.assertEqual(run.call_count, 2)
            checkpoint = next(Path(folder).glob('*/accounts.json'))
            self.assertEqual(json.loads(checkpoint.read_text())['accounts'], [export])

    def test_input_validation_preserves_password_delimiter(self):
        item = core.parse_account_line('\ufeffu@example.com----one----two----JBSW Y3DP EHPK3PXP', 1)
        self.assertEqual(item.password, 'one----two')
        with self.assertRaises(ValueError):
            core.parse_account_line('u@example.com----secret----INVALID!KEY', 1)
        accounts, errors = core.parse_accounts_text('\ufeff# comment\nu@example.com----secret----JBSWY3DPEHPK3PXP')
        self.assertFalse(errors)
        self.assertEqual(len(accounts), 1)


if __name__ == '__main__':
    unittest.main()
