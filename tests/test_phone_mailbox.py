from pathlib import Path
import base64
import sys
import time
import unittest
from datetime import datetime, timezone

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from phone_mailbox import MailboxBaseline, MailboxClient, MailboxError, validate_mailbox_url


EMAIL = "test.account@icloud.com"
TOKEN = "mailbox_test_token_only"
URL = f"http://mailbox.example:3000/messages/{TOKEN}/{EMAIL}"


def item(message_id, code=None, **changes):
    result = {
        "id": message_id,
        "mailbox": "INBOX",
        "subject": "您的临时 OpenAI 登录代码" + (f" {code}" if code else ""),
        "from_address": "noreply_at_tm_openai_com_forward_hash@icloud.com",
        "received_at": "2026-09-18 10:00:00",
    }
    result.update(changes)
    return result


def detail(code="123456", **changes):
    body = f"<html><style>.sample{{color:#456789}}</style><body><p>您的临时登录代码</p><strong>{code}</strong><script>999999</script></body></html>"
    result = {
        "subject": "您的临时 OpenAI 登录代码",
        "fromAddress": "noreply_at_tm_openai_com_forward_hash@icloud.com",
        "receivedAt": "2026-09-18 10:00:00",
        "html": True,
        "body": "data:text/html;charset=utf-8;base64," + base64.b64encode(body.encode()).decode(),
    }
    result.update(changes)
    return result


class MailboxTests(unittest.TestCase):
    def client(self, lists, details=None):
        details = details or {}
        self.requests = []
        pages = iter(lists)
        last_page = {"items": []}

        def handle(request):
            nonlocal last_page
            self.requests.append(request)
            if request.url.path.startswith("/api/messages/"):
                last_page = next(pages, last_page)
                return httpx.Response(200, json=last_page)
            message_id = request.url.path.split("/")[2]
            return httpx.Response(200, json=details.get(message_id, {}))

        http = httpx.Client(transport=httpx.MockTransport(handle))
        self.addCleanup(http.close)
        result = MailboxClient(URL, EMAIL, client=http)
        result.poll_interval = 0.001
        return result

    def wait(self, client, baseline=None, **kwargs):
        return client.wait_for_code(baseline or MailboxBaseline(), time.time(), time.monotonic() + 0.04, **kwargs)

    def test_url_matches_email_and_accepts_percent_encoding(self):
        self.assertEqual(validate_mailbox_url(URL, EMAIL.upper()), URL)
        self.assertIn("%40", validate_mailbox_url(URL.replace("@", "%40"), EMAIL))

    def test_rejects_malformed_or_mismatched_urls_without_leaking(self):
        for invalid in (
            URL.replace(EMAIL, "different@icloud.com"),
            URL.replace("http:", "file:"), URL + "?secret=value", URL + "#part",
            URL.replace("mailbox.example", "username:password@mailbox.example"),
            URL.replace(":3000", ":invalid"), URL + "/extra", URL + "\n",
            URL.replace("/messages/", "/json/"),
        ):
            with self.subTest(invalid=invalid), self.assertRaises(MailboxError) as raised:
                validate_mailbox_url(invalid, EMAIL)
            self.assertNotIn(TOKEN, str(raised.exception))
            self.assertNotIn("password", str(raised.exception))

    def test_fresh_subject_code(self):
        client = self.client([{"items": [item(2, "123456")]}])
        self.assertEqual(self.wait(client), "123456")
        self.assertEqual(len(self.requests), 1)

    def test_html_data_uri_does_not_execute_script_or_read_style(self):
        client = self.client([{"items": [item(2)]}], {"2": detail()})
        self.assertEqual(self.wait(client), "123456")
        self.assertEqual(len(self.requests), 2)

    def test_plaintext_detail(self):
        client = self.client([{"items": [item(2)]}], {"2": detail(html=False, body="Your login code: 123456")})
        self.assertEqual(self.wait(client), "123456")

    def test_snapshot_filters_baseline_ids_and_codes(self):
        client = self.client([
            {"items": [item(10, "111111")]},
            {"items": [item(10, "111111"), item(11, "111111"), item(12, "222222")]},
        ])
        baseline = client.snapshot()
        self.assertEqual(baseline.ids, frozenset({"10"}))
        self.assertEqual(baseline.codes, frozenset({"111111"}))
        self.assertNotIn("111111", repr(baseline))
        self.assertEqual(self.wait(client, baseline), "222222")

    def test_old_id_appearing_later_is_not_fresh(self):
        client = self.client([{"items": [item(9, "123456")]}])
        self.assertIsNone(self.wait(client, MailboxBaseline(ids=frozenset({"10"}))))

    def test_rejects_old_explicit_timestamp(self):
        client = self.client([{"items": [item(2, "123456", received_at="2000-01-01T00:00:00Z")]}])
        self.assertIsNone(self.wait(client))

    def test_ambiguous_timezone_does_not_override_new_id(self):
        client = self.client([{"items": [item(2, "123456", received_at="2026-09-18 10:00:00")]}])
        self.assertEqual(self.wait(client), "123456")

    def test_does_not_accept_other_senders_or_unrelated_subjects(self):
        for changes in (
            {"from_address": "attacker@openai.com.example.org"},
            {"from_address": "noreply_at_tm_openai_com_x@icloud.com.example.org"},
            {"subject": "Reset your OpenAI password, code 123456"},
            {"subject": "OpenAI phone verification code 123456"},
            {"subject": "Your store discount code 123456"},
            {"subject": "欢迎加入 OpenAI"},
        ):
            with self.subTest(changes=changes):
                client = self.client([{"items": [item(2, "123456", **changes)]}])
                self.assertIsNone(self.wait(client))

    def test_accepts_direct_openai_sender(self):
        client = self.client([{"items": [item(2, "123456", from_address="OpenAI <noreply@tm.openai.com>")]}])
        self.assertEqual(self.wait(client), "123456")

    def test_other_recipient_is_rejected(self):
        client = self.client([{"items": [item(2, "123456", recipient="other@icloud.com")]}])
        self.assertIsNone(self.wait(client))

    def test_actual_schema_folder_field_and_detail_without_recipient(self):
        client = self.client([
            {"items": [item(1, "111111", mailbox="JUNK")], "has_more": False},
            {"items": [item(2, mailbox="JUNK"), item(1, "111111", mailbox="JUNK")], "has_more": False},
        ], {"2": detail()})
        baseline = client.snapshot()
        self.assertEqual(baseline.codes, frozenset({"111111"}))
        self.assertEqual(self.wait(client, baseline), "123456")

    def test_explicit_matching_recipient_is_accepted(self):
        client = self.client([{"items": [item(2, "123456", recipient=f"Test <{EMAIL}>")]}])
        self.assertEqual(self.wait(client), "123456")

    def test_detail_sender_is_rechecked(self):
        client = self.client([{"items": [item(2)]}], {"2": detail(fromAddress="attacker@example.org")})
        self.assertIsNone(self.wait(client))

    def test_external_html_url_not_requested(self):
        client = self.client([{"items": [item(2)]}], {"2": detail(body="https://attacker.example/123456")})
        self.assertIsNone(self.wait(client))
        self.assertTrue(all(request.url.host == "mailbox.example" for request in self.requests))

    def test_malformed_or_unsupported_data_uri_is_ignored(self):
        for body in ("data:text/html;base64,!invalid", "data:application/javascript,123456"):
            with self.subTest(body=body):
                client = self.client([{"items": [item(2)]}], {"2": detail(body=body)})
                self.assertIsNone(self.wait(client))

    def test_ambiguous_codes_are_not_guessed(self):
        client = self.client([{"items": [item(2)]}], {"2": detail(html=False, body="123456 or 654321")})
        self.assertIsNone(self.wait(client))

    def test_stop_before_request(self):
        client = self.client([{"items": [item(2, "123456")]}])
        self.assertIsNone(self.wait(client, should_stop=lambda: True))
        self.assertEqual(self.requests, [])

    def test_snapshot_honors_stop_before_request(self):
        client = self.client([{"items": [item(2)]}])
        with self.assertRaises(MailboxError) as raised:
            client.snapshot(should_stop=lambda: True)
        self.assertEqual(raised.exception.category, "cancelled")
        self.assertEqual(self.requests, [])

    def test_snapshot_caps_old_body_requests_but_keeps_all_ids(self):
        client = self.client([{"items": [item(index) for index in range(1, 30)]}],
                             {str(index): detail() for index in range(1, 30)})
        baseline = client.snapshot()
        self.assertEqual(len(baseline.ids), 29)
        self.assertEqual(len(self.requests), 11)

    def test_deadline_before_request(self):
        client = self.client([{"items": []}])
        self.assertIsNone(client.wait_for_code(MailboxBaseline(), time.time(), time.monotonic() - 1))
        self.assertEqual(self.requests, [])

    def test_bad_response_is_safe_error(self):
        client = self.client([{"error": "private mailbox response"}])
        with self.assertRaises(MailboxError) as raised:
            client.snapshot()
        self.assertNotIn(TOKEN, str(raised.exception))
        self.assertNotIn("private", str(raised.exception))

    def test_http_error_and_redirect_do_not_expose_url(self):
        for status in (302, 403, 404, 500):
            with self.subTest(status=status):
                http = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(status, headers={"location": "https://external.example"})))
                self.addCleanup(http.close)
                client = MailboxClient(URL, EMAIL, client=http)
                with self.assertRaises(MailboxError) as raised:
                    client.snapshot()
                self.assertNotIn(TOKEN, str(raised.exception))
                self.assertNotIn("http", str(raised.exception))

    def test_network_error_has_no_secret_context(self):
        def handle(request):
            raise httpx.ConnectError(str(request.url))
        http = httpx.Client(transport=httpx.MockTransport(handle))
        self.addCleanup(http.close)
        with self.assertRaises(MailboxError) as raised:
            MailboxClient(URL, EMAIL, client=http).snapshot()
        self.assertNotIn(TOKEN, str(raised.exception))
        self.assertTrue(raised.exception.__suppress_context__)


class LinlanyuMailboxTests(unittest.TestCase):
    URL = f"https://msg.linlanyu.com/messages/{TOKEN}/{EMAIL}"

    @staticmethod
    def mail(code="123456", received_at=None, **changes):
        data = {
            "email": EMAIL, "hasMail": True, "code": code,
            "from": "OpenAI <noreply@tm.openai.com>",
            "subject": "Your OpenAI login code",
            "receivedAt": received_at or datetime.now(timezone.utc).isoformat(),
        }
        data.update(changes)
        return {"success": True, "data": data}

    def client(self, pages, *, url=None):
        pending = iter(pages)
        last = None
        self.requests = []

        def handle(request):
            nonlocal last
            self.requests.append(request)
            last = next(pending, last)
            return httpx.Response(200, json=last)

        http = httpx.Client(transport=httpx.MockTransport(handle))
        self.addCleanup(http.close)
        client = MailboxClient(url or self.URL, EMAIL, client=http)
        client.poll_interval = 0.001
        return client

    def wait(self, client, baseline=None, issued_after=None):
        return client.wait_for_code(baseline or MailboxBaseline(),
                                    time.time() - 1 if issued_after is None else issued_after,
                                    time.monotonic() + 0.04)

    def test_documented_endpoint_uses_exact_origin_and_encoded_params(self):
        client = self.client([self.mail()])
        self.assertEqual(self.wait(client), "123456")
        self.assertEqual(len(self.requests), 1)
        request = self.requests[0]
        self.assertEqual(request.url.scheme, "https")
        self.assertEqual(request.url.host, "msg.linlanyu.com")
        self.assertEqual(request.url.path, "/api/messages")
        self.assertEqual(dict(request.url.params), {
            "token": TOKEN, "email": EMAIL, "limit": "1", "simple": "1",
        })

    def test_empty_inbox_is_valid_without_message_fields(self):
        client = self.client([{"success": True, "data": {"email": EMAIL, "hasMail": False}}])
        self.assertEqual(client.snapshot(), MailboxBaseline())
        self.assertIsNone(self.wait(client))

    def test_baseline_stable_id_blocks_existing_message_then_accepts_new(self):
        old = self.mail("111111")
        new = self.mail("222222")
        client = self.client([old, old, new])
        baseline = client.snapshot()
        self.assertEqual(len(baseline.ids), 1)
        self.assertRegex(next(iter(baseline.ids)), r"^[a-f0-9]{64}$")
        self.assertEqual(baseline.codes, frozenset({"111111"}))
        self.assertEqual(client.snapshot(), baseline)
        self.assertEqual(self.wait(client, baseline), "222222")

    def test_changed_timestamp_does_not_reuse_baseline_code(self):
        client = self.client([self.mail("111111"), self.mail("111111")])
        self.assertIsNone(self.wait(client, client.snapshot()))

    def test_old_mail_not_seen_in_baseline_is_rejected(self):
        client = self.client([self.mail(received_at="2000-01-01T00:00:00Z")])
        self.assertIsNone(self.wait(client))

    def test_message_just_before_login_is_not_accepted_with_legacy_slack(self):
        issued_after = time.time()
        stamp = datetime.fromtimestamp(issued_after - 1, timezone.utc).isoformat()
        client = self.client([self.mail(received_at=stamp)])
        self.assertIsNone(self.wait(client, issued_after=issued_after))

    def test_new_message_after_login_with_forwarded_sender(self):
        issued_after = time.time() - 1
        client = self.client([self.mail(**{
            "from": "noreply_at_tm_openai_com_forward_hash@icloud.com",
            "subject": "您的临时 OpenAI 登录代码",
        })])
        self.assertEqual(self.wait(client, issued_after=issued_after), "123456")

    def test_unrelated_sender_or_subject_is_ignored(self):
        for changes in (
            {"from": "attacker@openai.com.example.org"},
            {"from": "noreply_at_tm_openai_com_x@icloud.com.example.org"},
            {"subject": "Your OpenAI password reset code"},
            {"subject": "Your OpenAI phone code"},
            {"subject": "Your store discount code"},
        ):
            with self.subTest(changes=changes):
                self.assertIsNone(self.wait(self.client([self.mail(**changes)])))

    def test_invalid_shape_recipient_code_timestamp_is_safe_error(self):
        bad = [None, [], {}, {"success": False, "data": {}},
               {"success": 1, "data": {}}, self.mail(email="other@icloud.com"),
               self.mail(hasMail="true"), self.mail(code=123456),
               self.mail(code="１２３４５６"), self.mail(code="12345"),
               self.mail(received_at="2026-09-18 10:00:00"),
               self.mail(received_at="not a timestamp"),
               self.mail(subject="Your OpenAI login code 654321")]
        for index, payload in enumerate(bad):
            with self.subTest(index=index), self.assertRaises(MailboxError) as raised:
                self.client([payload]).snapshot()
            self.assertNotIn(TOKEN, str(raised.exception))
            self.assertNotIn("123456", str(raised.exception))

    def test_provider_selection_requires_exact_hostname(self):
        client = self.client([{"items": [item(2, "123456")]}],
                             url=self.URL.replace("msg.linlanyu.com", "msg.linlanyu.com.example.org"))
        self.assertEqual(self.wait(client), "123456")
        self.assertTrue(self.requests[0].url.path.startswith("/api/messages/"))
        self.assertFalse(self.requests[0].url.query)

    def test_provider_does_not_follow_same_or_cross_origin_redirects(self):
        for location in ("/somewhere", "https://other.example/messages"):
            requests = []

            def handle(request):
                requests.append(request)
                return httpx.Response(307, headers={"location": location})

            with httpx.Client(transport=httpx.MockTransport(handle)) as http:
                with self.assertRaises(MailboxError):
                    MailboxClient(self.URL, EMAIL, client=http).snapshot()
            self.assertEqual(len(requests), 1)


if __name__ == "__main__":
    unittest.main()
