"""Registration orchestration tests use only synthetic mailbox links and adapters."""
import json
from types import SimpleNamespace

import pytest

from registration_flow import (_registration_entry_failure, _run_registered_oauth,
                               PlaywrightRegistrationAdapter, load_registration_inputs,
                               registration_fingerprint, run_batch_registration)
from account_inputs import parse_account_line
from server_engine import registration_credentials_bytes
from test_pool import account
from web_imports import preview_import, select_import
from test_web import client, data, engine, finished, login


MAILBOX = "https://mail.test/messages/token1234/test@example.com"


def registration_text(email="test@example.com"):
    return f"{email}----fixture-password----https://mail.test/messages/token1234/{email}"


def test_email_submit_clicks_only_the_selected_form_submit_with_playwright():
    calls = []

    class Locator:
        def locator(self, selector):
            calls.append(("locator", selector))
            return self

        def nth(self, index):
            calls.append(("nth", index))
            return self

        def click(self, **kwargs):
            calls.append(("click", kwargs))

    class Page:
        def evaluate(self, script, args):
            assert args == {"email": "test@example.com"}
            assert "target.click()" not in script
            return {"ok": True, "form_index": 1, "target_index": 3}

        def locator(self, selector):
            calls.append(("locator", selector))
            return Locator()

    assert PlaywrightRegistrationAdapter._submit_email_form(Page(), "test@example.com")
    assert calls == [
        ("locator", "form"), ("nth", 1),
        ("locator", "button,input[type=submit]"), ("nth", 3),
        ("click", {"timeout": 8000}),
    ]


def test_registration_input_requires_matching_mailbox_and_rejects_duplicates():
    item = load_registration_inputs(registration_text())[0]
    assert item.email == "test@example.com"
    assert item.mailbox_url == MAILBOX
    with pytest.raises(ValueError, match="接码地址"):
        load_registration_inputs("test@example.com----fixture-password")
    with pytest.raises(ValueError, match="接码地址"):
        load_registration_inputs(
            "test@example.com----fixture-password----https://mail.test/messages/token1234/other@example.com"
        )
    with pytest.raises(ValueError, match="重复邮箱"):
        load_registration_inputs(registration_text() + "\n" + registration_text())


def test_registration_input_accepts_microsoft_graph_mailbox_line():
    item = load_registration_inputs(
        "graph@example.com----mail-password----12345678-1234-1234-1234-123456789012----refresh-token"
    )[0]
    assert item.mailbox_url == ""
    assert item.password == ""
    assert item.mailbox_client_id.startswith("12345678-")
    assert item.mailbox_refresh_token == "refresh-token"


def test_graph_mailbox_password_is_not_used_as_registration_password():
    item = load_registration_inputs({
        "email": "graph@example.com",
        "password": "mailbox-secret",
        "mailbox_client_id": "12345678-1234-1234-1234-123456789012",
        "mailbox_refresh_token": "refresh-token",
    })[0]
    assert item.password == ""


def test_registered_oauth_delegates_to_shared_browser_state_machine():
    item = load_registration_inputs(registration_text())[0]
    oauth = SimpleNamespace(state="expected-state", code_verifier="verifier", redirect_uri="http://localhost/callback")
    callback = object()
    calls = []

    def login(page, account, session, callback_arg, timeout, should_stop, headless):
        calls.append((page, account, session, callback_arg, timeout, should_stop, headless))
        return SimpleNamespace(code="one-time-code", state="expected-state", error="")

    def exchange(code, verifier, redirect_uri, proxy):
        assert (code, verifier, redirect_uri, proxy) == (
            "one-time-code", "verifier", "http://localhost/callback", "proxy.example"
        )
        return {"access_token": "access", "refresh_token": "refresh", "id_token": "id"}

    payload = _run_registered_oauth(
        "page", item, "generated-password", oauth=oauth, callback=callback,
        timeout=180, should_stop=lambda: False, headless=True,
        login_with_browser_fn=login, exchange_code_fn=exchange,
        proxy="proxy.example",
    )
    assert payload["access_token"] == "access"
    assert len(calls) == 1
    assert calls[0][1].email == item.email
    assert calls[0][1].password == "generated-password"
    assert calls[0][2] is oauth and calls[0][3] is callback


def test_registered_oauth_rejects_stale_callback_state():
    item = load_registration_inputs(registration_text())[0]
    oauth = SimpleNamespace(state="expected-state", code_verifier="verifier", redirect_uri="http://localhost/callback")
    with pytest.raises(Exception, match="OAuth state mismatch"):
        _run_registered_oauth(
            "page", item, "generated-password", oauth=oauth, callback=object(),
            timeout=180, should_stop=lambda: False, headless=True,
            login_with_browser_fn=lambda *args: SimpleNamespace(code="code", state="stale", error=""),
            exchange_code_fn=lambda *args: {}, proxy=None,
        )


def test_totp_binding_requires_enroll_and_activate_confirmation(monkeypatch):
    monkeypatch.setattr("pyotp.TOTP.now", lambda self: "123456")

    class Page:
        def __init__(self, activate_body=None, activate_status=200):
            self.activate_body = activate_body
            self.activate_status = activate_status
            self.calls = []

        def evaluate(self, script, args):
            self.calls.append(args)
            if "mfa/enroll" in args[0]:
                return {"status": 200, "body": {"secret": "JBSWY3DPEHPK3PXP", "session_id": "sid"}}
            return {"status": self.activate_status, "body": self.activate_body or {}}

    page = Page({"success": True})
    secret, error = PlaywrightRegistrationAdapter._bind_totp_in_browser(
        page, "access", device_id="device", chat_base="https://chat.example", budget_ms=1000
    )
    assert secret == "JBSWY3DPEHPK3PXP" and error == ""
    assert len(page.calls) == 2
    assert page.calls[0][0].endswith("/mfa/enroll")
    assert page.calls[1][0].endswith("/activate_enrollment")
    assert page.calls[1][-1] == 1000

    for status, body in ((403, {"success": True}), (200, {"success": False}), (200, {})):
        failed_page = Page(body, status)
        failed_secret, failed_error = PlaywrightRegistrationAdapter._bind_totp_in_browser(
            failed_page, "access", device_id="device", budget_ms=1000
        )
        assert failed_secret is None
        assert failed_error


def test_totp_binding_does_not_run_without_session_access_token():
    class Page:
        def evaluate(self, *_args):
            raise AssertionError("missing session token must stop before MFA request")

    secret, error = PlaywrightRegistrationAdapter._bind_totp_in_browser(
        Page(), "", device_id="device"
    )
    assert secret is None
    assert "accessToken" in error


def test_registration_entry_failure_classifies_site_blocks_without_echoing_page_content():
    assert _registration_entry_failure(403, "Unable to load site") == (
        "uncertain", "注册入口拒绝当前网络请求 (HTTP 403)；未提交邮箱，请检查网络或代理"
    )
    assert _registration_entry_failure(429, "rate limit") == (
        "rate_limited", "注册入口返回 HTTP 429，站点暂时限流；未提交邮箱"
    )
    assert _registration_entry_failure(200, "", title="Just a moment...", url="https://chatgpt.com/__cf_chl_rt_tk=") == (
        "needs_interaction", "注册入口要求完成浏览器安全验证；未提交邮箱"
    )
    assert _registration_entry_failure(200, "", title="", url="https://chatgpt.com/") is None
    assert _registration_entry_failure(200, "login page") is None
    assert _registration_entry_failure(
        403,
        "Just a moment...",
        title="Attention Required",
        url="https://chatgpt.com/__cf_chl_rt_tk=challenge",
    ) == (
        "needs_interaction", "注册入口要求完成浏览器安全验证；未提交邮箱"
    )


def test_fallback_records_otp_window_before_signin_request(monkeypatch):
    events = []

    def now():
        events.append("timestamp")
        return 1234567890.0

    class Page:
        def evaluate(self, *_args):
            events.append("signin")
            return True

    monkeypatch.setattr("registration_flow.time.time", now)
    assert PlaywrightRegistrationAdapter._signin_fallback(Page(), "fixture@example.com") == 1234567890.0
    assert events == ["timestamp", "signin"]


def test_registration_stage_does_not_call_anonymous_homepage_complete():
    class Context:
        def __init__(self, cookies):
            self._cookies = cookies

        def cookies(self):
            return self._cookies

    class Page:
        url = "https://chatgpt.com/"

        def __init__(self, cookies):
            self.context = Context(cookies)

        def locator(self, _selector):
            raise AssertionError("anonymous homepage should be classified before selector fallback")

    assert PlaywrightRegistrationAdapter._stage(Page([])) == "unknown"
    assert PlaywrightRegistrationAdapter._stage(
        Page([{"name": "__Secure-next-auth.session-token", "value": "session"}])
    ) == "complete"


def test_create_account_requires_explicit_server_response():
    adapter = PlaywrightRegistrationAdapter()
    assert not adapter._existing_account_marker("Already have an account? Log in")
    assert adapter._existing_account_marker("user_already_exists")
    assert adapter._create_account_response(SimpleNamespace(
        url="https://auth.openai.com/api/accounts/create_account",
        status=200, json=lambda: {"redirect": "https://chatgpt.com/"},
    )) == "confirmed"
    assert adapter._create_account_response(SimpleNamespace(
        url="https://auth.openai.com/api/accounts/create_account",
        status=400, json=lambda: {"error": {"code": "user_already_exists"}},
    )) == "existing"
    assert adapter._create_account_response(SimpleNamespace(
        url="https://auth.openai.com/api/accounts/create_account",
        status=500, json=lambda: {"error": "temporarily_unavailable"},
    )) == "failed"
    assert adapter._create_account_response(SimpleNamespace(
        url="https://auth.openai.com/api/accounts/user/register",
        status=200, json=lambda: {},
    )) is None


def test_playwright_checkpoint_accepts_side_effect_flags():
    item = load_registration_inputs(registration_text())[0]
    payload = PlaywrightRegistrationAdapter()._checkpoint(
        item, "mailbox_ready", side_effects={"email_submit_attempted": False}
    )
    assert payload["stage"] == "mailbox_ready"
    assert payload["side_effects"] == {"email_submit_attempted": False}


def test_confirmed_creation_keeps_session_pending_on_unknown_page():
    item = load_registration_inputs(registration_text())[0]
    checkpoint = {"stage": "create_account", "create_confirmed": True,
                  "side_effects": {"profile_submitted": True}}
    result = PlaywrightRegistrationAdapter()._fail(
        item, "unknown", "uncertain", "页面未推进；未重放已提交请求", checkpoint=checkpoint
    )
    assert result.category == "auth_session_pending"
    assert result.checkpoint["create_confirmed"] is True
    assert result.checkpoint["side_effects"]["profile_submitted"] is True


def test_confirmed_creation_navigates_to_session_once_without_resubmitting(monkeypatch):
    class Mailbox:
        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def snapshot(self, *_args, **_kwargs):
            return object()

    class Page:
        def __init__(self):
            self.url = ""
            self.navigations = []
            self.response_observer = None

        def on(self, event, callback):
            if event == "response":
                self.response_observer = callback

        def set_default_timeout(self, *_args):
            pass

        def goto(self, url, **_kwargs):
            self.url = url
            self.navigations.append(url)
            return SimpleNamespace(status=200)

        def title(self):
            return ""

        def inner_text(self, *_args):
            return ""

        def wait_for_timeout(self, *_args):
            pass

    page = Page()

    class Browser:
        def new_context(self):
            return SimpleNamespace(new_page=lambda: page)

        def close(self):
            pass

    class Playwright:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

    class Adapter(PlaywrightRegistrationAdapter):
        def _visible(self, _page, selectors):
            return object() if any("login-email" in value for value in selectors) else None

        def _fill_like_user(self, *_args):
            pass

        def _submit_email_form(self, page, _email):
            page.response_observer(SimpleNamespace(
                url="https://auth.openai.com/api/accounts/create_account",
                status=200, json=lambda: {"redirect": "https://chatgpt.com/"},
            ))
            return True

        def _stage(self, _page):
            return "unknown"

    monkeypatch.setattr("registration_flow.MailboxClient", Mailbox)
    monkeypatch.setattr("playwright.sync_api.sync_playwright", lambda: Playwright())
    monkeypatch.setattr("openai_reauth.launch_browser", lambda *_args, **_kwargs: Browser())
    result = Adapter().register(
        load_registration_inputs(registration_text())[0], config={"timeout": 30},
        should_stop=lambda: False, on_stage=lambda _stage: None, checkpoint={},
    )
    assert result.category == "auth_session_pending"
    assert result.checkpoint["create_confirmed"] is True
    assert page.navigations == ["https://chatgpt.com/auth/login", "https://chatgpt.com/"]


@pytest.mark.parametrize("continuation_present", [False, True])
def test_verification_route_advances_at_most_once_before_otp(monkeypatch, continuation_present):
    clicks = []

    class Button:
        def click(self, **_kwargs):
            clicks.append("continue")

    class Mailbox:
        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def snapshot(self, *_args, **_kwargs):
            return object()

    class Page:
        url = "https://auth.openai.com/email-verification"

        def on(self, *_args):
            pass

        def set_default_timeout(self, *_args):
            pass

        def goto(self, *_args, **_kwargs):
            return SimpleNamespace(status=200)

        def title(self):
            return ""

        def inner_text(self, *_args):
            return ""

        def wait_for_timeout(self, *_args):
            pass

    class Browser:
        def new_context(self):
            return SimpleNamespace(new_page=lambda: Page())

        def close(self):
            pass

    class Playwright:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

    class Adapter(PlaywrightRegistrationAdapter):
        def _visible(self, page, selectors):
            if continuation_present and any("Continue to ChatGPT" in selector for selector in selectors):
                return Button()
            return object() if any("login-email" in selector for selector in selectors) else None

        def _fill_like_user(self, *_args):
            pass

        def _submit_email_form(self, *_args):
            return True

        def _stage(self, *_args):
            return "email_verification"

    monkeypatch.setattr("registration_flow.MailboxClient", Mailbox)
    monkeypatch.setattr("playwright.sync_api.sync_playwright", lambda: Playwright())
    monkeypatch.setattr("openai_reauth.launch_browser", lambda *_args, **_kwargs: Browser())
    item = load_registration_inputs(registration_text())[0]
    checkpoints = []
    result = Adapter().register(item, config={"timeout": 30}, should_stop=lambda: False,
                                on_stage=lambda _stage: None, checkpoint={},
                                on_checkpoint=checkpoints.append)
    assert result.category == "uncertain"
    assert result.checkpoint["stage"] == "email_verification"
    assert result.checkpoint["side_effects"] == ({
        "email_submit_attempted": True, "email_submitted": True,
        **({"verification_entry_attempted": True} if continuation_present else {}),
    })
    assert clicks == (["continue"] if continuation_present else [])
    assert len(checkpoints) < 10


def test_uncertain_checkpoint_is_not_replayed_or_written_with_password(tmp_path):
    item = load_registration_inputs(registration_text())[0]
    item.checkpoint = {"stage": "create_account", "state": "profile_submit_pending",
                       "registration_password": "must-not-be-copied",
                       "side_effects": {"profile_submit_attempted": True}}
    result = run_batch_registration([item], {"driver": "playwright"},
                                    adapter=PlaywrightRegistrationAdapter(), checkpoint_dir=tmp_path)[0]
    assert result.category == "uncertain"
    assert result.checkpoint["side_effects"]["profile_submit_attempted"]
    assert "registration_password" not in result.checkpoint
    assert "must-not-be-copied" not in next(tmp_path.glob("*.json")).read_text(encoding="utf-8")


def test_registration_import_selection_uses_registration_inputs():
    report, _ = preview_import("register", registration_text(), 10)
    assert report["rows"][0]["state"] == "ready"
    selected = select_import("register", registration_text(), 10, ["0"], report["fingerprint"])
    assert selected[0].email == "test@example.com"
    assert registration_fingerprint(registration_text()) == report["fingerprint"]


def test_disabled_registration_is_a_finished_non_success_task(engine):
    task = finished(engine, engine.start("register", registration_text()))
    assert task["rows"][0]["state"] == "registration_disabled"
    assert not task["accounts"]
    assert "未启用" in task["rows"][0]["message"]


def test_fixture_registration_is_explicit_and_synthetic(engine, monkeypatch):
    monkeypatch.setenv("SUBTOOLS_REGISTRATION_FIXTURE", "1")
    engine.save_config("register", {"driver": "fixture"})
    task = finished(engine, engine.start("register", registration_text()))
    assert task["rows"][0]["state"] == "success"
    assert task["accounts"]["0"]["platform"] == "fixture"
    checkpoints = list((engine.root / "tasks" / task["id"] / "registration-checkpoints").glob("*.json"))
    assert checkpoints == []


def test_registration_stop_reports_each_item_without_replaying():
    items = load_registration_inputs(
        registration_text() + "\n" + registration_text("two@example.com").replace("token1234", "token5678")
    )
    progress = []
    results = run_batch_registration(items, {}, should_stop=lambda: True, on_progress=lambda i, total, result: progress.append((i, result.category)))
    assert [result.category for result in results] == ["cancelled", "cancelled"]
    assert progress == [(1, "cancelled"), (2, "cancelled")]


def test_registration_stop_preserves_existing_checkpoint(tmp_path):
    item = load_registration_inputs(registration_text())[0]
    item.checkpoint = {"stage": "email_otp_wait", "state": "uncertain"}
    results = run_batch_registration([item], {}, should_stop=lambda: True, checkpoint_dir=tmp_path)
    assert results[0].category == "cancelled"
    assert results[0].checkpoint["stage"] == "email_otp_wait"
    saved = json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))
    assert saved["state"] == "cancelled" and saved["stage"] == "email_otp_wait"


def test_registration_adapter_error_is_uncertain_and_checkpointed(tmp_path):
    item = load_registration_inputs(registration_text())[0]

    class BrokenAdapter:
        def register(self, item, **kwargs):
            raise RuntimeError("fixture transport failed")

    results = run_batch_registration([item], {}, adapter=BrokenAdapter(), checkpoint_dir=tmp_path)
    assert results[0].category == "uncertain"
    assert "未自动重放" in results[0].error
    checkpoint = next(tmp_path.glob("*.json"))
    saved = json.loads(checkpoint.read_text(encoding="utf-8"))
    assert saved["state"] == "uncertain"
    assert saved["email"] == item.email


def test_registration_web_config_preview_and_start(client):
    login(client)
    config = client.get("/api/config")
    assert config.status_code == 200 and config.json()["register"]["driver"] == "disabled"
    assert config.json()["register"]["signup_url"] == "https://chatgpt.com/auth/login"
    preview = client.post("/api/preview/register", json={"text": registration_text()})
    assert preview.status_code == 200 and preview.json()[0]["email"] == "test@example.com"
    task = client.post("/api/tasks", json={"kind": "register", "text": registration_text()})
    assert task.status_code == 200
    client.app.state.engine.worker.join(5)
    assert client.get("/api/tasks/" + task.json()["id"]).json()["rows"][0]["state"] == "registration_disabled"


def test_playwright_registration_driver_is_configurable_without_starting_network(engine):
    saved = engine.save_config("register", {
        "driver": "playwright",
        "signup_url": "https://chatgpt.com/auth/login",
        "show_browser": True,
    })
    assert saved["driver"] == "playwright"
    assert saved["show_browser"] is True


def test_registration_engine_passes_resolved_proxy(engine, monkeypatch):
    seen = {}
    monkeypatch.setattr("server_engine.proxy_for", lambda _config: "http://proxy.example:3128")

    def capture(_items, config, **_kwargs):
        seen["proxy"] = config["proxy"]
        return []

    monkeypatch.setattr("server_engine.run_batch_registration", capture)
    engine.save_config("register", {"driver": "playwright"})
    finished(engine, engine.start("register", registration_text()))
    assert seen["proxy"] == "http://proxy.example:3128"


def test_registration_export_formats_and_selection(client):
    login(client)
    e = client.app.state.engine
    source = registration_text() + "\n" + registration_text("second@example.com")
    task = finished(e, e.start("register", source))
    first = account(email="test@example.com")
    first["credentials"].update(password="fixture-password", totp_secret="JBSWY3DPEHPK3PXP")
    task["rows"][0]["state"] = "success"
    task["accounts"]["0"] = first
    task["rows"][1]["state"] = "auth_session_pending"
    task["items"][1]["checkpoint"] = {"create_confirmed": True}
    e._save(task)
    path = "/api/tasks/" + task["id"]

    sub2 = client.get(path + "/export?target=sub2")
    assert sub2.status_code == 200
    assert "sub2api.json" in sub2.headers["content-disposition"]
    assert len(sub2.json()["accounts"]) == 1
    assert sub2.json()["accounts"][0]["credentials"]["totp_secret"] == "JBSWY3DPEHPK3PXP"
    cpa_warnings = client.get(path + "/export-warnings?target=cpa").json()["warnings"]
    assert any("credentials.password" in warning and "credentials.totp_secret" in warning for warning in cpa_warnings)
    cpa = client.get(path + "/export?target=cpa")
    assert cpa.status_code == 200 and "cpa.json" in cpa.headers["content-disposition"]
    assert "password" not in cpa.json() and "totp_secret" not in cpa.json()

    warnings = client.get(path + "/export-warnings?target=registration-text").json()["warnings"]
    assert any("会话未确认" in warning for warning in warnings)
    assert any("未绑定 2FA" in warning for warning in warnings)
    exported = client.get(path + "/export?target=registration-text")
    assert exported.status_code == 200
    assert "registered-accounts.txt" in exported.headers["content-disposition"]
    assert exported.text.splitlines() == [
        "test@example.com----fixture-password----JBSWY3DPEHPK3PXP",
        "second@example.com----fixture-password",
    ]
    assert parse_account_line(exported.text.splitlines()[0]).totp_secret == "JBSWY3DPEHPK3PXP"
    assert parse_account_line(exported.text.splitlines()[1]).totp_secret == ""
    selected = client.get(path + "/export?target=registration-text&selected=1")
    assert selected.text.splitlines() == ["second@example.com----fixture-password"]
    assert client.get(path + "/export?target=sub2&selected=1").status_code == 400


def test_registration_credentials_export_rejects_unconfirmed_and_invalid_records(engine):
    task = finished(engine, engine.start("register", registration_text()))
    task["rows"][0]["state"] = "auth_session_pending"
    with pytest.raises(ValueError, match="没有可导出"):
        engine.export_registration_credentials(task["id"])
    task["items"][0]["checkpoint"] = {"create_confirmed": True}
    task["items"][0]["password"] = ""
    with pytest.raises(ValueError, match="缺少保存的注册密码"):
        engine.export_registration_credentials(task["id"])
    task["items"][0]["password"] = "fixture-password"
    with pytest.raises(ValueError, match="不属于此任务"):
        engine.export_registration_credentials(task["id"], ["missing"])
    task["rows"][0]["state"] = "success"
    task["accounts"]["0"] = account(email="different@example.com")
    with pytest.raises(ValueError, match="身份与注册记录不一致"):
        engine.export_registration_credentials(task["id"])
    task["accounts"].clear()
    task["items"][0]["password"] = "bad----password"
    records, _ = engine.export_registration_credentials(task["id"])
    with pytest.raises(ValueError, match="无法表示"):
        registration_credentials_bytes(records)


def test_registration_text_export_is_not_available_for_other_tasks(client):
    login(client)
    e = client.app.state.engine
    task = finished(e, e.start("register", registration_text()))
    task["kind"] = "auth"
    response = client.get("/api/tasks/" + task["id"] + "/export-warnings?target=registration-text")
    assert response.status_code == 400
    assert "仅用于注册任务" in response.json()["error"]
