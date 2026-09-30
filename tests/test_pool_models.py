"""Model restrictions follow sub2api's identity model_mapping contract."""

import copy
import json
import threading
import tkinter as tk
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

import pool_gui
from pool_client import PoolClient, PoolError, parse_model_whitelist
from pool_flow import PushJob, push_one, run_pool_push
from test_pool import AdminBackend, account, settings
import test_gui as gui_tests
import test_pool_gui as pool_gui_tests

MODEL_FIXTURE = ("codex-auto-review", "gpt-5.5", "gpt-5.6-sol", "gpt-5.6-terra", "gpt-6-astra", "gpt-reserve")


def test_model_names_accept_lines_commas_semicolons_and_deduplicate():
    models = parse_model_whitelist(" codex-auto-review\r\ngpt-5.5，gpt-5.6-sol;gpt-5.6-terra；gpt-6-astra,gpt-reserve\ngpt-5.5 ")
    assert models == MODEL_FIXTURE


@pytest.mark.parametrize("text", ["", " \n，; ", "gpt 5.5", "gpt-*", "gpt-5.5=>gpt-6-astra", '["gpt-5.5"]'])
def test_invalid_or_empty_replace_does_not_silently_clear_restrictions(text):
    with pytest.raises(ValueError):
        parse_model_whitelist(text)


def test_model_policy_is_part_of_destination_but_order_is_not():
    assert settings().destination_id() != settings(model_whitelist=()).destination_id()
    assert settings(model_whitelist=("gpt-5.5", "gpt-6-astra")).destination_id() == settings(model_whitelist=("gpt-6-astra", "gpt-5.5")).destination_id()


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("models", [None, (), MODEL_FIXTURE])
def test_model_policy_on_create_and_update_preserves_other_credentials(existing, models):
    original = account(model_mapping={"old-alias": "old-target"}, refresh_token="original-refresh")
    old = {**original, "id": 8, "group_ids": [7], "priority": 50, "concurrency": 1, "extra": {"keep": True}}
    backend = AdminBackend([old] if existing else [])
    source = account(model_mapping={"source-alias": "source-target"}, refresh_token="")
    unchanged = copy.deepcopy(source)
    job = PushJob("fixture@example.com", account=source)
    config = settings(model_whitelist=models)
    with backend.client(config) as client:
        push_one(client, config, job, client.accounts())
    saved = backend.records[job.account_id]
    expected = source["credentials"]["model_mapping"] if models is None else {name: name for name in models}
    assert saved["credentials"]["model_mapping"] == expected
    assert job.state == ("updated" if existing else "created")
    assert job.account == unchanged
    if existing:
        assert saved["credentials"]["refresh_token"] == "original-refresh"
        assert saved["extra"] == {"keep": True}
    if models == ():
        assert "已清除模型限制" in job.message
    elif models:
        assert "6 个白名单模型" in job.message


def test_default_login_push_keeps_existing_model_mapping_when_input_has_none():
    backend = AdminBackend([{**account(model_mapping={"alias": "target"}), "id": 8}])
    job = PushJob("fixture@example.com", account=account())
    with backend.client() as client:
        push_one(client, settings(), job, client.accounts())
    assert backend.records[8]["credentials"]["model_mapping"] == {"alias": "target"}


def test_oauth_accounts_receive_the_selected_whitelist():
    from openai_reauth import ReauthResult
    from pool_flow import parse_push_text
    backend = AdminBackend()
    jobs = parse_push_text("fixture@example.com----fixture-password")
    def authorize(inputs, **kwargs):
        assert kwargs["skip_phone_verification"] is True
        kwargs["on_progress"](1, 1, ReauthResult(inputs[0].email, True, account=account(), category="success"))
    run_pool_push(jobs, settings(model_whitelist=("gpt-5.5",)), stop=threading.Event(), on_progress=lambda _: None,
                  authorize=authorize, client_factory=backend.client, recovery_dir=None)
    assert backend.records[jobs[0].account_id]["credentials"]["model_mapping"] == {"gpt-5.5": "gpt-5.5"}


def test_pending_write_rejects_changed_whitelist_without_sending_another_request():
    backend = AdminBackend()
    backend.lost_responses = 2
    job = PushJob("fixture@example.com", account=account())
    config = settings(model_whitelist=("gpt-5.5",))
    with backend.client(config) as client:
        with pytest.raises(PoolError):
            push_one(client, config, job, [])
        count = len(backend.requests)
        with pytest.raises(PoolError) as error:
            push_one(client, settings(model_whitelist=("gpt-6-astra",)), job, [])
        assert error.value.uncertain and len(backend.requests) == count
        push_one(client, config, job, client.accounts())
    assert len(backend.records) == 1 and job.state == "created"


@pytest.mark.parametrize("mapping", [None, [], {"gpt-5.5": "different"}, {}])
def test_write_response_must_confirm_whitelist(mapping):
    backend = AdminBackend()
    def handler(req):
        response = backend(req)
        data = response.json()
        data["data"]["credentials"]["model_mapping"] = mapping
        return httpx.Response(200, json=data)
    config = settings(model_whitelist=("gpt-5.5",))
    job = PushJob("fixture@example.com", account=account())
    with PoolClient(config, transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(PoolError) as error:
            push_one(client, config, job, [])
    assert error.value.uncertain and job.pending


def test_missing_mapping_in_write_response_is_read_back():
    backend = AdminBackend()
    def handler(req):
        response = backend(req)
        if req.method == "POST":
            data = response.json()
            del data["data"]["credentials"]["model_mapping"]
            return httpx.Response(200, json=data)
        return response
    config = settings(model_whitelist=("gpt-5.5",))
    job = PushJob("fixture@example.com", account=account())
    with PoolClient(config, transport=httpx.MockTransport(handler)) as client:
        push_one(client, config, job, [])
    assert job.state == "created"
    assert [req[0] for req in backend.requests] == ["POST", "GET"]


@pytest.mark.parametrize("extra", [{"openai_passthrough": True}, {"openai_oauth_passthrough": True}])
def test_passthrough_accounts_are_reported_before_any_write(extra):
    backend = AdminBackend([{**account(), "id": 8, "extra": extra}])
    job = PushJob("fixture@example.com", account=account())
    with backend.client() as client:
        with pytest.raises(PoolError, match="自动透传") as error:
            push_one(client, settings(model_whitelist=("gpt-5.5",)), job, client.accounts())
    assert error.value.category == "models" and job.pending is None
    assert all(req[0] == "GET" for req in backend.requests)


class PoolModelGuiTests(gui_tests.TkCase):
    def setUp(self):
        super().setUp()
        config_patch = patch.object(pool_gui, "CONFIG_PATH", Path(self.folder.name) / "pool.json")
        config_patch.start()
        self.addCleanup(config_patch.stop)

    page = pool_gui_tests.PoolGuiTests.page
    connect_page = pool_gui_tests.PoolGuiTests.connect_page

    def test_model_text_defaults_to_preserve_and_selection_survives_reload(self):
        _, page = self.page()
        self.connect_page(page, AdminBackend())
        assert page._settings().model_whitelist is None
        page.model_mode_var.set(pool_gui.MODEL_MODES["replace"])
        page.model_picker.custom_text.insert("1.0", "\n".join(MODEL_FIXTURE))
        assert page.model_picker.add_custom()
        assert page._settings().model_whitelist == MODEL_FIXTURE
        page._save_settings()
        data = json.loads(page.config_path.read_text(encoding="utf-8"))
        assert data["model_mode"] == "replace"
        assert data["model_whitelist_text"].splitlines() == list(MODEL_FIXTURE)
        page.model_mode_var.set(pool_gui.MODEL_MODES["clear"])
        assert page._settings().model_whitelist == ()
        page._load_settings()
        assert page.model_mode_var.get() == pool_gui.MODEL_MODES["replace"]
        assert page.model_picker.selected_models() == MODEL_FIXTURE

    def test_empty_whitelist_does_not_block_group_loading_but_blocks_start(self):
        _, page = self.page()
        page.model_mode_var.set(pool_gui.MODEL_MODES["replace"])
        self.connect_page(page, AdminBackend())
        with pytest.raises(ValueError, match="至少"):
            page._settings()
        page.input_text.insert("1.0", json.dumps(account()))
        with patch.object(page, "_launch") as launch:
            page.start()
        launch.assert_not_called()
        assert not page.task_lock.locked()

    def test_changed_whitelist_allows_repush_and_busy_disables_editing(self):
        _, page = self.page()
        self.connect_page(page, AdminBackend())
        page.input_text.insert("1.0", json.dumps(account()))
        assert page.preview()
        job = page.jobs[0]
        job.state = "created"
        job.completed_destination = page._settings().destination_id()
        page.model_mode_var.set(pool_gui.MODEL_MODES["replace"])
        page.model_picker.custom_text.insert("1.0", "\n".join(MODEL_FIXTURE))
        assert page.model_picker.add_custom()
        with patch.object(page, "_launch") as launch:
            page.start()
        launch.assert_called_once()
        assert page.model_picker.custom_text.cget("state") == tk.DISABLED
        assert str(page.model_picker.add_btn.cget("state")) == tk.DISABLED
        page._lock_held = False
        page.task_lock.release()
