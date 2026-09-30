"""Live-sync API contract and model selection lifecycle with a local mock only."""

import copy
import json
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

import pool_gui
from pool_client import PoolError
from test_pool import AdminBackend, account
import test_gui as gui_tests
import test_pool_gui as pool_gui_tests


class ModelBackend(AdminBackend):
    def __init__(self):
        super().__init__([{**account(model_mapping={"old": "target"}), "id": 42}])
        self.catalog = {"models": ["gpt-5.5", "gpt-6-astra", "gpt-5.5"], "warnings": []}
        self.sync_error = None
        self.before_sync_return = None

    def __call__(self, request):
        if request.url.path.endswith("/models/sync-upstream"):
            self.requests.append((request.method, request.url.path, None, dict(request.headers)))
            if self.before_sync_return:
                self.before_sync_return()
            if self.sync_error == "timeout":
                raise httpx.ReadTimeout("secret upstream response", request=request)
            if self.sync_error:
                return httpx.Response(self.sync_error, json={"message": "fixture-admin-key fixture-access"})
            return httpx.Response(200, json={"code": 0, "data": self.catalog})
        return super().__call__(request)


def test_upstream_sync_uses_saved_oauth_account_and_keeps_its_configuration():
    backend = ModelBackend()
    unchanged = copy.deepcopy(backend.records)
    with backend.client() as client:
        models, notices = client.sync_models(42)
    assert models == ("gpt-5.5", "gpt-6-astra") and not notices
    assert [row[0] for row in backend.requests] == ["GET", "POST"]
    sync_request = backend.requests[-1]
    assert sync_request[1] == "/api/v1/admin/accounts/42/models/sync-upstream"
    assert sync_request[3]["x-api-key"] == "fixture-admin-key"
    assert sync_request[2] is None and "idempotency-key" not in sync_request[3]
    assert backend.records == unchanged


def test_model_source_list_excludes_shadows_and_never_retains_credentials():
    backend = ModelBackend()
    backend.records[43] = {**account(), "id": 43, "parent_account_id": 42}
    with backend.client() as client:
        sources = client.model_sources()
    assert sources == [{"id": 42, "name": "fixture@example.com"}]
    assert "fixture-access" not in repr(sources) and "credentials" not in repr(sources)


@pytest.mark.parametrize("record_changes", [{"type": "apikey"}, {"platform": "anthropic"}, {"parent_account_id": 7}])
def test_source_type_changes_cannot_sync_the_wrong_account(record_changes):
    backend = ModelBackend()
    backend.records[42].update(record_changes)
    with backend.client() as client:
        with pytest.raises(PoolError, match="类型已变化"):
            client.sync_models(42)
    assert all(row[0] == "GET" for row in backend.requests)


@pytest.mark.parametrize("error", [400, 401, 403, 404, 429, 500, 502, "timeout"])
def test_failed_sync_has_no_automatic_retry_or_raw_response_leak(error):
    backend = ModelBackend()
    backend.sync_error = error
    with backend.client() as client:
        with pytest.raises(PoolError) as caught:
            client.sync_models(42)
    assert len([row for row in backend.requests if row[0] == "POST"]) == 1
    assert "fixture-admin-key" not in str(caught.value)
    assert "fixture-access" not in str(caught.value)
    assert "secret upstream response" not in str(caught.value)


def test_gateway_error_is_distinguished_without_echoing_its_body():
    backend = ModelBackend()
    def handler(request):
        if request.url.path.endswith("/models/sync-upstream"):
            return httpx.Response(502, json={"cloudflare_error": True, "detail": "fixture-access fixture-admin-key"})
        return backend(request)
    from pool_client import PoolClient
    from test_pool import settings
    with PoolClient(settings(), transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(PoolError, match="站点网关") as caught:
            client.sync_models(42)
    assert caught.value.category == "server"
    assert "fixture-access" not in str(caught.value) and "fixture-admin-key" not in str(caught.value)


@pytest.mark.parametrize("catalog", [{}, {"models": "gpt-5.5"}, {"models": [None]}, {"models": ["gpt-*"]}, {"models": ["gpt-5.5"], "warnings": "bad"}])
def test_invalid_model_catalog_is_not_silently_accepted(catalog):
    backend = ModelBackend()
    backend.catalog = catalog
    with backend.client() as client:
        with pytest.raises(PoolError, match="保留原列表"):
            client.sync_models(42)


def test_capability_warnings_are_mapped_without_echoing_backend_messages():
    backend = ModelBackend()
    backend.catalog["warnings"] = [{"code": "upstream_model_metadata_partial", "message": "fixture-access"},
                                   {"code": "upstream_model_metadata_incomplete"}, {"code": ["bad"]}]
    with backend.client() as client:
        _, notices = client.sync_models(42)
    assert "部分模型能力" in notices[0] and "fixture-access" not in repr(notices)


class ModelSyncGuiTests(gui_tests.TkCase):
    page = pool_gui_tests.PoolGuiTests.page
    connect_page = pool_gui_tests.PoolGuiTests.connect_page

    def setUp(self):
        super().setUp()
        config_patch = patch.object(pool_gui, "CONFIG_PATH", Path(self.folder.name) / "pool.json")
        config_patch.start()
        self.addCleanup(config_patch.stop)

    def ready(self):
        _, page = self.page()
        backend = ModelBackend()
        self.connect_page(page, backend)
        page.model_mode_var.set(pool_gui.MODEL_MODES["replace"])
        self.work(page, backend, page.load_model_sources)
        assert page._model_source_id() == 42
        return page, backend

    def work(self, page, backend, operation):
        with patch.object(pool_gui, "PoolClient", backend.client):
            operation()
            page.worker.join(3)
        assert not page.worker.is_alive()
        page._drain()

    def remove_model(self, picker, model):
        row = next(row for row in picker.tree.get_children() if picker.tree.set(row, "model") == model)
        picker.tree.selection_set(row)
        picker._remove_selected()

    def test_sync_deselection_resync_and_push_use_only_retained_models(self):
        page, backend = self.ready()
        self.work(page, backend, page.sync_upstream_models)
        assert page._settings().model_whitelist == ("gpt-5.5", "gpt-6-astra")
        self.remove_model(page.model_picker, "gpt-5.5")
        backend.catalog["models"].append("gpt-5.6-sol")
        self.work(page, backend, page.sync_upstream_models)
        assert page._settings().model_whitelist == ("gpt-6-astra", "gpt-5.6-sol")
        assert page.model_picker.choices["gpt-5.5"] is False
        page.input_text.insert("1.0", json.dumps(account()))
        assert page.preview()
        with patch.object(pool_gui, "PoolClient", backend.client), patch.object(pool_gui, "TOOL_DIR", Path(self.folder.name)), \
                patch("pool_flow.refresh_account", side_effect=lambda source, **_: copy.deepcopy(source)):
            page._run_worker(page.jobs, page._settings(), 180, None, True)
        assert backend.records[42]["credentials"]["model_mapping"] == {"gpt-6-astra": "gpt-6-astra", "gpt-5.6-sol": "gpt-5.6-sol"}

    def test_empty_and_failed_sync_leave_existing_choices_untouched(self):
        page, backend = self.ready()
        self.work(page, backend, page.sync_upstream_models)
        self.remove_model(page.model_picker, "gpt-5.5")
        before = page.model_picker.snapshot()
        backend.catalog["models"] = []
        self.work(page, backend, page.sync_upstream_models)
        assert page.model_picker.snapshot() == before
        assert "空列表" in page.model_sync_var.get()
        backend.sync_error = 502
        self.work(page, backend, page.sync_upstream_models)
        assert page.model_picker.snapshot() == before
        assert "上游模型失败" in page.status_var.get()

    def test_cancellation_discards_late_catalog_without_mutating_selection(self):
        page, backend = self.ready()
        before = page.model_picker.snapshot()
        backend.before_sync_return = page.stop_flag.set
        self.work(page, backend, page.sync_upstream_models)
        assert page.model_picker.snapshot() == before
        assert "已停止" in page.model_sync_var.get()

    def test_changed_site_invalidates_source_and_ignores_stale_results(self):
        page, backend = self.ready()
        old_connection = page._connected_id
        page.site_var.set("https://new-sub2.test")
        assert page._model_source_id() is None and not page._model_sources
        page.events.put(("model_synced", old_connection, 42, ("gpt-5.5",), ()))
        page._drain()
        assert not page.model_picker.choices
        with patch.object(page, "_launch") as launch:
            page.sync_upstream_models()
        launch.assert_not_called()

    def test_new_site_without_oauth_accounts_explains_how_to_continue(self):
        page, backend = self.ready()
        backend.records.clear()
        self.work(page, backend, page.load_model_sources)
        assert page._model_source_id() is None
        assert "先推送一个账号" in page.model_sync_var.get()
        assert str(page.model_sync_btn.cget("state")) == "disabled"

    def test_deselections_and_legacy_text_migrate_through_config(self):
        _, page = self.page()
        page.config_path.write_text(json.dumps({"model_mode": "replace", "model_whitelist_text": "gpt-5.5\ngpt-6-astra"}), encoding="utf-8")
        page._load_settings()
        assert page.model_picker.selected_models() == ("gpt-5.5", "gpt-6-astra")
        self.remove_model(page.model_picker, "gpt-5.5")
        page._save_settings()
        page.model_picker.restore({})
        page._load_settings()
        page.model_picker.merge_upstream(("gpt-5.5", "gpt-6-astra"))
        assert page.model_picker.selected_models() == ("gpt-6-astra",)

    def test_custom_add_search_and_busy_edit_guards(self):
        page, _ = self.ready()
        picker = page.model_picker
        picker.custom_text.insert("1.0", "custom-model，gpt-5.5")
        assert picker.add_custom()
        picker.search_var.set("custom")
        assert len(picker.tree.get_children()) == 1
        picker.select_all(False)
        assert not picker.selected_models()
        picker.select_all(True)
        page._set_busy("model_sync")
        picker.select_all(False)
        assert len(picker.selected_models()) == 2
        assert not picker.add_custom()
        picker.search_var.set("")
        picker.tree.selection_set(picker.tree.get_children()[0])
        picker._remove_selected()
        assert len(picker.selected_models()) == 2

    def test_worker_reads_models_without_calling_tk(self):
        page, backend = self.ready()
        with patch.object(page.model_picker, "merge_upstream", side_effect=AssertionError("worker touched Tk")), \
             patch.object(pool_gui, "PoolClient", backend.client):
            page.sync_upstream_models()
            page.worker.join(3)
        assert not page.worker.is_alive()
        page._drain()
        assert page.model_picker.selected_models() == ("gpt-5.5", "gpt-6-astra")
