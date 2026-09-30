"""Web hardening regression checks, using only synthetic account material."""
import copy
import io
import json
import time
import zipfile
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

import progress_events
from account_inputs import parse_account_line
from server_engine import export_bytes
from web_history import TaskHistory
from web_app import create_app
from web_imports import preview_import, select_import
from web_limits import RequestBudget
from test_pool import account
from test_web import data, engine, client, login, fake_login, finished


def test_partial_preview_is_safe_and_requires_explicit_selection(engine, monkeypatch):
    raw = 'good@example.com----fixture-password\nnot-an-email----private-wrong-input'
    report = engine.import_preview('auth', raw)
    assert [r['state'] for r in report['rows']] == ['ready', 'invalid']
    assert 'private-wrong-input' not in json.dumps(report)
    assert 'fixture-password' not in json.dumps(report)
    with pytest.raises(ValueError, match='先识别'):
        engine.start('auth', raw)
    spy = Mock(side_effect=fake_login)
    monkeypatch.setattr('server_engine.run_batch_reauth', spy)
    task = finished(engine, engine.start('auth', raw, import_selected=['0'], fingerprint=report['fingerprint']))
    assert len(task['rows']) == 1 and task['rows'][0]['state'] == 'success'
    with pytest.raises(ValueError, match='已变化'):
        engine.start('auth', raw + '\n', import_selected=['0'], fingerprint=report['fingerprint'])
    with pytest.raises(ValueError, match='有效'):
        engine.start('auth', raw, import_selected=['1'], fingerprint=report['fingerprint'])
    assert spy.call_count == 1


def test_duplicate_selection_keeps_workspaces_separate():
    first = account(space='space-a')
    second = account(space='space-b')
    text = json.dumps([first, second, first])
    report, _ = preview_import('pool', text, 10)
    assert [r['state'] for r in report['rows']] == ['conflict', 'ready', 'conflict']
    assert len(select_import('pool', text, 10, ['1', '2'], report['fingerprint'])) == 2
    with pytest.raises(ValueError, match='同一身份'):
        select_import('pool', text, 10, ['0', '2'], report['fingerprint'])
    with pytest.raises(ValueError, match='单批最多'):
        preview_import('pool', text, 2)
    report, _ = preview_import('auth', 'ok@example.com----pass\n{"broken":', 10)
    assert report['errors']
    with pytest.raises(ValueError, match='JSON'):
        select_import('auth', 'ok@example.com----pass\n{"broken":', 10, ['0'], report['fingerprint'])


def test_otpauth_accepts_standard_totp_without_altering_password():
    prefix = 'fixture@example.com----password-with----delimiters----'
    value = parse_account_line(prefix + 'otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&issuer=Test')
    assert value.password == 'password-with----delimiters'
    assert value.totp_secret == 'JBSWY3DPEHPK3PXP'
    for suffix in ('&algorithm=SHA256', '&digits=8', '&period=60', '&secret=SECOND'):
        with pytest.raises(ValueError):
            parse_account_line(prefix + 'otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP' + suffix)


def make_task(key, *, age=0, state='success', pending=None):
    return {'id': key, 'created': time.time() - age, 'finished': time.time() - age,
            'kind': 'auth', 'status': 'finished', 'message': 'fixture',
            'rows': [{'uid': '0', 'email': 'fixture@example.com', 'state': state}],
            'items': [{'password': 'fixture-secret', 'pending': pending}], 'accounts': {'0': account()}, 'logs': []}


def test_lazy_history_pagination_archive_and_recovery_preserved(engine):
    for index in range(35):
        engine._save(make_task(f'task-{index}', age=40 * 86400))
    pending = make_task('pending', age=40 * 86400, state='uncertain', pending={'key': 'fixture-write'})
    engine._save(pending)
    engine._save(make_task('unprocessed', age=40 * 86400, state='ready'))
    reopened = TaskHistory(engine.store, cache_size=3, archive_days=30)
    assert not reopened.cache
    assert reopened.page(0, 25, True)['total'] == 35
    assert len(reopened.page(25, 25, True)['rows']) == 10
    assert reopened.page()['total'] == 2
    assert 'fixture-secret' not in json.dumps(reopened.page(0, 100, True))
    for index in range(12):
        assert reopened[f'task-{index}']['accounts']
    assert len(reopened.cache) == 3
    reopened.archive('task-0', False)
    assert not TaskHistory(engine.store, archive_days=30).index['task-0']['archived']
    assert engine.store.read('tasks/pending.json')['items'][0]['pending']['key'] == 'fixture-write'
    with pytest.raises(ValueError, match='仅可归档'):
        reopened.archive('pending')
    with pytest.raises(ValueError):
        reopened['../../admin']


def test_history_cache_does_not_evict_running_task_or_requested_record(engine):
    history = TaskHistory(engine.store, cache_size=1)
    active = make_task('active')
    active['status'] = 'running'
    history.save(active)
    history.save(make_task('one'))
    history.save(make_task('two'))
    assert history['one']['id'] == 'one'
    assert history['active'] is active
    assert len(history.cache) == 2


def test_stale_summary_reconciles_checkpoint_and_restart_never_replays(engine):
    task = make_task('interrupted')
    task['status'] = 'running'
    engine._save(task)
    restored = TaskHistory(engine.store)
    assert restored.index['interrupted']['status'] == 'interrupted'
    assert restored['interrupted']['status'] == 'interrupted'
    task['status'] = 'finished'
    task['accounts']['0']['credentials']['refresh_token'] = 'fixture-rotated'
    engine.store.write('tasks/interrupted.json', task)  # process lost before summary write
    newer = TaskHistory(engine.store)
    assert newer['interrupted']['accounts']['0']['credentials']['refresh_token'] == 'fixture-rotated'
    assert newer.index['interrupted']['status'] == 'finished'
    (engine.root / 'history/interrupted.json').write_text('corrupt-summary')
    rebuilt = TaskHistory(engine.store)
    assert rebuilt['interrupted']['accounts']['0']['credentials']['refresh_token'] == 'fixture-rotated'


def test_observed_stages_are_public_and_observer_cannot_break_login(engine, monkeypatch):
    snapshots = []
    def authorize(items, **opts):
        progress_events.emit(items[0].email, 'page')
        progress_events.emit(items[0].email, 'email')
        snapshots.append(engine.public(engine.active))
        return fake_login(items, **opts)
    monkeypatch.setattr('server_engine.run_batch_reauth', authorize)
    task = finished(engine, engine.start('auth', 'fixture@example.com----fixture-pass'))
    assert snapshots[0]['rows'][0]['stage_active']
    assert [s['key'] for s in task['rows'][0]['steps']] == ['page', 'email']
    assert task['rows'][0]['steps'][-1]['status'] == 'done'
    assert not task['rows'][0]['stage_active']
    assert 'fixture-pass' not in json.dumps(snapshots)
    progress_events.bind(Mock(side_effect=ValueError('observer error')))
    try:
        progress_events.emit('fixture@example.com', 'page')
    finally:
        progress_events.bind(None)


def test_new_exports_keep_original_fields_and_selected_scope(client):
    login(client)
    first = account(email='Case@example.com')
    first['priority'] = 0
    first['credentials']['organization_id'] = 'fixture-org'
    first['extra'] = {'custom': 'preserve-me'}
    content, name, media, _ = export_bytes([first], 'cpa')
    assert media == 'application/json' and name.endswith('.json')
    assert list(json.loads(content)) == ['type', 'email', 'expired', 'id_token', 'account_id', 'disabled', 'access_token', 'last_refresh', 'refresh_token']
    content, name, media, _ = export_bytes([first, copy.deepcopy(first)], 'sub2-single')
    with zipfile.ZipFile(io.BytesIO(content)) as z:
        assert len(set(n.casefold() for n in z.namelist())) == 2
        restored = json.loads(z.read(z.namelist()[0]))['accounts'][0]
        assert restored['priority'] == 0
        assert restored['credentials']['organization_id'] == 'fixture-org'
        assert restored['extra']['custom'] == 'preserve-me'
    task = make_task('export')
    task['accounts']['1'] = account(email='other@example.com')
    task['rows'].append({'uid':'1', 'email':'other@example.com', 'state':'success'})
    e = client.app.state.engine
    e._save(task)
    response = client.get('/api/tasks/export/export?target=cpa&selected=1')
    assert response.status_code == 200 and response.json()['email'] == 'other@example.com'
    assert client.get('/api/tasks/export/export?selected=wrong').status_code == 400
    assert client.get('/api/history?limit=1').json()['total'] == 1
    assert client.post('/api/tasks/export/archive',json={}).status_code == 200
    assert client.get('/api/history').json()['total'] == 0
    assert client.get('/api/tasks/export').status_code == 200


def test_request_budgets_reset_and_leave_stop_and_poll_available(data, monkeypatch):
    budget = RequestBudget(1)
    with monkeypatch.context() as clock:
        clock.setattr('web_limits.time.monotonic', Mock(side_effect=[0, 0, 61]))
        assert budget.take() == 0
        assert budget.take() == 60
        assert budget.take() == 0
    monkeypatch.setenv('SUBTOOLS_SUBMITS_PER_MINUTE', '1')
    with TestClient(create_app(data, 'fixture-password-for-web')) as c:
        login(c)
        assert c.post('/api/tasks',json={'kind':'wrong'}).status_code == 400
        response = c.post('/api/tasks',json={'kind':'wrong'})
        assert response.status_code == 429 and int(response.headers['retry-after']) > 0
        assert c.get('/api/status').status_code == 200
        assert c.post('/api/tasks/fixture/stop').status_code == 200
