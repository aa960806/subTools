"""Web migration contracts; synthetic accounts, no paid or live operations."""
import copy
import io
import json
import threading
import time
import zipfile
from pathlib import Path
from unittest.mock import Mock

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from account_inputs import account_input_from_mapping
from openai_reauth import ReauthResult
from server_engine import Engine, export_bytes, pacing_options, pool_settings
from server_storage import configure_storage, Store
from web_app import create_app
from test_pool import account, AdminBackend


@pytest.fixture
def data(tmp_path, monkeypatch):
    monkeypatch.delenv('SUBTOOLS_SECRET_KEY', raising=False)
    monkeypatch.delenv('SUBTOOLS_SECRET_KEY_FILE', raising=False)
    monkeypatch.delenv('SUBTOOLS_PUBLIC_ORIGIN', raising=False)
    monkeypatch.setenv('SUBTOOLS_DATA_DIR', str(tmp_path))
    monkeypatch.setenv('SUBTOOLS_SECRET_KEY_FILE', str(tmp_path / 'master.key'))
    (tmp_path / 'master.key').write_bytes(Fernet.generate_key())
    configure_storage(tmp_path)
    return tmp_path


@pytest.fixture
def engine(data):
    e = Engine(data)
    yield e
    e.close()


@pytest.fixture
def client(data):
    with TestClient(create_app(data, 'fixture-password-for-web'), raise_server_exceptions=False) as c:
        yield c


def login(client):
    r = client.post('/api/login', json={'password':'fixture-password-for-web'})
    assert r.status_code == 200
    client.headers['x-csrf-token'] = r.json()['csrf']


def finished(e, result):
    e.worker.join(5)
    assert not e.worker.is_alive()
    assert e.active is None
    return e.get(result['id'])


def fake_login(inputs, **options):
    results = []
    for i, item in enumerate(inputs, 1):
        result = ReauthResult(item.email, True, account=account(email=item.email))
        if options.get('result_transform'):
            result = options['result_transform'](item, result)
        results.append(result)
        if options.get('on_progress'):
            options['on_progress'](i, len(inputs), result)
    return results


def test_portable_encryption_no_plaintext_and_wrong_key_rejected(data, monkeypatch):
    store = Store(data)
    store.write('config/auth.json', {'password':'never-write-this-in-plaintext'})
    assert 'never-write' not in (data/'config/auth.json').read_text()
    assert store.read('config/auth.json')['password'] == 'never-write-this-in-plaintext'
    monkeypatch.setenv('SUBTOOLS_SECRET_KEY', Fernet.generate_key().decode())
    with pytest.raises(ValueError, match='解密'):
        store.read('config/auth.json')


def test_private_routes_require_session_and_csrf(client):
    for url in ('/api/config','/api/tasks','/api/legacy','/api/browser/frame'):
        assert client.get(url).status_code == 401
    login(client)
    token = client.headers.pop('x-csrf-token')
    assert client.put('/api/config/auth',json={'timeout':200}).status_code == 403
    client.headers['x-csrf-token'] = token
    assert client.put('/api/config/auth',json={'timeout':200}).status_code == 200
    assert client.put('/api/config/auth',json={},headers={'Origin':'https://evil.test'}).status_code == 403
    assert client.get('/data/master.key').status_code == 404
    assert 'frame-ancestors' in client.get('/').headers['content-security-policy']
    client.post('/api/logout',json={})
    assert client.get('/api/config').status_code == 401


def test_login_rate_limit_and_password_errors(client):
    for _ in range(8):
        assert client.post('/api/login', json={'password':'wrong'}).status_code == 401
    assert client.post('/api/login', json={'password':'wrong'}).status_code == 429


def test_invalid_requests_and_countries(client):
    login(client)
    assert client.post('/api/tasks', json=[]).status_code == 400
    assert client.post('/api/tasks', json={'kind':'unsupported'}).status_code == 400
    assert client.put('/api/config/auth', json={'show_browser':'false'}).status_code == 400
    assert client.post('/api/preview/auth', content='broken').status_code == 400
    countries = client.get('/api/countries').json()
    assert [r['pinyin'] for r in countries] == sorted(r['pinyin'] for r in countries)
    assert any(r['code']=='187' for r in countries)
    assert client.post('/api/legacy/open',json={'path':'../../master.key'}).status_code == 400


def test_secrets_preserved_and_explicitly_clearable(engine):
    result = engine.save_config('phone', {'api_key':'test-secret-key'})
    assert result['api_key']=='' and result['api_key_saved']
    engine.save_config('phone', {'api_key':''})
    assert engine.config('phone')['api_key']=='test-secret-key'
    engine.save_config('phone', {'clear_api_key':True})
    assert not engine.config('phone')['api_key']


def test_pacing_values_reach_original_oauth(engine, monkeypatch):
    authorize = Mock(side_effect=fake_login)
    monkeypatch.setattr('server_engine.run_batch_reauth', authorize)
    engine.save_config('auth', {'human_pacing':False,'human_scale':2.5})
    task=finished(engine, engine.start('auth','fixture@example.com----fixture-pass'))
    assert task['rows'][0]['state']=='success'
    assert authorize.call_args.kwargs['human'].enabled is False
    assert authorize.call_args.kwargs['human'].scale == 2.5
    public = json.dumps(engine.public(task['id']))
    assert 'fixture-pass' not in public and 'fixture-refresh' not in public
    assert 'fixture-pass' not in (engine.root/'tasks'/f"{task['id']}.json").read_text()


def test_refresh_failure_never_automatically_logins_then_explicit_identity_guard(engine, monkeypatch):
    from oauth_refresh import RefreshError
    refresh = Mock(side_effect=RefreshError('refresh_unknown','结果未确认'))
    monkeypatch.setattr('oauth_refresh.refresh_account',refresh)
    monkeypatch.setattr('oauth_refresh.recover_refresh_account',lambda *args,**kwargs:None)
    authorize = Mock(side_effect=fake_login)
    monkeypatch.setattr('server_engine.run_batch_reauth',authorize)
    original = account(space='different-workspace')
    task=finished(engine,engine.start('auth',json.dumps(original)))
    assert task['rows'][0]['state']=='refresh_unknown'
    assert not authorize.called
    finished(engine,engine.start('auth',previous=task['id']))
    assert refresh.call_count==1 and not authorize.called
    task=finished(engine,engine.start('auth',previous=task['id'],relogin=True))
    assert task['rows'][0]['state']=='identity'
    assert not task['accounts']
    assert task['items'][0]['oauth_account']['credentials']['chatgpt_account_id']=='different-workspace'


def test_rotation_checkpoint_survives_restart(engine, monkeypatch):
    updated=account(refresh_token='rotated-fixture-token')
    monkeypatch.setattr('oauth_refresh.refresh_account',Mock(return_value=updated))
    task=finished(engine,engine.start('auth',json.dumps(account())))
    saved=engine.store.read(f"tasks/{task['id']}.json")
    assert saved['items'][0]['oauth_account']['credentials']['refresh_token']=='rotated-fixture-token'
    restored=Engine(engine.root)
    try:
        assert restored.get(task['id'])['rows'][0]['state']=='success'
        assert restored.active is None
    finally:
        restored.close()


def test_single_task_gate_stop_and_unprocessed_rows(engine, monkeypatch):
    entered=threading.Event()
    def blocked(items, **options):
        entered.set()
        while not options['should_stop'](): time.sleep(.01)
        return []
    monkeypatch.setattr('server_engine.run_batch_reauth',blocked)
    task=engine.start('auth','fixture@example.com----fixture-pass')
    assert entered.wait(2)
    with pytest.raises(ValueError,match='已有任务'):
        engine.start('auth','other@example.com----fixture-pass')
    engine.stop.set()
    task=finished(engine,task)
    assert task['status']=='stopped' and task['rows'][0]['state']=='ready'


def test_phone_calls_existing_handler_with_retry_plan(engine, monkeypatch):
    runner=Mock(side_effect=lambda items,settings,**kw: fake_login(items,**kw))
    monkeypatch.setattr('server_engine.run_batch_phone_verify',runner)
    engine.save_config('phone', {'api_key':'fixture-key','country':'38','fallback_countries':['4'],
                              'country_retry_count':1,'auto_retry_count':2,'human_scale':1.7})
    task=finished(engine,engine.start('phone','fixture@example.com----fixture-pass'))
    assert task['rows'][0]['state']=='success'
    settings=runner.call_args.args[1]
    assert settings.number_attempts==3 and settings.fallback_countries==['4']
    assert runner.call_args.kwargs['human_options']=={'enabled':True,'scale':1.7}


def test_pool_create_then_identity_update_and_config(engine, monkeypatch):
    import pool_flow
    backend=AdminBackend()
    engine.save_config('pool',{'site':'https://sub2.test','credential':'fixture-key','group_ids':[7],
                              'proxy_id':42,'load_factor':5,'priority':9,'concurrency':6})
    monkeypatch.setattr('server_engine.run_pool_push',lambda *args,**kw:pool_flow.run_pool_push(
        *args,**kw,client_factory=backend.client,refresh=lambda a,**_:a))
    first=finished(engine,engine.start('pool',json.dumps(account())))
    second=finished(engine,engine.start('pool',json.dumps(account())))
    assert first['rows'][0]['state']=='created' and second['rows'][0]['state']=='updated'
    assert len(backend.records)==1
    record=next(iter(backend.records.values()))
    assert (record['proxy_id'],record['load_factor'],record['priority'],record['concurrency'])==(42,5,9,6)
    assert engine.transfer(first['id'],'pool')


def test_inspection_is_read_only_and_schedule_survives_unchanged_save(engine, monkeypatch):
    import pool_inspection
    backend=AdminBackend([{**account(),'id':1,'group_ids':[7]}])
    engine.save_config('pool',{'site':'https://sub2.test','credential':'fixture-key','group_ids':[7]})
    monkeypatch.setattr('server_engine.inspect_pool',lambda *args,**kw:pool_inspection.inspect_pool(
        *args,**kw,client_factory=backend.client))
    task=finished(engine,engine.start('inspect'))
    assert task['status']=='finished'
    assert backend.requests and all(r[0]=='GET' for r in backend.requests)
    engine.schedule={'minutes':10,'next':time.time()+600}
    engine.save_config('pool',{})
    assert engine.schedule
    engine.save_config('pool',{'group_ids':[8]})
    assert engine.schedule is None


def test_models_can_be_loaded_before_white_list_selection(engine, monkeypatch):
    engine.save_config('pool',{'site':'https://sub2.test','credential':'fixture-key','model_mode':'replace','model_choices':{}})
    config=engine.config('pool')
    assert pool_settings(config,reading=True).model_whitelist is None
    with pytest.raises(ValueError,match='模型'):
        pool_settings(config)


def test_conversion_export_standard_fields_and_collision_free_zip(client):
    login(client)
    text=json.dumps({'accounts':[account(),account()], 'exported_at':'2026-01-01T00:00:00Z'})
    r=client.post('/api/convert',json={'text':text,'target':'cpa'})
    assert r.status_code==200 and r.json()['count']==2
    result=client.post('/api/convert/export',json={'text':text,'target':'cpa'})
    with zipfile.ZipFile(io.BytesIO(result.content)) as archive:
        assert len(set(archive.namelist()))==2
        assert list(json.loads(archive.read(archive.namelist()[0])))==['type','email','expired','id_token','account_id','disabled','access_token','last_refresh','refresh_token']


def test_legacy_pool_restore_preserves_pending_journal(client, data):
    from pool_recovery import PoolJournal
    from pool_flow import parse_push_text
    from test_pool import settings
    jobs=parse_push_text(json.dumps(account()))
    path=data/'recovery/pool-example/queue.dpapi.json'
    PoolJournal(path).save(settings(),jobs)
    login(client)
    result=client.post('/api/legacy/open',json={'path':'pool-example/queue.dpapi.json'})
    assert result.status_code==200
    task=result.json()['task']
    assert task['status']=='interrupted'
    restored=data/'tasks'/task['id']/'queue.dpapi.json'
    assert restored.read_bytes()==path.read_bytes()
    assert 'credential' not in result.json()['settings']


def test_corrupt_task_preserved_and_reported(engine):
    file=engine.root/'tasks/broken.json'
    file.parent.mkdir(exist_ok=True)
    file.write_text('broken')
    reopened=Engine(engine.root)
    try:
        assert reopened.warnings and file.read_text()=='broken'
    finally:
        reopened.close()


def test_checkpoint_error_releases_task_gate(engine, monkeypatch):
    monkeypatch.setattr('server_engine.run_batch_reauth',fake_login)
    original=engine._save
    count=0
    def save(task):
        nonlocal count
        count+=1
        if count>1: raise OSError('disk full')
        return original(task)
    monkeypatch.setattr(engine,'_save',save)
    task=finished(engine,engine.start('auth','fixture@example.com----fixture-pass'))
    assert task['status']=='failed' and not engine.gate.locked()


def test_pool_defer_resume_does_not_repeat_completed_jobs(engine,monkeypatch):
    from pool_flow import PushJob
    from dataclasses import asdict
    from test_pool import settings
    from pool_recovery import PoolJournal
    engine.save_config('pool',{'site':'https://sub2.test','credential':'fixture-key','group_ids':[7,8],
                              'priority':12,'concurrency':4})
    job=PushJob('fixture@example.com',account=account(),state='deferred')
    tid='a'*32
    task={'id':tid,'kind':'pool','status':'interrupted','created':time.time(),'items':[asdict(job)],
          'rows':[{'uid':job.uid,'email':job.email,'state':'deferred','message':'','account_id':None}],
          'accounts':{},'logs':[],'report':None}
    engine.tasks[tid]=task
    PoolJournal(engine.root/'tasks'/tid/'queue.dpapi.json').save(settings(),[job])
    engine.defer(tid,[job.uid])
    def push(jobs,config,**kwargs):
        assert jobs[0].state=='ready'
        jobs[0].state='updated'
        kwargs['on_progress'](jobs[0])
    monkeypatch.setattr('server_engine.run_pool_push',push)
    task=finished(engine,engine.start('pool',previous=tid))
    assert task['rows'][0]['state']=='updated'
    with pytest.raises(ValueError,match='没有可处理'):
        engine.start('pool',previous=tid)


def test_browser_queue_does_not_replay_into_next_account():
    from browser_bridge import BrowserBridge, bind, attach, detach
    bridge=BrowserBridge()
    bind(bridge)
    try:
        attach(object())
        bridge.commands.put({'action':'text','text':'previous-account-secret'})
        detach()
        attach(object())
        assert bridge.commands.empty()
    finally:
        detach();bind(None)


def test_browser_handoff_requires_current_frame_and_rejects_stopped_task(client):
    from browser_bridge import bind, attach, detach
    login(client)
    e = client.app.state.engine
    e.active = 'fixture-handoff'
    e.bridge.enabled = True
    bind(e.bridge)
    try:
        attach(object())
        assert client.post('/api/browser/input', json={'action':'text','text':'x'}).status_code == 400
        e.bridge.frame = b'fixture-frame-one'
        first = client.get('/api/browser/frame')
        generation = first.headers['X-Browser-Generation']
        command = {'action':'text', 'text':'previous-account-secret', 'generation':generation}
        assert client.post('/api/browser/input', json=command).status_code == 200
        detach()
        attach(object())
        assert client.get('/api/browser/frame').status_code == 204
        e.bridge.frame = b'fixture-frame-two'
        assert client.post('/api/browser/input', json=command).status_code == 400
        assert e.bridge.commands.empty()
        second = client.get('/api/browser/frame')
        command['generation'] = second.headers['X-Browser-Generation']
        assert command['generation'] != generation
        assert client.post('/api/browser/input', json=command).status_code == 200
        e.stop.set()
        assert e.bridge.commands.empty()
        assert client.get('/api/browser/frame').status_code == 204
        assert client.post('/api/browser/input', json=command).status_code == 400
    finally:
        detach();bind(None)
        e.active = None
