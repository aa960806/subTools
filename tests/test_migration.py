import json
from pathlib import Path

from cryptography.fernet import Fernet
import pytest

from migrate_desktop import migrate
from server_storage import Store


def setup_source(tmp_path):
    source=tmp_path/'old'
    source.mkdir()
    (source/'openai_reauth.py').write_text('# source fixture')
    (source/'phone_smsbower.json').write_text(json.dumps({'api_key':'plain-fixture-key','timeout':'150',
        'max_reuse':'2','country':'4','auto_retry_count':'2','human_scale':'1.5'}))
    (source/'pool_push.json').write_text(json.dumps({'site':'https://sub2.test','credential':'plain-fixture-admin',
        'group_ids':[7],'load_factor':'5','priority':'12','concurrency':'4'}))
    (source/'recovery/run').mkdir(parents=True)
    (source/'recovery/run/accounts.json').write_text('{"accounts":[]}')
    return source


def test_migrate_copies_configs_and_history_without_touching_source(tmp_path,monkeypatch):
    monkeypatch.setenv('SUBTOOLS_SECRET_KEY',Fernet.generate_key().decode())
    monkeypatch.delenv('SUBTOOLS_SECRET_KEY_FILE',raising=False)
    monkeypatch.setenv('SUBTOOLS_DATA_DIR',str(tmp_path/'new'))
    source=setup_source(tmp_path)
    before={str(p.relative_to(source)):p.read_bytes() for p in source.rglob('*') if p.is_file()}
    result=migrate(source,tmp_path/'new')
    assert result=={'configs':2,'history_files':1,'rewrapped':0}
    store=Store(tmp_path/'new')
    assert store.read('config/phone.json')['sms_timeout']==150
    assert store.read('config/phone.json')['human_scale']==1.5
    assert store.read('config/pool.json')['credential']=='plain-fixture-admin'
    assert store.read('config/pool.json')['load_factor']==5
    assert {str(p.relative_to(source)):p.read_bytes() for p in source.rglob('*') if p.is_file()}==before
    assert 'plain-fixture' not in (tmp_path/'new/config/phone.json').read_text()
    with pytest.raises(ValueError,match='拒绝覆盖'):
        migrate(source,tmp_path/'new')


def test_failed_dpapi_conversion_keeps_original_and_does_not_install_configs(tmp_path,monkeypatch):
    monkeypatch.setenv('SUBTOOLS_SECRET_KEY',Fernet.generate_key().decode())
    monkeypatch.setenv('SUBTOOLS_DATA_DIR',str(tmp_path/'new'))
    source=setup_source(tmp_path)
    record=source/'recovery/run/broken.json'
    record.write_text('{"encrypted":"dpapi:invalid-fixture"}')
    with pytest.raises(ValueError,match='无法解密'):
        migrate(source,tmp_path/'new')
    assert record.exists()
    assert not (tmp_path/'new/config').exists()
