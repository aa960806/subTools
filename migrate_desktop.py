"""Migrate local settings/history using the original Windows user's DPAPI access.

Copies private state; moving the source installation is a separate final step.
No network operations, browser launches, or account mutations are performed.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil

from local_secrets import unprotect_secret, protect_secret
from server_engine import DEFAULTS, SECRET_FIELDS
from server_storage import configure_storage, Store


def portable(value, counter):
    if isinstance(value, dict):
        return {k:portable(v,counter) for k,v in value.items()}
    if isinstance(value, list):
        return [portable(v,counter) for v in value]
    if isinstance(value,str) and value.startswith('dpapi:'):
        clear = unprotect_secret(value)
        if not clear:
            raise ValueError('无法解密旧记录，请在原 Windows 用户下迁移；原文件未修改')
        protected = protect_secret(clear)
        if not protected.startswith('fernet:') or unprotect_secret(protected) != clear:
            raise ValueError('迁移后加密校验失败')
        counter[0] += 1
        return protected
    return value


def migrate(source, destination):
    source = Path(source).resolve()
    root = configure_storage(destination)
    if root == source or root.is_relative_to(source):
        raise ValueError('目标数据目录必须独立于旧工具目录')
    if not (source/'openai_reauth.py').is_file():
        raise ValueError('未找到旧工具源码，请检查目录')
    store = Store(root)
    counter, configs = [0], {}
    for kind, name in (('auth','auth_settings.json'),('phone','phone_smsbower.json'),('pool','pool_push.json')):
        file = source/name
        if not file.exists(): continue
        if (root/'config'/f'{kind}.json').exists():
            raise ValueError('目标已有配置，拒绝覆盖；请先备份并选择新的数据目录')
        old = json.loads(file.read_text(encoding='utf-8-sig'))
        value = copy.deepcopy(DEFAULTS[kind])
        for key in value:
            if key in old: value[key] = old[key]
        for field in SECRET_FIELDS[kind]:
            secret = value[field]
            value[field] = unprotect_secret(secret)
            if secret and not value[field]:
                raise ValueError(f'{kind} 配置无法解密，原文件未修改')
        if kind in ('auth','phone'):
            value['network_mode'] = old.get('network_mode', 'custom' if old.get('use_proxy',bool(value['proxy'])) else 'direct')
            value['proxy_scheme'] = value['proxy_scheme'].lower()
            value['human_scale'] = float(value['human_scale'])
        if kind=='phone': value['sms_timeout'] = old.get('timeout',180)
        for key, default in DEFAULTS[kind].items():
            if type(default) is int: value[key] = int(value[key])
        if kind=='pool':
            for key in ('proxy_id','load_factor'):
                value[key] = None if value[key] in (None,'') else int(value[key])
        configs[kind] = value
    original_recovery = source/'recovery'
    if (root/'recovery').exists():
        raise ValueError('目标已有恢复记录，拒绝覆盖')
    pending = root/'migration-pending'
    pending.mkdir(exist_ok=False)
    manifest = []
    try:
        if original_recovery.exists():
            for file in original_recovery.rglob('*'):
                if file.is_symlink(): raise ValueError('恢复目录含符号链接，请先人工核对')
                if not file.is_file(): continue
                target = pending/'recovery'/file.relative_to(original_recovery)
                target.parent.mkdir(parents=True,exist_ok=True)
                raw = file.read_bytes()
                if file.suffix=='.json':
                    data = json.loads(raw.decode('utf-8-sig'))
                    converted = portable(data,counter)
                    if converted != data:
                        target.write_text(json.dumps(converted,ensure_ascii=False,indent=2),encoding='utf-8')
                    else:
                        shutil.copy2(file,target)
                else:
                    shutil.copy2(file,target)
                manifest.append({'path':file.relative_to(source).as_posix(),
                                 'original_sha256':hashlib.sha256(raw).hexdigest(),
                                 'migrated_sha256':hashlib.sha256(target.read_bytes()).hexdigest()})
        # All records are readable and rewrapped before any target config is installed.
        for kind, config in configs.items():
            store.write(f'config/{kind}.json',config)
            if store.read(f'config/{kind}.json') != config: raise ValueError('配置校验失败')
        if (pending/'recovery').exists():
            (pending/'recovery').rename(root/'recovery')
        store.write('migration-manifest.json', {'source':str(source),'files':manifest,'rewrapped':counter[0]})
        pending.rmdir()
    except Exception:
        # Preserve staged files for diagnosis; never alter the original installation.
        raise
    return {'configs':len(configs),'history_files':len(manifest),'rewrapped':counter[0]}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description='迁移桌面版私有配置和恢复记录（不调用外部接口）')
    parser.add_argument('source',type=Path)
    parser.add_argument('--data',type=Path,default=Path(__file__).parent/'data')
    args=parser.parse_args()
    print(json.dumps(migrate(args.source,args.data),ensure_ascii=False))
