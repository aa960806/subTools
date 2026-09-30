"""Portable encrypted storage; application data never belongs in Git."""
from __future__ import annotations
import json
import os
from pathlib import Path
from cryptography.fernet import Fernet
from reauth_formats import _atomic_write_json


def configure_storage(directory):
    root = Path(directory).resolve()
    root.mkdir(parents=True, exist_ok=True)
    key = root / 'master.key'
    if not os.environ.get('SUBTOOLS_SECRET_KEY') and not os.environ.get('SUBTOOLS_SECRET_KEY_FILE'):
        if not key.exists():
            fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(Fernet.generate_key())
        os.environ['SUBTOOLS_SECRET_KEY_FILE'] = str(key)
    os.environ['SUBTOOLS_DATA_DIR'] = str(root)
    return root


class Store:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def write(self, path, data):
        from local_secrets import protect_secret, is_protected
        value = protect_secret(json.dumps(data, ensure_ascii=False, allow_nan=False))
        if not is_protected(value):
            raise RuntimeError('无法加密保存，请检查数据密钥')
        _atomic_write_json(self.root / path, {'version': 1, 'encrypted': value}, overwrite=True)

    def read(self, path, default=None):
        from local_secrets import unprotect_secret, is_protected
        file = self.root / path
        if not file.exists():
            return default
        outer = json.loads(file.read_text(encoding='utf-8'))
        if outer.get('version') != 1 or not is_protected(outer.get('encrypted')):
            raise ValueError('加密记录格式不正确')
        value = unprotect_secret(outer['encrypted'])
        if not value:
            raise ValueError('无法解密记录，请检查原始数据密钥')
        return json.loads(value)
