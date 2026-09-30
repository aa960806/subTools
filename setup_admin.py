"""Initialize or reset the web password locally; never prints the password."""
import argparse
import getpass
import os
import secrets
from pathlib import Path

from server_storage import configure_storage, Store
from web_app import password_hash


def main():
    parser = argparse.ArgumentParser(description='设置 SubTools 管理员密码')
    parser.add_argument('--generate', action='store_true', help='生成密码并保存到私有数据目录')
    parser.add_argument('--reset', action='store_true', help='明确重置现有密码（先停止服务）')
    args = parser.parse_args()
    root = configure_storage(os.environ.get('SUBTOOLS_DATA_DIR', Path(__file__).parent / 'data'))
    store = Store(root)
    if store.read('admin.json') and not args.reset:
        print('管理员已初始化；需要重置时先停止服务，再使用 --reset。')
        return
    if args.generate:
        password = secrets.token_urlsafe(24)
    else:
        password = getpass.getpass('管理员密码（至少 12 位）：')
        if password != getpass.getpass('再次输入：'):
            raise SystemExit('两次密码不一致')
    if len(password) < 12:
        raise SystemExit('密码至少 12 位')
    salt = secrets.token_hex(16)
    store.write('admin.json', {'salt': salt, 'hash': password_hash(password, salt)})
    if args.generate:
        file = root / 'initial-password.txt'
        fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as output:
            output.write(password + '\n')
        print(f'密码已写入：{file}；读取后请妥善保管或删除此文件。')
    else:
        (root / 'initial-password.txt').unlink(missing_ok=True)
        print('管理员密码已保存。')


if __name__ == '__main__':
    main()
