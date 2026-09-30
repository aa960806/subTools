"""Read-only import preview. Selection is revalidated against the exact input."""
import hashlib
import json

from account_inputs import input_records, account_input_from_mapping, parse_account_line
from pool_flow import parse_push_text, identity_of


def preview_import(kind, text, max_accounts):
    if kind not in ('auth', 'phone', 'pool') or not isinstance(text, str):
        raise ValueError('输入类型无效')
    rows, items, errors, identities = [], {}, [], {}
    try:
        for index, (line, raw) in enumerate(input_records(text)):
            if index >= max_accounts:
                raise ValueError(f'单批最多 {max_accounts} 条记录，请拆分输入')
            uid = str(index)
            try:
                if kind == 'pool':
                    parsed = parse_push_text(json.dumps(raw, ensure_ascii=False) if isinstance(raw, dict) else raw)
                else:
                    parsed = [account_input_from_mapping(raw, line, include_oauth=kind != 'phone')
                              if isinstance(raw, dict) else parse_account_line(raw, line)]
                if len(parsed) != 1:
                    raise ValueError('该记录包含多个账号，请拆分为独立账号对象')
                item = parsed[0]
                account = item.account if kind == 'pool' else item.oauth_account
                identity = identity_of(account) if account else ('', '', item.email.casefold())
                # Do not collapse multiple workspaces or resolve conflicting credentials.
                key = (identity[0], identity[1] or identity[2])
                previous = identities.get(key)
                message = getattr(item, 'message', '') or ('已有凭据，优先刷新' if account else '等待 OAuth 登录')
                row = {'uid': uid, 'line': line, 'email': item.email, 'state': 'ready', 'message': message,
                       'selectable': True, 'default_selected': previous is None}
                if previous is not None:
                    row.update(state='conflict', message='同身份重复或凭据冲突，请选择其中一条', default_selected=False)
                    for r in rows:
                        if r['uid'] == previous:
                            r.update(state='conflict', message=row['message'], default_selected=False)
                else:
                    identities[key] = uid
                items[uid] = (item, key)
                rows.append(row)
            except ValueError:
                # Parser errors may echo a malformed token or password. Keep preview safe.
                rows.append({'uid': uid, 'line': line, 'email': '未识别', 'state': 'invalid',
                             'message': f'第 {line} 行格式无效，请检查账号、JSON 或 2FA 格式',
                             'selectable': False, 'default_selected': False})
    except ValueError as exc:
        if str(exc).startswith('单批最多'):
            raise
        errors.append('JSON 结构或语法无效，后续记录未继续解析；请修正后重新识别')
    if not rows and not errors:
        errors.append('请输入账号或账号 JSON')
    return {'rows': rows, 'errors': errors, 'fingerprint': hashlib.sha256(text.encode()).hexdigest()}, items


def select_import(kind, text, max_accounts, selected=None, fingerprint=None):
    report, items = preview_import(kind, text, max_accounts)
    if report['errors']:
        raise ValueError('；'.join(report['errors']))
    if selected is None:
        if any(r['state'] != 'ready' for r in report['rows']):
            raise ValueError('输入含无效或重复记录，请先识别并选择要处理的账号')
        selected = list(items)
    else:
        if fingerprint != report['fingerprint']:
            raise ValueError('输入已变化，请重新识别后选择')
        if not isinstance(selected, list) or any(not isinstance(v, str) for v in selected):
            raise ValueError('导入选择无效')
        if len(selected) != len(set(selected)) or not set(selected) <= items.keys():
            raise ValueError('请选择有效账号记录')
    if not selected:
        raise ValueError('请至少选择一个有效账号')
    keys = [items[uid][1] for uid in selected]
    if len(keys) != len(set(keys)):
        raise ValueError('同一身份只能选择一条，请核对重复记录')
    # Preserve original input order even if checkbox selection order differs.
    return [item for uid, (item, _) in items.items() if uid in selected]
