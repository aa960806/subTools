"""Single-worker orchestration around the existing OAuth/SMS/pool engines."""
from __future__ import annotations
import copy
import io
import json
import os
import threading
import time
import uuid
import zipfile
from dataclasses import asdict
from pathlib import Path

from account_inputs import AccountInput, load_accounts, login_mapping
from browser_bridge import BrowserBridge, StopEvent, bind, detach
from human_pacing import human_settings_from_options
from oauth_refresh import run_refresh_first
from login_interaction import LoginInteraction
from protocol_login import run_batch_protocol
from openai_reauth import run_batch_reauth, set_log_callback, redact_diagnostic
from phone_flow import parse_phone_jobs, run_batch_phone_verify
from phone_network import resolve_phone_proxy
from phone_pool import SmsbowerSettings, phone_retry_plan
from phone_smsbower import SmsBowerClient, validate_price, parse_country_choice
from pool_client import PoolSettings, PoolClient, PoolError
from pool_flow import parse_push_text, run_pool_push
from pool_inspection import inspect_pool, inspection_delta
from pool_recovery import PoolJournal
from reauth_conversion import parse_conversion_text
from reauth_formats import build_export_payload, build_cpa_payload, safe_email_filename, conversion_warnings, _conversion_identity
from server_storage import Store
from web_history import TaskHistory
from web_imports import preview_import, select_import
import progress_events

DEFAULTS = {
    'auth': {'network_mode': 'direct', 'proxy': '', 'proxy_scheme': 'http', 'timeout': 180,
             'show_browser': False, 'human_pacing': True, 'human_scale': 1.0, 'login_method': 'browser'},
    'phone': {'api_key': '', 'network_mode': 'direct', 'proxy': '', 'proxy_scheme': 'http',
              'country': '38', 'fallback_countries': [], 'max_reuse': 3, 'min_price': '', 'max_price': '0.06',
              'sms_timeout': 180, 'timeout': 300, 'sms_poll_interval': 5, 'auto_retry_count': 2,
              'country_retry_count': 0, 'auto_price_match': True, 'show_browser': True,
              'human_pacing': True, 'human_scale': 1.0},
    'pool': {'site': '', 'auth_kind': 'api_key', 'credential': '', 'group_ids': [], 'priority': 50,
             'concurrency': 3, 'model_mode': 'preserve', 'model_choices': {}, 'scheduling_mode': 'override',
             'proxy_id': None, 'load_factor': None, 'timeout': 180, 'show_browser': False, 'login_method': 'browser'},
}
SECRET_FIELDS = {'auth': ('proxy',), 'phone': ('api_key', 'proxy'), 'pool': ('credential',)}


def integer(value, label, minimum=0, maximum=10000):
    if isinstance(value, bool) or not str(value).isascii() or not str(value).isdecimal():
        raise ValueError(f'{label}必须是整数')
    value = int(value)
    if not minimum <= value <= maximum:
        raise ValueError(f'{label}应为 {minimum}–{maximum}')
    return value


def pacing_options(config):
    return {'enabled': config['human_pacing'], 'scale': config['human_scale']}


def pool_settings(config, *, reading=False):
    mode = config['model_mode']
    if mode not in ('preserve', 'replace', 'clear'):
        raise ValueError('模型设置无效')
    models = None if mode == 'preserve' else tuple(k for k, v in config['model_choices'].items() if v) if mode == 'replace' else ()
    if mode == 'replace' and not models and not reading:
        raise ValueError('请至少保留一个模型，或明确选择清除限制')
    if reading:
        models = None
    config = PoolSettings(config['site'], config['auth_kind'], config['credential'], tuple(config['group_ids']),
                          integer(config['priority'], '优先级'), integer(config['concurrency'], '并发数'), models,
                          config['scheduling_mode'], config['proxy_id'], config['load_factor'])
    config.validate(require_groups=False)
    return config


def proxy_for(config):
    return resolve_phone_proxy(config['network_mode'], config.get('proxy', ''), config.get('proxy_scheme', 'http')) or None


def sms_settings(config):
    settings = SmsbowerSettings(api_key=config['api_key'], country=parse_country_choice(config['country']),
        fallback_countries=config['fallback_countries'], min_price=validate_price(config['min_price']),
        max_price=validate_price(config['max_price']), max_reuse=integer(config['max_reuse'], '复用数量', 1),
        sms_timeout=integer(config['sms_timeout'], '短信超时', 30, 3600),
        sms_poll_interval=integer(config['sms_poll_interval'], '轮询间隔', 1, 60),
        number_attempts=integer(config['auto_retry_count'], '小重试', 0, 100) + 1,
        country_retry_count=integer(config['country_retry_count'], '大重试', 0, 100),
        proxy=proxy_for(config) or '', network_source=config['network_mode'], auto_price_match=config['auto_price_match'])
    if not settings.api_key.strip():
        raise ValueError('请填写 SMSBower API Key')
    phone_retry_plan(settings)
    return settings


def export_bytes(accounts, target):
    if target not in ('sub2', 'sub2-single', 'cpa'):
        raise ValueError('目标格式无效')
    if not accounts:
        raise ValueError('没有可导出的账号')
    warnings = conversion_warnings(accounts, 'sub2' if target == 'sub2-single' else target)
    if target == 'sub2':
        return json.dumps(build_export_payload(accounts), ensure_ascii=False, indent=2).encode(), 'accounts.json', 'application/json', warnings
    members = []
    stream, used = io.BytesIO(), set()
    for account in accounts:
        payload = build_cpa_payload(account) if target == 'cpa' else build_export_payload([account])
        email = payload['email'] if target == 'cpa' else _conversion_identity(account)['email'] or 'account'
        stem, suffix = safe_email_filename(email), 1
        name = stem + '.json'
        while name.casefold() in used:
            suffix += 1
            name = f'{stem}__{suffix}.json'
        used.add(name.casefold())
        members.append((name, json.dumps(payload, ensure_ascii=False, indent=2).encode()))
    if len(members) == 1:
        name, content = members[0]
        return content, name, 'application/json', warnings
    with zipfile.ZipFile(stream, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, content in members:
            archive.writestr(name, content)
    return stream.getvalue(), f'{target}-accounts.zip', 'application/zip', warnings


class Engine:
    def __init__(self, root):
        self.root = Path(root)
        self.store = Store(root)
        self.lock = threading.RLock()
        self.gate = threading.Lock()
        self.max_accounts = integer(os.environ.get('SUBTOOLS_MAX_ACCOUNTS', '200'), '单批账号上限', 1, 10000)
        self.tasks = TaskHistory(self.store,
            cache_size=integer(os.environ.get('SUBTOOLS_TASK_CACHE', '20'), '任务缓存', 1, 200),
            archive_days=integer(os.environ.get('SUBTOOLS_ARCHIVE_DAYS', '30'), '自动归档天数', 0, 3650))
        self.active = None
        self.worker = None
        self.bridge = BrowserBridge()
        self.interaction = LoginInteraction()
        self.stop = StopEvent(self.bridge)
        self.closed = threading.Event()
        self.schedule = None
        self.inspection = None
        self.warnings = list(self.tasks.warnings)
        self.timer = threading.Thread(target=self._timer, daemon=True)
        self.timer.start()

    def config(self, kind, public=False):
        with self.lock:
            value = {**copy.deepcopy(DEFAULTS[kind]), **(self.store.read(f'config/{kind}.json', {}) or {})}
        if public:
            for field in SECRET_FIELDS[kind]:
                value[field + '_saved'] = bool(value.get(field))
                value[field] = ''
        return value

    def save_config(self, kind, changes):
        with self.lock:
            value = self.config(kind)
            previous = copy.deepcopy(value)
            for key in DEFAULTS[kind]:
                if key in changes:
                    if key in SECRET_FIELDS[kind] and changes[key] == '' and not changes.get('clear_' + key):
                        continue
                    value[key] = changes[key]
                if key in SECRET_FIELDS[kind] and changes.get('clear_' + key):
                    value[key] = ''
            for key, default in DEFAULTS[kind].items():
                if isinstance(default, bool) and type(value[key]) is not bool:
                    raise ValueError(f'{key} 必须是布尔值')
                if isinstance(default, (dict, list, str)) and not isinstance(value[key], type(default)):
                    raise ValueError(f'{key} 格式不正确')
            if value.get('login_method', 'browser') not in ('browser', 'protocol'):
                raise ValueError('登录方式须为浏览器或协议')
            self.store.write(f'config/{kind}.json', value)
            if kind == 'pool' and any(value[k] != previous[k] for k in ('site', 'auth_kind', 'credential', 'group_ids')):
                self.schedule = None
        return self.config(kind, public=True)

    def _save(self, task):
        self.tasks.save(task)

    def get(self, task_id):
        with self.lock:
            if task_id not in self.tasks:
                raise ValueError('任务不存在')
            return self.tasks[task_id]

    def public(self, task_id):
        with self.lock:
            task = self.get(task_id)
            result = copy.deepcopy({k: task.get(k) for k in ('id', 'kind', 'status', 'created', 'message', 'rows', 'logs', 'report', 'warnings')})
            result['login_method'] = task.get('config', {}).get(task['kind'], {}).get('login_method', 'browser')
            result['login_prompt'] = self.interaction.snapshot() if self.active == task_id else None
            for row in result.get('rows', []):
                end = time.time() if row.get('stage_active') else row.get('stage_finished', row.get('stage_started', 0))
                row['stage_seconds'] = max(0, int(end - row.get('stage_started', end)))
            return result

    def list_tasks(self):
        with self.lock:
            return self.tasks.page(limit=200)['rows']

    def import_preview(self, kind, text):
        return preview_import(kind, text, self.max_accounts)[0]

    def export_accounts(self, task_id, selected=None):
        task = self.get(task_id)
        if selected is not None:
            if not isinstance(selected, list) or any(not isinstance(s, str) for s in selected) or not selected:
                raise ValueError('请选择需要导出的成功账号')
            if not set(selected) <= {r['uid'] for r in task['rows']}:
                raise ValueError('选中账号不属于此任务')
        successful = {r['uid'] for r in task['rows'] if r['state'] in ('success', 'created', 'updated')}
        accounts = [a for uid, a in task['accounts'].items() if uid in successful and (selected is None or uid in selected)]
        if not accounts:
            raise ValueError('选中范围内没有成功结果可导出')
        return accounts

    def preview(self, kind, text):
        if kind == 'pool':
            jobs = parse_push_text(text)
            return [{'email':j.email, 'message':j.message} for j in jobs]
        items = parse_phone_jobs(text) if kind == 'phone' else load_accounts(text)
        return [{'email':x.email, 'message':'已有凭据，优先刷新' if x.oauth_account else '等待 OAuth 登录'} for x in items]

    def start(self, kind, text='', *, previous=None, selected=None, relogin=False, import_selected=None, fingerprint=None):
        if kind not in ('auth', 'phone', 'pool', 'inspect'):
            raise ValueError('任务类型无效')
        if not self.gate.acquire(blocking=False):
            raise ValueError('已有任务运行，请先停止或等待结束')
        try:
            configs = {k:self.config(k) for k in DEFAULTS}
            config = configs['pool' if kind == 'inspect' else kind]
            if config.get('login_method', 'browser') not in ('browser', 'protocol'):
                raise ValueError('登录方式须为浏览器或协议')
            if kind in ('pool', 'inspect'):
                pool_settings(config, reading=kind == 'inspect').validate(require_groups=kind == 'pool')
            if kind != 'inspect':
                integer(config['timeout'], '账号超时', 30, 7200)
                human_settings_from_options(pacing_options(configs['auth' if kind == 'pool' else kind]))
                proxy_for(configs['auth' if kind == 'pool' else kind])
            if kind == 'phone':
                sms_settings(config)
            with self.lock:
                if previous:
                    task = self.get(previous)
                    if task['kind'] != kind:
                        raise ValueError('任务类型不一致')
                    task = copy.deepcopy(task)
                else:
                    items = [] if kind == 'inspect' else select_import(kind, text, self.max_accounts, import_selected, fingerprint)
                    task = {'id':uuid.uuid4().hex, 'created':time.time(), 'kind':kind, 'status':'ready',
                            'items':[asdict(x) for x in items], 'rows':[], 'accounts':{}, 'logs':[], 'message':'等待处理', 'report':None}
                    task['rows'] = [{'uid':x.uid if kind == 'pool' else str(i), 'email':x.email, 'state':'ready', 'message':'等待处理', 'account_id':None}
                                    for i,x in enumerate(items)]
                if selected is not None and (not isinstance(selected, list) or any(not isinstance(v,str) for v in selected)):
                    raise ValueError('选中账号列表无效')
                if selected is not None and not set(selected) <= {r['uid'] for r in task['rows']}:
                    raise ValueError('选中账号不属于此任务')
                chosen = [r['uid'] for r in task['rows'] if (selected is None or r['uid'] in selected)
                          and r['state'] not in ('success','created','updated','deferred')]
                if kind != 'inspect' and not chosen:
                    raise ValueError('没有可处理账号；成功或暂缓账号不会重复执行')
                if previous and kind != 'inspect' and config.get('login_method', 'browser') == 'browser' and (relogin or any(r['uid'] in chosen and r['state']=='needs_interaction' for r in task['rows'])):
                    config['show_browser'] = True
                for row in task['rows']:
                    if row['uid'] in chosen:
                        row['state'] = 'ready'
                        for key in ('stage', 'stage_started', 'stage_finished', 'steps', 'stage_active'):
                            row.pop(key, None)
                task.update(status='running', message='任务运行中', config=configs, finished=None)
                self._save(task)
                self.active = task['id']
                self.bridge = BrowserBridge()
                self.interaction = LoginInteraction()
                self.bridge.enabled = kind != 'inspect' and config.get('login_method', 'browser') == 'browser' and config.get('show_browser', False)
                self.stop = StopEvent(self.bridge)
            self.worker = threading.Thread(target=self._run, args=(task, chosen, relogin), daemon=True)
            self.worker.start()
            return self.public(task['id'])
        except BaseException:
            self.gate.release()
            raise

    def _run(self, task, chosen, relogin):
        self.stop.owner = threading.get_ident()
        bind(self.bridge)
        kind, configs = task['kind'], task['config']
        config = configs['pool' if kind == 'inspect' else kind]
        secrets = []
        def gather(value):
            if isinstance(value, dict):
                for k,v in value.items():
                    if k in ('password','totp_secret','mailbox_url','access_token','id_token','refresh_token','api_key','credential','proxy') and isinstance(v,str) and v:
                        secrets.append(v)
                    else: gather(v)
            elif isinstance(value, list):
                for v in value: gather(v)
        gather(task)
        def log(message):
            with self.lock:
                task['logs'].append(redact_diagnostic(str(message), tuple(secrets)))
                task['logs'] = task['logs'][-1500:]
        def stage(email, key):
            with self.lock:
                candidates = [r for r in task['rows'] if r['uid'] in chosen and r['email'].casefold() == email.casefold()
                              and r['state'] in ('ready', 'not_processed', 'relogin', 'refreshing', 'pushing')]
                if not candidates:
                    return
                row = next((r for r in candidates if r.get('stage_active')), candidates[0])
                if row.get('stage') == key and row.get('stage_active'):
                    return
                now = time.time()
                steps = row.setdefault('steps', [])
                if steps and steps[-1]['status'] == 'active':
                    steps[-1].update(status='done', seconds=max(0, int(now - steps[-1]['started'])))
                steps.append({'key': key, 'label': progress_events.LABELS[key], 'status': 'active', 'started': now})
                row['steps'] = steps[-20:]
                row.update(stage=key, stage_started=now, stage_active=True)
        def finish_stage(row):
            row.update(stage_active=False, stage_finished=time.time())
            if row.get('steps'):
                step = row['steps'][-1]
                step.update(status='done' if row['state'] in ('success', 'created', 'updated') else 'attention',
                            seconds=max(0, int(time.time() - step['started'])))
        def progress(index, total, result):
            uid = chosen[index - 1]
            with self.lock:
                row = next(r for r in task['rows'] if r['uid'] == uid)
                row.update(state='success' if result.ok else result.category, message=result.error or '授权成功', phone_status=result.phone_status)
                finish_stage(row)
                item = items[index - 1]
                if result.ok and result.account:
                    item.oauth_account = result.account
                    item.refresh_state = 'refreshed'
                elif result.category in ('refresh_failed', 'refresh_unknown', 'refreshing'):
                    item.refresh_state = result.category
                row['refresh_state'] = item.refresh_state
                # Store rotated credentials and decision-needed state before continuing.
                task['items'][int(uid)] = asdict(item)
                if kind == 'phone' and result.ok:
                    row['message'] = '手机号绑定成功，OAuth 完成' if result.phone_status == 'verified' else 'OAuth 完成，本次未补绑手机号'
                if result.ok and result.account:
                    task['accounts'][uid] = result.account
                self._save(task)
        set_log_callback(log)
        progress_events.bind(stage)
        recovery = self.root / 'recovery'
        try:
            if kind == 'inspect':
                report = inspect_pool(pool_settings(config, reading=True), self.stop, group_ids=config['group_ids'])
                with self.lock:
                    report['changes'] = inspection_delta(self.inspection, report)
                    self.inspection = report
                    task['report'] = report
                    task['rows'] = [{'uid':str(x['id']), 'email':x['email'], 'state':'attention' if x['issues'] else 'success',
                                     'message':'；'.join(x['issues']) or '未发现已存状态异常（未测上游）', 'account_id':x['id']} for x in report['accounts']]
            elif kind == 'pool':
                journal_path = self.root / 'tasks' / task['id'] / 'queue.dpapi.json'
                journal = PoolJournal(journal_path)
                if journal_path.exists():
                    _, jobs = journal.load()
                else:
                    from pool_flow import PushJob
                    jobs = [PushJob(**{**r, 'login':AccountInput(**r['login']) if r.get('login') else None}) for r in task['items']]
                rows = {r['uid']:r for r in task['rows']}
                for j in jobs:
                    if rows[j.uid]['state'] == 'deferred':
                        j.state = 'deferred'
                    elif j.state == 'deferred':
                        j.state = 'ready'
                selected_jobs = [j for j in jobs if j.uid in chosen]
                def pool_progress(job):
                    with self.lock:
                        rows[job.uid].update(state=job.state, message=job.message, account_id=job.account_id, refresh_state=job.refresh_state)
                        if job.state in ('pushing', 'refreshing'):
                            stage(job.email, 'pushing' if job.state == 'pushing' else 'refresh')
                        elif job.state not in ('ready', 'relogin'):
                            finish_stage(rows[job.uid])
                        task['items'] = [asdict(j) for j in jobs]
                        if job.account: task['accounts'][job.uid] = job.account
                        self._save(task)
                    log(f'{job.email}：{job.message}')
                pacing = human_settings_from_options(pacing_options(configs['auth']))
                def authorize(*args, **kwargs):
                    if config['login_method'] == 'protocol':
                        return run_batch_protocol(*args, **kwargs, human=pacing, prompt=self.interaction.request)
                    return run_batch_reauth(*args, **kwargs, human=pacing)
                run_pool_push(selected_jobs, pool_settings(config), stop=self.stop, on_progress=pool_progress,
                    timeout=int(config['timeout']), proxy=proxy_for(configs['auth']), headless=not config['show_browser'],
                    recovery_dir=recovery, journal=journal, journal_jobs=jobs, authorize=authorize,
                    relogin_ids=tuple(chosen) if relogin else ())
            else:
                items = [AccountInput(**task['items'][int(uid)]) for uid in chosen]
                if kind == 'auth':
                    # Keep imported identity and metadata when the user explicitly opts in.
                    from pool_flow import find_existing
                    originals = {}
                    if relogin:
                        for item in items:
                            if item.oauth_account and item.refresh_state in ('refresh_failed', 'refresh_unknown', 'refreshing'):
                                originals[id(item)] = copy.deepcopy(item.oauth_account)
                                item.oauth_account = None
                    def verify_result(item, result):
                        original = originals.get(id(item))
                        if original:
                            item.oauth_account = original
                        if not original or not result.ok:
                            return result
                        try:
                            if not find_existing(result.account, [{**original, 'id':1}]):
                                raise PoolError('重新登录的账号或空间不一致，未替换原输入', category='identity')
                        except PoolError as exc:
                            result.ok, result.category, result.error, result.account = False, 'identity', str(exc), None
                            return result
                        merged = copy.deepcopy(original)
                        merged['credentials'].update(result.account['credentials'])
                        from oauth_refresh import clear_synthetic_marker
                        clear_synthetic_marker(merged)
                        result.account = merged
                        return result
                    def guarded_authorize(batch, **opts):
                        if config['login_method'] == 'protocol':
                            return run_batch_protocol(batch, **opts, result_transform=verify_result, prompt=self.interaction.request)
                        return run_batch_reauth(batch, **opts, result_transform=verify_result)
                    def runner(batch, **opts):
                        return run_refresh_first(batch, authorize=guarded_authorize, **opts)
                else:
                    def runner(batch, **opts):
                        opts.pop('human',None)
                        return run_batch_phone_verify(batch, sms_settings(config), **opts, human_options=pacing_options(config))
                runner(items, timeout=int(config['timeout']), proxy=proxy_for(config), headless=not config['show_browser'],
                       should_stop=self.stop.is_set, on_progress=progress, recovery_dir=recovery,
                       human=human_settings_from_options(pacing_options(config)))
                with self.lock:
                    for uid, item in zip(chosen, items):
                        # Login-only copies must not erase the preserved refresh identity.
                        if kind == 'auth' and item.oauth_account is None and id(item) in originals:
                            item.oauth_account = originals[id(item)]
                        task['items'][int(uid)] = asdict(item)
            task['status'] = 'stopped' if self.stop.is_set() else 'finished'
            task['message'] = '已停止，可重试未成功账号' if self.stop.is_set() else '本轮结束，请查看逐账号结果'
        except Exception as exc:
            task['status'] = 'stopped' if self.stop.is_set() else 'failed'
            task['message'] = redact_diagnostic(str(exc), tuple(secrets)) if isinstance(exc, ValueError) or hasattr(exc,'category') else f'运行中断（{type(exc).__name__}），已保留任务'
            log(task['message'])
        finally:
            self.interaction.clear()
            progress_events.bind(None)
            set_log_callback(None)
            detach()
            bind(None)
            try:
                with self.lock:
                    task['finished'] = time.time()
                    for row in task['rows']:
                        if row.get('stage_active'):
                            finish_stage(row)
                    try:
                        self._save(task)
                    except Exception:
                        task['status'] = 'failed'
                        task['message'] = '任务保存失败；请立即导出当前结果并检查数据目录权限和空间'
                    finally:
                        self.active = None
            finally:
                self.gate.release()

    def defer(self, task_id, selected):
        with self.lock:
            task = self.get(task_id)
            if self.active == task_id: raise ValueError('运行中不可暂缓')
            pending = {i.get('uid') for i in task['items'] if i.get('pending')}
            for row in task['rows']:
                if row['uid'] in selected and row['uid'] not in pending and row['state'] not in ('success','created','updated'):
                    row['state'] = 'ready' if row['state'] == 'deferred' else 'deferred'
                    row['message'] = '等待处理' if row['state'] == 'ready' else '已暂缓'
            self._save(task)
        return self.public(task_id)

    def transfer(self, task_id, target, selected=None):
        with self.lock:
            task = self.get(task_id)
            if target == 'phone':
                rows = [r for r in task['rows'] if (selected is None or r['uid'] in selected) and r['state'] in ('phone_required','deferred','failed','needs_interaction')]
                records = []
                for row in rows:
                    raw = next((i.get('login') for i in task['items'] if i.get('uid') == row['uid']), None) if task['kind'] == 'pool' else task['items'][int(row['uid'])]
                    if raw: records.append(login_mapping(AccountInput(**raw)))
            elif target == 'pool':
                successful = {r['uid'] for r in task['rows'] if r['state'] in ('success','created','updated')}
                records = [value for uid,value in task['accounts'].items() if uid in successful and (selected is None or uid in selected)]
            else:
                raise ValueError('转入目标无效')
            if not records: raise ValueError('没有可转入的账号')
            return json.dumps(records, ensure_ascii=False, indent=2)

    def remote(self, action):
        with PoolClient(pool_settings(self.config('pool'), reading=True)) as client:
            if action == 'connect': return {'groups':client.groups(), 'proxies':client.proxies()}
            if action == 'sources': return client.model_sources()
            models, notices = client.sync_models(integer(action, '来源 ID', 1, 2**53))
            return {'models':models,'notices':notices}

    def sms_read(self, action):
        config = self.config('phone')
        client = SmsBowerClient(api_key=config['api_key'], proxy=proxy_for(config))
        if not config['api_key']: raise ValueError('请先保存 SMSBower API Key')
        if action == 'balance': return {'balance':client.get_balance()}
        if action == 'prices': return client.get_price_options()
        if action == 'quotes': return client.get_prices('dr', parse_country_choice(config['country']))
        raise ValueError('查询类型无效')

    def _timer(self):
        maintenance_at = time.monotonic() + 3600
        while not self.closed.wait(1):
            with self.lock:
                schedule = copy.deepcopy(self.schedule)
                if time.monotonic() >= maintenance_at:
                    try: self.tasks.archive_completed()
                    except Exception: self.warnings = ['历史任务归档失败，原始记录仍保留']
                    maintenance_at = time.monotonic() + 3600
            if schedule and time.time() >= schedule['next'] and not self.gate.locked():
                try: self.start('inspect')
                except Exception:
                    self.warnings = ['定时巡检启动失败，请核对后台连接配置后重新启用']
                with self.lock:
                    if self.schedule == schedule: self.schedule['next'] = time.time() + schedule['minutes'] * 60

    def close(self):
        self.closed.set()
        self.schedule = None
        self.stop.set()
        if self.worker: self.worker.join(timeout=35)
