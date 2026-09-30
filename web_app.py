"""Authenticated web interface for SubTools. Run one Uvicorn worker."""
from __future__ import annotations
import asyncio
import hashlib
import hmac
import json
import os
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from server_storage import configure_storage, Store
from server_engine import Engine, integer, export_bytes
from reauth_conversion import parse_conversion_text
from reauth_formats import build_export_payload, build_cpa_payload, conversion_warnings, account_conversion_status
from phone_smsbower import COUNTRY_CATALOG, COUNTRY_PINYIN, country_label

ROOT = Path(__file__).resolve().parent


def password_hash(password, salt):
    return hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()


def create_app(data_dir=None, password=None):
    sessions, failures = {}, {}
    @asynccontextmanager
    async def lifespan(app):
        from oauth_refresh import _refresh_lease
        root = configure_storage(data_dir or os.environ.get('SUBTOOLS_DATA_DIR', ROOT / 'data'))
        import openai_reauth
        openai_reauth.DEBUG_DIR = root / 'debug'
        with _refresh_lease(root / 'server.lock'):
            store = Store(root)
            auth = store.read('admin.json')
            if auth is None:
                initial = password or os.environ.get('SUBTOOLS_ADMIN_PASSWORD')
                if not initial and os.environ.get('SUBTOOLS_ADMIN_PASSWORD_FILE'):
                    initial = Path(os.environ['SUBTOOLS_ADMIN_PASSWORD_FILE']).read_text().strip()
                if not initial:
                    raise RuntimeError('首次启动需设置 SUBTOOLS_ADMIN_PASSWORD（至少 12 位）')
                if len(initial) < 12: raise RuntimeError('管理员密码至少 12 位')
                salt = secrets.token_hex(16)
                auth = {'salt':salt, 'hash':password_hash(initial,salt)}
                store.write('admin.json',auth)
            app.state.auth = auth
            app.state.engine = Engine(root)
            try: yield
            finally:
                app.state.engine.close()
                sessions.clear()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware('http')
    async def access_control(request, call_next):
        path = request.url.path
        if request.method not in ('GET','HEAD','OPTIONS'):
            origin = request.headers.get('origin')
            expected = os.environ.get('SUBTOOLS_PUBLIC_ORIGIN') or str(request.base_url).rstrip('/')
            if (origin and origin.rstrip('/') != expected.rstrip('/')) or request.headers.get('sec-fetch-site') == 'cross-site':
                return JSONResponse({'error':'请求来源不匹配'},status_code=403)
        if path.startswith('/api/') and path != '/api/login':
            token = request.cookies.get('subtools_session','')
            session = sessions.get(token)
            if not session or session['expires'] < time.time():
                sessions.pop(token,None)
                return JSONResponse({'error':'请先登录'},status_code=401)
            if request.method != 'GET' and not hmac.compare_digest(request.headers.get('x-csrf-token',''), session['csrf']):
                return JSONResponse({'error':'页面会话已失效，请重新登录'},status_code=403)
            request.state.session = session
        length = request.headers.get('content-length')
        if length and (not length.isdecimal() or int(length) > 20*1024*1024):
            return JSONResponse({'error':'请求不能超过 20 MB'},status_code=413)
        # Enforce the cap even for chunked requests before JSON parsing.
        if request.method in ('POST','PUT','PATCH'):
            size = 0
            body = []
            async for chunk in request.stream():
                size += len(chunk)
                if size > 20*1024*1024: return JSONResponse({'error':'请求不能超过 20 MB'},status_code=413)
                body.append(chunk)
            request._body = b''.join(body)
        response = await call_next(request)
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'"
        return response

    @app.exception_handler(ValueError)
    async def invalid(request, exc):
        return JSONResponse({'error':str(exc)},status_code=400)

    @app.exception_handler(Exception)
    async def failure(request, exc):
        from openai_reauth import redact_diagnostic
        # Never reflect server response bodies, tokens or Playwright call logs.
        message = redact_diagnostic(str(exc)) if hasattr(exc,'category') else f'操作未完成（{type(exc).__name__}）'
        return JSONResponse({'error':message},status_code=400)

    async def payload(request):
        try: value = await request.json()
        except Exception: raise ValueError('请求需要有效 JSON') from None
        if not isinstance(value,dict): raise ValueError('请求必须是 JSON 对象')
        return value

    @app.get('/healthz')
    def health(): return {'ok':True}

    @app.post('/api/login')
    async def login(request:Request):
        data = await payload(request)
        key = request.client.host if request.client else 'local'
        attempts = [x for x in failures.get(key,[]) if x > time.time()-300]
        if len(attempts)>=8: return JSONResponse({'error':'登录尝试过多，请 5 分钟后重试'},status_code=429)
        candidate = data.get('password','')
        if not isinstance(candidate,str) or len(candidate)>1024: raise ValueError('密码格式无效')
        auth = app.state.auth
        digest = await asyncio.to_thread(password_hash,candidate,auth['salt'])
        if not hmac.compare_digest(digest,auth['hash']):
            failures[key]=attempts+[time.time()]
            return JSONResponse({'error':'密码不正确'},status_code=401)
        failures.pop(key,None)
        for old in list(sessions):
            if sessions[old]['expires']<time.time(): sessions.pop(old)
        if len(sessions)>=32: sessions.pop(next(iter(sessions)))
        token,csrf=secrets.token_urlsafe(32),secrets.token_urlsafe(24)
        sessions[token]={'csrf':csrf,'expires':time.time()+12*3600}
        response=JSONResponse({'csrf':csrf})
        response.set_cookie('subtools_session',token,httponly=True,samesite='strict',max_age=12*3600,
                            secure=request.url.scheme=='https' or os.environ.get('SUBTOOLS_PUBLIC_ORIGIN','').startswith('https://'))
        return response

    @app.get('/api/session')
    def session(request:Request): return {'csrf':request.state.session['csrf']}

    @app.post('/api/logout')
    def logout(request:Request):
        sessions.pop(request.cookies.get('subtools_session'),None)
        response=JSONResponse({'ok':True});response.delete_cookie('subtools_session');return response

    @app.get('/api/config')
    def configs(): return {k:app.state.engine.config(k,public=True) for k in ('auth','phone','pool')}

    @app.put('/api/config/{kind}')
    async def configure(kind:str,request:Request):
        if kind not in ('auth','phone','pool'): raise ValueError('配置类型无效')
        return app.state.engine.save_config(kind,await payload(request))

    @app.get('/api/status')
    def status():
        e=app.state.engine
        return {'active':e.active,'schedule':e.schedule,'inspection':e.inspection,'platform':os.name,'warnings':e.warnings}

    @app.post('/api/preview/{kind}')
    async def preview(kind:str,request:Request):
        if kind not in ('auth','phone','pool'): raise ValueError('类型无效')
        data=await payload(request)
        return app.state.engine.preview(kind,data.get('text',''))

    @app.post('/api/tasks')
    async def start(request:Request):
        data=await payload(request)
        return app.state.engine.start(data.get('kind'),data.get('text',''))

    @app.get('/api/tasks')
    def tasks(): return app.state.engine.list_tasks()

    @app.get('/api/tasks/{task_id}')
    def task(task_id:str): return app.state.engine.public(task_id)

    @app.post('/api/tasks/{task_id}/stop')
    def stop(task_id:str):
        e=app.state.engine
        if e.active==task_id: e.stop.set()
        return {'ok':True}

    @app.post('/api/tasks/{task_id}/retry')
    async def retry(task_id:str,request:Request):
        data=await payload(request)
        e=app.state.engine
        return e.start(e.get(task_id)['kind'],previous=task_id,selected=data.get('selected'),relogin=data.get('relogin') is True)

    @app.post('/api/tasks/{task_id}/defer')
    async def defer(task_id:str,request:Request):
        data=await payload(request)
        return app.state.engine.defer(task_id,data.get('selected',[]))

    @app.post('/api/tasks/{task_id}/transfer')
    async def transfer(task_id:str,request:Request):
        data=await payload(request)
        return {'text':app.state.engine.transfer(task_id,data.get('target'),data.get('selected'))}

    @app.get('/api/tasks/{task_id}/export')
    def download(task_id:str,target:str='sub2'):
        e=app.state.engine
        with e.lock:
            t=e.get(task_id)
            if t['kind']=='inspect':
                if not t.get('report'): raise ValueError('巡检尚未完成')
                content=json.dumps(t['report'],ensure_ascii=False,indent=2).encode();name='inspection.json';media='application/json'
            else:
                accounts=[a for uid,a in t['accounts'].items() if any(r['uid']==uid and r['state'] in ('success','created','updated') for r in t['rows'])]
                if not accounts: raise ValueError('尚无成功结果可导出')
                content,name,media,_=export_bytes(accounts,target)
        return Response(content,media_type=media,headers={'Content-Disposition':f'attachment; filename="{name}"'})

    @app.get('/api/tasks/{task_id}/export-warnings')
    def export_warnings(task_id:str,target:str='sub2'):
        if target not in ('sub2','cpa'): raise ValueError('目标格式无效')
        e=app.state.engine
        with e.lock:
            t=e.get(task_id)
            successful={r['uid'] for r in t['rows'] if r['state'] in ('success','created','updated')}
            accounts=[a for uid,a in t['accounts'].items() if uid in successful]
            if not accounts: raise ValueError('尚无成功结果可导出')
            return {'warnings':conversion_warnings(accounts,target)}

    @app.post('/api/convert')
    async def convert(request:Request):
        data=await payload(request);kind,accounts=parse_conversion_text(data.get('text',''))
        target=data.get('target','sub2')
        if target not in ('sub2','cpa'): raise ValueError('目标格式无效')
        return {'kind':kind,'count':len(accounts),'warnings':conversion_warnings(accounts,target),
                'rows':[account_conversion_status(a) for a in accounts],
                'preview':build_export_payload(accounts) if target=='sub2' else [build_cpa_payload(a) for a in accounts]}

    @app.post('/api/convert/export')
    async def convert_export(request:Request):
        data=await payload(request);_,accounts=parse_conversion_text(data.get('text',''))
        content,name,media,_=export_bytes(accounts,data.get('target','sub2'))
        return Response(content,media_type=media,headers={'Content-Disposition':f'attachment; filename="{name}"'})

    @app.post('/api/pool/{action}')
    async def pool_action(action:str,request:Request):
        if action not in ('connect','sources','models'): raise ValueError('操作无效')
        data=await payload(request)
        return await asyncio.to_thread(app.state.engine.remote,data.get('source_id') if action=='models' else action)

    @app.get('/api/countries')
    def countries():
        return [{'code':c,'label':country_label(c),'pinyin':COUNTRY_PINYIN[c],'en':en} for c,zh,en in sorted(COUNTRY_CATALOG,key=lambda r:COUNTRY_PINYIN[r[0]])]

    @app.post('/api/sms/{action}')
    async def sms(action:str): return await asyncio.to_thread(app.state.engine.sms_read,action)

    @app.post('/api/inspection/schedule')
    async def schedule(request:Request):
        data=await payload(request)
        minutes=integer(data.get('minutes',15),'巡检间隔',1,1440)
        app.state.engine.schedule={'minutes':minutes,'next':time.time()} if data.get('enabled') is True else None
        return {'schedule':app.state.engine.schedule}

    @app.get('/api/browser/frame')
    def frame():
        e=app.state.engine
        if not e.active or not e.bridge.enabled or not e.bridge.frame:
            return Response(status_code=204)
        return Response(e.bridge.frame,media_type='image/jpeg')

    @app.post('/api/browser/input')
    async def browser_input(request:Request):
        data=await payload(request)
        e=app.state.engine
        if not e.active or not e.bridge.enabled: raise ValueError('当前任务没有可操作的浏览器')
        action=data.get('action');command={'action':action}
        if action=='click':
            command.update(x=integer(data.get('x'),'横坐标',0,1279),y=integer(data.get('y'),'纵坐标',0,899))
        elif action=='text':
            if not isinstance(data.get('text'),str) or len(data['text'])>4096: raise ValueError('输入文本过长')
            command['text']=data['text']
        elif action=='key':
            if data.get('key') not in ('Enter','Tab','Backspace','Escape','Control+A','ArrowUp','ArrowDown','ArrowLeft','ArrowRight','Delete'): raise ValueError('按键无效')
            command['key']=data['key']
        elif action=='scroll': command['delta']=600 if data.get('delta',0)>0 else -600
        else: raise ValueError('浏览器操作无效')
        try:e.bridge.commands.put_nowait(command)
        except Exception:raise ValueError('操作过快，请稍候') from None
        return {'ok':True}

    @app.get('/api/legacy')
    def legacy():
        root=app.state.engine.root/'recovery';rows=[]
        if not root.exists():return rows
        for file in root.glob('**/*.json'):
            if file.is_symlink() or not file.resolve().is_relative_to(root.resolve()):continue
            if file.name in ('accounts.json','queue.dpapi.json') or file.name.startswith('phone-results-'):
                rows.append({'path':file.relative_to(root).as_posix(),'modified':file.stat().st_mtime,
                             'kind':'pool' if file.name=='queue.dpapi.json' else 'phone-report' if file.name.startswith('phone-results-') else 'auth'})
        return sorted(rows,key=lambda x:x['modified'],reverse=True)[:200]

    @app.post('/api/legacy/open')
    async def open_legacy(request:Request):
        data=await payload(request);e=app.state.engine;root=(e.root/'recovery').resolve();file=(root/data.get('path','')).resolve()
        if not file.is_relative_to(root) or file.is_symlink() or not file.is_file() or file.stat().st_size>64*1024*1024: raise ValueError('记录路径无效')
        if file.name=='queue.dpapi.json':
            from pool_recovery import PoolJournal
            config,jobs=PoolJournal(file).load()
            # Restoring is read-only; no auto login or backend write.
            import uuid
            from dataclasses import asdict
            tid=uuid.uuid4().hex
            task={'id':tid,'kind':'pool','created':time.time(),'status':'interrupted','message':'已恢复，请核对站点和分组后继续',
                  'items':[asdict(j) for j in jobs], 'rows':[{'uid':j.uid,'email':j.email,'state':j.state,'message':j.message,'account_id':j.account_id,'refresh_state':j.refresh_state} for j in jobs],
                  'accounts':{j.uid:j.account for j in jobs if j.account},'logs':[],'report':None}
            # Keep the exact encrypted journal, including pending writes.
            import shutil
            dest=e.root/'tasks'/tid/'queue.dpapi.json';dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(file,dest)
            with e.lock:e._save(task);e.tasks[tid]=task
            return {'task':e.public(tid),'settings':config,'credential_site':e.config('pool')['site']}
        if file.name=='accounts.json' or file.name.startswith('phone-results-'):
            return {'text':file.read_text(encoding='utf-8'),'kind':'convert' if file.name=='accounts.json' else 'report'}
        raise ValueError('不支持打开此记录')

    app.mount('/static',StaticFiles(directory=ROOT/'web'),name='static')
    @app.get('/')
    def index():return FileResponse(ROOT/'web'/'index.html')
    return app

app=create_app()
