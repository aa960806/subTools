"""Small, bounded sub2api admin client. Never include response bodies in errors."""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

import httpx


class PoolError(RuntimeError):
    def __init__(self, message, *, category="failed", uncertain=False):
        super().__init__(message)
        self.category = category
        self.uncertain = uncertain


def validate_model_names(names):
    if not isinstance(names, tuple) or any(
        not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@+\-]*", name)
        for name in names
    ):
        raise ValueError("模型白名单请填写完整模型名称；不能包含空格、通配符或映射表达式")


def parse_model_whitelist(text: str) -> tuple[str, ...]:
    names = tuple(dict.fromkeys(name.strip() for name in re.split(r"[\r\n,，;；]+", text) if name.strip()))
    if not names:
        raise ValueError("请至少填写一个模型；解除限制请明确选择「清除模型限制」")
    validate_model_names(names)
    return names


def normalize_site(value: str) -> str:
    raw = str(value).strip().rstrip("/")
    if not raw or any(c.isspace() for c in raw) or "\\" in raw:
        raise ValueError("请输入完整的 sub2api 地址，例如 https://sub2.example.com")
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError:
        raise ValueError("站点地址或端口无效") from None
    if (parsed.scheme not in ("http", "https") or not parsed.hostname or
            parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment):
        raise ValueError("站点地址须为 HTTP(S)，不能包含用户名、密码、查询参数或片段")
    path = parsed.path.rstrip("/")
    for suffix in ("/api/v1/admin", "/api/v1"):
        if path.endswith(suffix):
            path = path[:-len(suffix)]
            break
    if any(part in (".", "..") or "%" in part for part in path.split("/")):
        raise ValueError("站点路径无效，请填写站点根地址或部署前缀")
    hostname = parsed.hostname.lower()
    authority = f"[{hostname}]" if ":" in hostname else hostname
    if port and not (parsed.scheme == "https" and port == 443 or parsed.scheme == "http" and port == 80):
        authority += f":{port}"
    return urlunsplit((parsed.scheme, authority, path, "", ""))


@dataclass(frozen=True)
class PoolSettings:
    site: str
    auth_kind: str
    credential: str = field(repr=False)
    group_ids: tuple[int, ...] = ()
    priority: int = 50
    concurrency: int = 3
    # None follows existing import behavior; () explicitly clears restrictions.
    model_whitelist: tuple[str, ...] | None = None
    scheduling_mode: str = "override"
    # None keeps the remote binding; 0 explicitly clears it. IDs belong to the target site.
    proxy_id: int | None = None
    load_factor: int | None = None

    def validate(self, *, require_groups=True):
        normalize_site(self.site)
        if self.auth_kind not in ("api_key", "bearer"):
            raise ValueError("请选择管理员 API Key 或管理员访问令牌")
        if not self.credential.strip() or any(c.isspace() for c in self.credential.strip()):
            raise ValueError("管理员凭据为空或包含空白字符")
        if any(isinstance(v, bool) or not isinstance(v, int) or v < 0 for v in (self.priority, self.concurrency)):
            raise ValueError("优先级和并发数必须是非负整数")
        if require_groups and not self.group_ids:
            raise ValueError("请至少选择一个目标分组")
        if any(isinstance(v, bool) or not isinstance(v, int) or v <= 0 for v in self.group_ids):
            raise ValueError("分组 ID 无效，请重新加载分组")
        if self.model_whitelist is not None:
            validate_model_names(self.model_whitelist)
        if self.scheduling_mode not in ("override", "preserve"):
            raise ValueError("请选择有效的调度配置策略")
        if self.proxy_id is not None and (type(self.proxy_id) is not int or self.proxy_id < 0):
            raise ValueError("后台代理 ID 无效，请重新加载代理")
        if self.load_factor is not None and (type(self.load_factor) is not int or not 0 <= self.load_factor <= 10000):
            raise ValueError("负载系数必须为 0–10000 的整数；留空保留，0 恢复默认")

    def connection_id(self):
        return hashlib.sha256((normalize_site(self.site) + "\0" + self.auth_kind + "\0" + self.credential).encode()).hexdigest()

    def destination_id(self):
        models = None if self.model_whitelist is None else tuple(sorted(set(self.model_whitelist)))
        return (normalize_site(self.site), tuple(sorted(self.group_ids)), self.priority, self.concurrency, models,
                self.scheduling_mode, self.proxy_id, self.load_factor)


class PoolClient:
    def __init__(self, settings: PoolSettings, stop: threading.Event | None = None, *, transport=None):
        settings.validate(require_groups=False)
        self.settings = settings
        self.stop = stop or threading.Event()
        self.base = normalize_site(settings.site) + "/api/v1/admin"
        header = "x-api-key" if settings.auth_kind == "api_key" else "Authorization"
        secret = settings.credential.strip()
        self.http = httpx.Client(
            headers={header: secret if settings.auth_kind == "api_key" else "Bearer " + secret,
                     "Accept": "application/json"},
            timeout=httpx.Timeout(20, connect=10), follow_redirects=False, transport=transport,
        )

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.http.close()

    def check_stop(self):
        if self.stop.is_set():
            raise PoolError("已停止", category="cancelled")

    def request(self, method, path, *, body=None, params=None, request_key=None):
        if not re.fullmatch(r"/(?:groups/all|proxies/all|accounts(?:/[1-9]\d*(?:/models/sync-upstream)?)?)", path):
            raise ValueError("不支持的管理接口路径")
        syncing = path.endswith("/models/sync-upstream")
        if syncing and method != "POST":
            raise ValueError("模型同步接口须使用 POST")
        writing = method in ("POST", "PUT") and not syncing
        if writing and not request_key:
            raise ValueError("写入必须提供幂等标识")
        ambiguous = False
        # A retry uses the identical body/key; never fall back to a different write endpoint.
        attempts = 1 if syncing else 2
        for attempt in range(attempts):
            if self.stop.is_set():
                raise PoolError("已停止，先前写入结果仍需核对" if writing and attempt else "已停止",
                                category="cancelled", uncertain=writing and attempt > 0)
            try:
                response = self.http.request(method, self.base + path, json=body, params=params,
                                             headers={"Idempotency-Key": request_key} if request_key else None,
                                             **({"timeout": httpx.Timeout(60, connect=10)} if syncing else {}))
            except httpx.TransportError:
                ambiguous = writing
                if attempt + 1 < attempts and not self.stop.wait(0.5):
                    continue
                if syncing:
                    raise PoolError("模型同步未获响应，保留原列表；可稍后重试，后台可能已更新模型能力缓存", category="network") from None
                raise PoolError("网络请求未获确认，请重试以核对结果", category="network", uncertain=writing) from None
            code = response.status_code
            if code >= 500:
                ambiguous = writing
                if attempt + 1 < attempts and not self.stop.wait(0.5):
                    continue
            if code == 401:
                raise PoolError("管理员凭据无效或已过期，请重新连接", category="auth", uncertain=ambiguous)
            if code == 403:
                raise PoolError("管理员权限不足或站点拒绝访问", category="auth", uncertain=ambiguous)
            if code == 429:
                raise PoolError("后台限流，已暂停本批次，请稍后重试", category="rate_limited", uncertain=ambiguous)
            if 300 <= code < 400:
                raise PoolError("管理接口发生重定向，请填写最终站点地址后重新连接", category="endpoint", uncertain=ambiguous)
            if code >= 400:
                # Even an HTTP error may arrive after a server commits a write.
                message = {404: "管理接口或账号不存在，请核对站点版本", 409: "后台检测到配置或幂等请求冲突，请核对后重试"}.get(code, "后台拒绝请求")
                if syncing:
                    message = {400: "来源账号无法同步模型，请在后台检查账号类型及凭据",
                               404: "同步接口或来源账号不存在，请核对后台版本并重新加载账号",
                               502: "后台读取上游模型失败，请检查来源账号凭据、后台代理和网络"}.get(code, "模型同步失败，保留原列表")
                    if code >= 500:
                        try:
                            gateway = response.json()
                        except ValueError:
                            gateway = None
                        if isinstance(gateway, dict) and gateway.get("cloudflare_error") is True:
                            message = "站点网关返回错误，未收到后台模型同步确认；保留原列表，请检查站点网关及源站日志"
                raise PoolError(f"{message}（HTTP {code}）", category="server" if code >= 500 else "failed", uncertain=ambiguous or writing and code == 409)
            try:
                data = response.json()
            except ValueError:
                raise PoolError("后台返回的内容不是 JSON，请核对 API 地址", category="protocol", uncertain=writing) from None
            if not isinstance(data, dict) or data.get("code") != 0 or "data" not in data:
                raise PoolError("后台响应格式异常或业务操作失败", category="protocol", uncertain=writing)
            return data["data"]

    def groups(self):
        data = self.request("GET", "/groups/all", params={"platform": "openai"})
        if not isinstance(data, list):
            raise PoolError("分组响应格式异常", category="protocol")
        groups = []
        for item in data:
            if not isinstance(item, dict) or not isinstance(item.get("id"), int) or isinstance(item["id"], bool) or item["id"] <= 0:
                raise PoolError("分组信息不完整", category="protocol")
            if item.get("platform") == "openai" and item.get("status") == "active" and item.get("subscription_type") != "composite":
                groups.append(item)
        return groups

    def validate_groups(self):
        self.settings.validate()
        available = {item["id"] for item in self.groups()}
        if not set(self.settings.group_ids) <= available:
            raise PoolError("所选分组已失效或不支持 OpenAI，请重新加载分组", category="groups")
        if self.settings.proxy_id:
            if self.settings.proxy_id not in {item["id"] for item in self.proxies()}:
                raise PoolError("所选后台代理已失效或停用，请重新加载代理", category="groups")

    def proxies(self):
        data = self.request("GET", "/proxies/all")
        if not isinstance(data, list):
            raise PoolError("后台代理列表响应格式异常", category="protocol")
        result = []
        for item in data:
            if not isinstance(item, dict) or type(item.get("id")) is not int or item["id"] <= 0:
                raise PoolError("后台代理信息不完整", category="protocol")
            if item.get("status") == "active":
                # The UI and journal do not need proxy passwords or URLs.
                result.append({"id": item["id"], "name": str(item.get("name") or "未命名代理").split("----", 1)[0]})
        return result

    def model_sources(self):
        # Return only labels and IDs to the UI, never retain account tokens there.
        sources = []
        for account in self.accounts():
            if account.get("parent_account_id"):
                continue
            name = account.get("name") or account["credentials"].get("email") or "未命名账号"
            sources.append({"id": account["id"], "name": str(name).replace("\n", " ").replace("\r", " ")})
        return sources

    def sync_models(self, account_id):
        if type(account_id) is not int or account_id <= 0:
            raise ValueError("请选择有效的同步来源账号")
        account = self.get_account(account_id)
        if account.get("platform") != "openai" or account.get("type") != "oauth" or account.get("parent_account_id"):
            raise PoolError("来源账号类型已变化，请重新加载 OpenAI OAuth 来源账号", category="models")
        data = self.request("POST", f"/accounts/{account_id}/models/sync-upstream")
        if (not isinstance(data, dict) or not isinstance(data.get("models"), list) or
                any(not isinstance(model, str) for model in data["models"])):
            raise PoolError("模型列表响应格式异常，保留原列表", category="protocol")
        models = tuple(dict.fromkeys(model.strip() for model in data["models"] if model.strip()))
        try:
            validate_model_names(models)
        except ValueError:
            raise PoolError("上游列表包含无法用于白名单的模型名称，保留原列表", category="protocol") from None
        notices = []
        known = {
            "upstream_model_metadata_partial": "部分模型能力信息不完整，模型名称仍可选择",
            "upstream_model_metadata_incomplete": "模型名称已返回，能力信息尚不完整",
        }
        warnings = data.get("warnings") or []
        if not isinstance(warnings, list):
            raise PoolError("模型同步提示格式异常，保留原列表", category="protocol")
        for warning in warnings:
            code = warning.get("code") if isinstance(warning, dict) else None
            notices.append(known.get(code if isinstance(code, str) else "", "后台返回额外同步提示，请在后台检查模型能力信息"))
        return models, tuple(dict.fromkeys(notices))

    def accounts(self, *, require_identity=True):
        records, seen = [], set()
        page = 1
        while True:
            data = self.request("GET", "/accounts", params={"platform": "openai", "type": "oauth", "page": page,
                                                            "page_size": 100, "sort_by": "created_at", "sort_order": "asc"})
            if (not isinstance(data, dict) or not isinstance(data.get("items"), list) or
                    type(data.get("total")) is not int or data["total"] < 0):
                raise PoolError("账号列表响应格式异常", category="protocol")
            for item in data["items"]:
                self._account_response(item)
                if (item.get("platform") != "openai" or item.get("type") != "oauth" or
                        require_identity and not isinstance(item.get("credentials"), dict)):
                    raise PoolError("账号列表缺少凭据身份或筛选结果异常，已停止以避免重复创建", category="protocol")
                if item["id"] in seen:
                    raise PoolError("账号分页重复或后台正在变化，请重新连接后重试", category="protocol")
                seen.add(item["id"])
                records.append(item)
            if len(records) >= data["total"]:
                return records
            if not data["items"] or page >= 10000:
                raise PoolError("账号分页不完整，已停止以避免重复创建", category="protocol")
            page += 1

    @staticmethod
    def _account_response(data, *, writing=False):
        if (not isinstance(data, dict) or isinstance(data.get("id"), bool) or
                not isinstance(data.get("id"), int) or data["id"] <= 0):
            raise PoolError("后台未返回有效账号 ID，操作结果待核对", category="protocol", uncertain=writing)
        return data

    def get_account(self, account_id):
        return self._account_response(self.request("GET", f"/accounts/{account_id}"))

    def write(self, method, path, body, key):
        return self._account_response(self.request(method, path, body=body, request_key=key), writing=True)


def write_key(site, method, path, body):
    serialized = json.dumps([normalize_site(site), method, path, body], sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return "reauth-pool-" + hashlib.sha256(serialized.encode()).hexdigest()
