"""Read-only inventory inspection. No refresh, login, model probe or remote writes."""
from __future__ import annotations

import re
import time
from collections import defaultdict
from datetime import datetime, timezone

from pool_client import PoolClient, normalize_site
from reauth_formats import parse_datetime_to_unix


def inspection_delta(previous, current):
    """Compare issues only within one site/group scope; removal is not recovery."""
    scope = lambda report: (report.get("site"), tuple(sorted(report.get("group_ids", ()))))
    if previous is None or scope(previous) != scope(current):
        return {"baseline": True, "new": [], "resolved": [], "persistent": [], "removed_ids": []}
    old = {row["id"]: set(row["issues"]) for row in previous["accounts"]}
    new = {row["id"]: set(row["issues"]) for row in current["accounts"]}
    changes = {"baseline": False, "new": [], "resolved": [], "persistent": [],
               "removed_ids": sorted(old.keys() - new.keys())}
    for account_id, issues in new.items():
        before = old.get(account_id, set())
        for key, values in (("new", issues - before), ("resolved", before - issues), ("persistent", issues & before)):
            changes[key].extend({"id": account_id, "issue": issue} for issue in sorted(values))
    return changes


class ReadOnlyPoolClient(PoolClient):
    def request(self, method, path, **kwargs):
        if method != "GET" or path not in ("/accounts", "/proxies/all"):
            raise ValueError("巡检仅允许读取账号及代理列表")
        return super().request(method, path, **kwargs)


def inspect_pool(settings, stop, *, group_ids=(), client_factory=ReadOnlyPoolClient, now=None):
    settings.validate(require_groups=False)
    now = time.time() if now is None else now
    with client_factory(settings, stop) as client:
        accounts = client.accounts(require_identity=False)
        proxies = {item["id"] for item in client.proxies()}
    rows = []
    for item in accounts:
        if stop.is_set():
            from pool_client import PoolError
            raise PoolError("巡检已停止，保留上次结果", category="cancelled")
        if item.get("parent_account_id"):
            continue
        groups = item.get("group_ids")
        groups = [value for value in groups if type(value) is int and value > 0] if isinstance(groups, list) else []
        if group_ids and not set(groups).intersection(group_ids):
            continue
        creds = item.get("credentials") or {}
        creds = creds if isinstance(creds, dict) else {}
        email = str(creds.get("email") or item.get("name") or "").split("----", 1)[0].strip()
        if not re.fullmatch(r"[^\s@:/]+@[^\s@:/]+\.[^\s@:/]+", email) or len(email) > 254:
            email = "未提供邮箱"
        issues = []
        status = item.get("status")
        if status == "error":
            issues.append("后台标记异常")
        elif status == "disabled":
            issues.append("已禁用")
        elif status != "active":
            issues.append("状态未知")
        if item.get("schedulable") is False:
            issues.append("调度已关闭")
        for key, label in (("rate_limit_reset_at", "限流冷却"), ("overload_until", "过载冷却"),
                           ("temp_unschedulable_until", "临时不可调度")):
            until = parse_datetime_to_unix(item.get(key))
            if until is not None and until > now:
                issues.append(label)
        expiry = parse_datetime_to_unix(creds.get("expires_at"))
        if expiry is None:
            issues.append("凭据到期时间未知")
        elif expiry <= now:
            issues.append("access token 已过期")
        elif expiry <= now + 86400:
            issues.append("access token 24 小时内到期")
        account_expiry = parse_datetime_to_unix(item.get("expires_at"))
        if account_expiry is not None and account_expiry <= now:
            issues.append("后台账号已到期")
        token_status = item.get("credentials_status") or {}
        token_status = token_status if isinstance(token_status, dict) else {}
        has_refresh = token_status.get("has_refresh_token")
        if has_refresh is None and isinstance(creds.get("refresh_token"), str) and creds["refresh_token"]:
            has_refresh = True
        if has_refresh is False:
            issues.append("缺少刷新令牌")
        elif has_refresh is not True:
            issues.append("刷新令牌存在性未知")
        proxy_id = item.get("proxy_id")
        proxy_id = proxy_id if type(proxy_id) is int and proxy_id > 0 else None
        if proxy_id and proxy_id not in proxies:
            issues.append("代理失效或停用")
        if not groups:
            issues.append("未绑定分组")
        space, user = creds.get("chatgpt_account_id"), creds.get("chatgpt_user_id")
        user = user if isinstance(user, str) else ""
        identity = (space, user or email.casefold()) if isinstance(space, str) and space and (user or email != "未提供邮箱") else None
        if identity is None:
            issues.append("身份字段不完整")
        rows.append({"id": item["id"], "email": email, "status": status if status in ("active", "error", "disabled") else "unknown",
                     "issues": issues, "group_ids": groups, "proxy_id": proxy_id,
                     "load_factor": item.get("load_factor") if type(item.get("load_factor")) is int else None,
                     "expires_at": expiry, "has_refresh_token": has_refresh if type(has_refresh) is bool else None,
                     "_identity": identity, "_user": user})
    by_user, by_email = defaultdict(list), defaultdict(list)
    for row in rows:
        if row["_identity"]:
            space = row["_identity"][0]
            if row["_user"]:
                by_user[(space, row["_user"])].append(row)
            if row["email"] != "未提供邮箱":
                by_email[(space, row["email"].casefold())].append(row)
    for related in by_user.values():
        if len(related) > 1:
            for row in related:
                row["issues"].append("同身份重复账号")
    for related in by_email.values():
        users = {row["_user"] for row in related if row["_user"]}
        if len(related) > 1:
            label = "同邮箱同空间用户 ID 冲突" if len(users) > 1 else "同身份重复账号"
            for row in related:
                if label not in row["issues"]:
                    row["issues"].append(label)
    for row in rows:
        del row["_identity"], row["_user"]
    return {"site": normalize_site(settings.site), "checked_at": datetime.fromtimestamp(now, timezone.utc).isoformat(),
            "read_only": True, "group_ids": list(group_ids), "total": len(rows),
            "attention": sum(bool(row["issues"]) for row in rows), "accounts": rows,
            "note": "仅依据后台已存状态，未测试上游可用性；没有刷新、重新登录或修改账号。"}
