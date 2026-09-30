"""Encrypted, atomic pool queue checkpoints. Loading never sends a request."""
from __future__ import annotations

import json
import re
import time
import uuid
from dataclasses import asdict
from pathlib import Path

from account_inputs import AccountInput
from local_secrets import protect_secret, unprotect_secret, is_protected
from pool_client import PoolError, PoolSettings, write_key
from reauth_formats import _atomic_write_json, _object_without_duplicates, _reject_constant


def _tuple(value):
    return tuple(_tuple(item) for item in value) if isinstance(value, list) else value


class PoolJournal:
    def __init__(self, path, *, protect=protect_secret, unprotect=unprotect_secret):
        self.path = Path(path)
        self.protect, self.unprotect = protect, unprotect

    @classmethod
    def create(cls, directory):
        folder = Path(directory) / ("pool-" + time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8])
        return cls(folder / "queue.dpapi.json")

    def save(self, settings, jobs):
        config = asdict(settings)
        config.pop("credential")
        payload = {"version": 1, "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                   "settings": config, "jobs": [asdict(job) for job in jobs]}
        try:
            encrypted = self.protect(json.dumps(payload, ensure_ascii=False, allow_nan=False))
            if not is_protected(encrypted):
                raise ValueError("encryption failed")
            _atomic_write_json(self.path, {"version": 1, "encrypted": encrypted}, overwrite=True)
        except Exception:
            raise PoolError("推池任务加密保存失败，已停止后续写入；请检查本机加密和恢复目录权限", category="storage") from None

    def load(self):
        from pool_flow import PendingWrite, PushJob
        try:
            if self.path.stat().st_size > 64 * 1024 * 1024:
                raise ValueError
            outer = json.loads(self.path.read_text(encoding="utf-8"))
            if outer.get("version") != 1 or not is_protected(outer.get("encrypted")):
                raise ValueError
            raw = self.unprotect(outer["encrypted"])
            data = json.loads(raw, parse_constant=_reject_constant, object_pairs_hook=_object_without_duplicates)
            if data.get("version") != 1 or not isinstance(data.get("jobs"), list):
                raise ValueError
            config = data["settings"]
            if "credential" in config:
                raise ValueError
            config["group_ids"] = tuple(config["group_ids"])
            if config.get("model_whitelist") is not None:
                config["model_whitelist"] = tuple(config["model_whitelist"])
            settings = PoolSettings(**config, credential="restored-placeholder")
            settings.validate()
            jobs, ids = [], set()
            for row in data["jobs"]:
                uid = row["uid"]
                if not isinstance(uid, str) or not re.fullmatch(r"[a-f0-9]{32}", uid) or uid in ids:
                    raise ValueError
                ids.add(uid)
                login = AccountInput(**row["login"]) if row.get("login") else None
                pending = PendingWrite(**row["pending"]) if row.get("pending") else None
                if pending:
                    pending.destination = _tuple(pending.destination)
                    if (pending.destination != settings.destination_id() or
                        not (pending.method == "POST" and pending.path == "/accounts" or
                             pending.method == "PUT" and re.fullmatch(r"/accounts/[1-9]\d*", pending.path)) or
                        pending.key != write_key(settings.site, pending.method, pending.path, pending.body)):
                        raise ValueError
                    pending.needs_reconcile = True
                job = PushJob(**{**row, "login": login, "pending": pending,
                                 "completed_destination": _tuple(row.get("completed_destination"))})
                if pending:
                    job.state, job.message = "uncertain", "恢复的写入需先核对后台，再继续推送"
                elif job.refresh_state == "refreshing":
                    job.refresh_state = "refresh_unknown"
                    job.state, job.message = "refresh_unknown", "前次刷新结果未确认，请选择是否重新登录"
                elif job.state == "pushing":
                    job.state, job.message = "not_processed", "上次中断，可继续处理"
                if not job.account and not job.login and not job.pending:
                    raise ValueError
                jobs.append(job)
            if not jobs:
                raise ValueError
            return config, jobs
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            raise PoolError("无法恢复此任务：文件损坏、格式不支持或加密密钥不匹配；旧 DPAPI 文件需在原 Windows 用户下迁移", category="storage") from None
