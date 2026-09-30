"""Encrypted history summaries and bounded, lazy loading of full task records.

Archiving only hides completed tasks from the default list. It never removes
credentials, recovery checkpoints, SMS orders, or pending backend writes.
"""
from collections import OrderedDict
from collections.abc import MutableMapping
import re
import time


class TaskHistory(MutableMapping):
    def __init__(self, store, *, cache_size=20, archive_days=30):
        self.store, self.cache_size, self.archive_days = store, cache_size, archive_days
        self.index, self.cache, self.warnings = {}, OrderedDict(), []
        for file in (store.root / 'tasks').glob('*.json'):
            try:
                key = self.validate(file.stem)
                if file.is_symlink():
                    raise ValueError('linked task')
                try:
                    summary = store.read(f'history/{key}.json')
                except Exception:
                    # The summary is a disposable index; the task is authoritative.
                    summary = None
                stat = file.stat()
                if not summary or summary.get('revision') != [stat.st_mtime_ns, stat.st_size]:
                    task = store.read(f'tasks/{key}.json')
                    if task['id'] != key:
                        raise ValueError('task identity mismatch')
                    if summary:
                        self.index[key] = summary
                    summary = self.summarize(task)
                    summary['revision'] = [stat.st_mtime_ns, stat.st_size]
                    store.write(f'history/{key}.json', summary)
                if summary['status'] == 'running':
                    summary = {**summary, 'status': 'interrupted', 'message': '服务器上次中断；请核对结果后手动继续'}
                self.index[key] = summary
            except Exception:
                self.warnings.append(f'无法读取任务记录 {file.name}；原文件已保留，请核对数据密钥或备份')
        self.archive_completed()

    @staticmethod
    def validate(key):
        if not isinstance(key, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', key):
            raise ValueError('任务 ID 无效')
        return key

    def summarize(self, task):
        summary = {k: task.get(k) for k in ('id', 'kind', 'status', 'created', 'finished', 'message')}
        summary['archived'] = self.index.get(task['id'], {}).get('archived', False)
        summary['restored_at'] = self.index.get(task['id'], {}).get('restored_at', 0)
        summary['archive_safe'] = task['status'] == 'finished' and (
            task['kind'] == 'inspect' or bool(task.get('rows')) and
            all(r['state'] in ('success', 'created', 'updated') for r in task['rows']))
        if any(i.get('pending') for i in task.get('items', [])):
            summary['archive_safe'] = False
        return summary

    def _cache(self, key, task):
        self.cache[key] = task
        self.cache.move_to_end(key)
        while sum(v['status'] != 'running' for v in self.cache.values()) > self.cache_size:
            removable = next((k for k, v in self.cache.items() if v['status'] != 'running'), None)
            if removable is None:
                break
            self.cache.pop(removable)

    def __getitem__(self, key):
        self.validate(key)
        if key not in self.index:
            raise KeyError(key)
        if key not in self.cache:
            task = self.store.read(f'tasks/{key}.json')
            if task is None:
                raise ValueError('任务记录不存在，请检查数据目录')
            if task['status'] == 'running':
                task.update(status='interrupted', message='服务器上次中断；请检查结果后选择继续，不会自动重登或买号')
                for row in task.get('rows', []):
                    row['stage_active'] = False
                    for step in row.get('steps', []):
                        if step.get('status') == 'active':
                            step['status'] = 'attention'
            self._cache(key, task)
        self.cache.move_to_end(key)
        return self.cache[key]

    def __setitem__(self, key, task):
        self.validate(key)
        revision = self.index.get(key, {}).get('revision')
        self.index[key] = {**self.summarize(task), 'revision': revision}
        self._cache(key, task)

    def __delitem__(self, key):
        raise ValueError('任务只能归档，不能删除恢复记录')

    def __iter__(self):
        return iter(self.index)

    def __len__(self):
        return len(self.index)

    def __contains__(self, key):
        return key in self.index

    def save(self, task):
        key = self.validate(task['id'])
        self.store.write(f'tasks/{key}.json', task)
        self[key] = task
        stat = (self.store.root / f'tasks/{key}.json').stat()
        self.index[key]['revision'] = [stat.st_mtime_ns, stat.st_size]
        self.store.write(f'history/{key}.json', self.index[key])

    def archive(self, key, archived=True):
        summary = self.index.get(key)
        if summary is None:
            raise ValueError('任务不存在')
        if archived and not summary.get('archive_safe'):
            raise ValueError('仅可归档全部成功的完成任务；待处理和待核对记录须保留在当前列表')
        summary = {**summary, 'archived': archived}
        if not archived:
            summary['restored_at'] = time.time()
        self.store.write(f'history/{key}.json', summary)
        self.index[key] = summary

    def archive_completed(self):
        if not self.archive_days:
            return
        cutoff = time.time() - self.archive_days * 86400
        for key, summary in list(self.index.items()):
            if (summary.get('archive_safe') and not summary.get('archived')
                    and max(summary.get('finished') or summary['created'], summary.get('restored_at', 0)) < cutoff):
                self.archive(key)

    def page(self, offset=0, limit=25, archived=False):
        rows = sorted((s for s in self.index.values() if bool(s.get('archived')) == archived),
                      key=lambda s: s['created'], reverse=True)
        public = [{k: s.get(k) for k in ('id', 'kind', 'status', 'created', 'message', 'archived', 'archive_safe')}
                  for s in rows[offset:offset + limit]]
        return {'rows': public, 'total': len(rows), 'offset': offset, 'limit': limit}
