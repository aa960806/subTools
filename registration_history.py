"""Encrypted, cross-task registration guard. Used only by registration jobs."""
import hashlib

from registration_flow import registration_needs_review


class RegistrationHistory:
    def __init__(self, store):
        self.store = store
        self.revisions = {}

    @staticmethod
    def _path(email):
        key = hashlib.sha256(email.strip().casefold().encode()).hexdigest()
        return f'registration/emails/{key}.json'

    def lookup(self, email):
        value = self.store.read(self._path(email))
        if value is not None and (not isinstance(value, dict) or value.get('email') != email.strip().casefold()
                                  or not value.get('task_id') or not isinstance(value.get('checkpoint'), dict)):
            raise ValueError('注册历史记录无法核对；请检查数据目录，未开始注册')
        return value

    def record_task(self, task):
        if task['kind'] != 'register':
            return
        for row in task['rows']:
            if row.get('source_task') or row['state'] == 'registration_blocked':
                continue
            item = task['items'][int(row['uid'])]
            cp = item.get('checkpoint') or {}
            account = task.get('accounts', {}).get(row['uid']) or {}
            if account.get('platform') == 'fixture':
                continue
            complete = row['state'] == 'success' and account.get('platform') == 'openai'
            if not complete and not registration_needs_review(cp) and row['state'] not in {'existing_account', 'partial_registered'}:
                continue
            previous = self.lookup(item['email'])
            confirmed = bool(cp.get('create_confirmed') or complete)
            if previous and previous['task_id'] != task['id']:
                # During migration, prefer a confirmed account to an earlier
                # uncertain attempt. A duplicate task must not erase its owner.
                if previous.get('complete') or not (complete or confirmed and not previous['checkpoint'].get('create_confirmed')):
                    continue
            effects = dict(cp.get('side_effects') or {})
            if previous and previous['task_id'] == task['id']:
                effects = {**previous['checkpoint'].get('side_effects', {}), **effects}
                confirmed |= bool(previous['checkpoint'].get('create_confirmed'))
                complete |= bool(previous.get('complete'))
            value = {'email': item['email'].strip().casefold(), 'task_id': task['id'], 'uid': row['uid'],
                     'state': 'success' if complete else row['state'], 'complete': complete,
                     'checkpoint': {'stage': 'finalize' if complete else cp.get('stage', 'auth_flow'),
                                    'state': 'success' if complete else cp.get('state', row['state']),
                                    'create_confirmed': confirmed, 'side_effects': effects}}
            if value != previous:
                self.store.write(self._path(item['email']), value)

    def reconcile(self, tasks):
        # Import older tasks, including archived ones, and recover the guard if
        # a previous process stopped between saving its task and saving this index.
        for task_id, summary in list(tasks.index.items()):
            if summary.get('kind') != 'register':
                continue
            revision = summary.get('revision')
            if task_id in self.revisions and self.revisions[task_id] == revision:
                continue
            self.record_task(tasks[task_id])
            self.revisions[task_id] = revision
