"""Authenticated Portal bridge to the Controller's durable clone action store."""
from copy import deepcopy
from datetime import datetime, timezone
import re
from threading import Lock
import time
from uuid import UUID

from .auto_response import CLONE, PROJECT
from .n91_business.service import BusinessError
from .openstack_inventory import InventoryError
from .quarantine_recovery import ACTIVE
from .ssh_openstack import SSHTransport
from .workload_quarantine import QuarantineError


class RemoteAutomaticResponse:
    def __init__(self, path, transport=None):
        self.transport = transport or SSHTransport(path, 'quarantine')
        self.cached, self.cached_at, self.lock = None, 0, Lock()

    def request(self, op, **fields):
        try:
            data, _ = self.transport.rpc({'op': op, 'server_id': CLONE, **fields})
            return data
        except InventoryError as error:
            if error.code in {'RESTORE_OPERATION_CHANGED', 'RESTORE_PORT_CHANGED', 'QUARANTINE_BUSY'}:
                raise BusinessError(409, error.code) from None
            raise BusinessError(503, 'AUTO_CONTROLLER_UNAVAILABLE') from None

    def status(self, *, force=False):
        with self.lock:
            if not force and self.cached is not None and time.monotonic() - self.cached_at < 3:
                return deepcopy(self.cached)
            data = self.request('auto_status')
            try:
                if (data['schema'] != 'n91-automatic-response-1' or data['target_id'] != CLONE
                        or data['policy']['project_id'] != PROJECT or data['policy']['restore_mode'] != 'MANUAL'
                        or not re.fullmatch(r'[a-f0-9]{64}', data['policy_sha256'])
                        or type(data['armed']) is not bool or not isinstance(data['decisions'], list)
                        or len(data['decisions']) > 50 or not isinstance(data['quarantine'], dict)):
                    raise ValueError()
                for row in data['decisions']:
                    if row.get('operation_id'):
                        UUID(row['operation_id'])
                observed = datetime.fromisoformat(data['read_at'].replace('Z', '+00:00'))
                if observed.tzinfo is None or abs((datetime.now(timezone.utc) - observed).total_seconds()) > 30:
                    raise ValueError()
            except (KeyError, TypeError, ValueError):
                raise BusinessError(503, 'AUTO_CONTROLLER_RESPONSE_INVALID') from None
            self.cached, self.cached_at = deepcopy(data), time.monotonic()
            return data

    def operation_status(self, *, force=False):
        data = self.status(force=force)
        state = {**data['quarantine'], 'automatic_response': True, 'restore_mode': 'MANUAL',
                 'policy_version': data['policy']['version'], 'policy_sha256': data['policy_sha256']}
        decision = next((row for row in data['decisions'] if state.get('operation_id')
                         and row.get('operation_id') == state['operation_id']), None)
        if decision:
            state.update(incident_id=decision['incident_id'], stream_id=decision['stream_id'])
        return state

    def journal(self):
        data = self.request('auto_journal')
        if not isinstance(data.get('operations'), list) or any(
                row.get('server_id') != CLONE or row.get('project_id') != PROJECT for row in data['operations']):
            raise BusinessError(503, 'AUTO_CONTROLLER_RESPONSE_INVALID')
        return data

    def restore(self, actor, request_id, operation_id):
        if 'Executor' not in actor.roles:
            raise QuarantineError(403, 'QUARANTINE_EXECUTOR_REQUIRED')
        data = self.request('auto_restore', actor_id=actor.user_id, request_id=request_id, operation_id=operation_id)
        self.cached = None
        if data.get('operation_id') != operation_id or data.get('state') not in {'RESTORED', 'RESTORE_FAILED'}:
            raise BusinessError(503, 'AUTO_RESTORE_NOT_VERIFIED')
        return data


class CombinedQuarantineRecovery:
    def __init__(self, local, remote):
        self.local, self.remote = local, remote
        self.cloud = local.cloud

    def configured(self):
        return self.local.configured()

    def restore_due(self):
        return self.local.restore_due()

    def status(self, server_id):
        local = self.local.status(server_id)
        if server_id != CLONE:
            return local
        remote = self.remote.operation_status()
        if remote.get('state') in ACTIVE:
            return remote
        if local.get('state') in ACTIVE:
            return local
        if (remote.get('quarantined_at') or '') > (local.get('quarantined_at') or ''):
            return remote
        return local

    def quarantine(self, server_id, actor, request_id):
        if server_id == CLONE and self.remote.operation_status(force=True).get('state') in ACTIVE:
            raise QuarantineError(409, 'QUARANTINE_ALREADY_ACTIVE')
        return self.local.quarantine(server_id, actor, request_id)

    def restore(self, server_id, actor, request_id, operation_id):
        if server_id == CLONE and self.remote.operation_status(force=True).get('operation_id') == operation_id:
            return self.remote.restore(actor, request_id, operation_id)
        return self.local.restore(server_id, actor, request_id, operation_id)
