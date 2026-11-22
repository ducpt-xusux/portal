from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.auto_remote import CombinedQuarantineRecovery, RemoteAutomaticResponse
from app.auto_response import CLONE, POLICY, POLICY_SHA256
from app.n91_business.service import BusinessError
from app.workload_quarantine import QuarantineError


def test_clone_restore_routes_to_authoritative_controller_operation():
    operation = str(uuid4())
    actor = SimpleNamespace(user_id=str(uuid4()), roles=('Executor',))
    calls = []
    local = SimpleNamespace(cloud=None, restore=lambda *args: calls.append('local'),
                            status=lambda _: {'state': 'RESTORED', 'quarantined_at': '2026-01-01T00:00:00Z'})
    remote = SimpleNamespace(operation_status=lambda **_: {'operation_id': operation, 'state': 'QUARANTINED'},
                             restore=lambda *args: calls.append(args) or {'state': 'RESTORED'})
    combined = CombinedQuarantineRecovery(local, remote)
    assert combined.status(CLONE)['state'] == 'QUARANTINED'
    with pytest.raises(QuarantineError, match='ALREADY_ACTIVE'):
        combined.quarantine(CLONE, actor, str(uuid4()))
    combined.restore(CLONE, actor, 'TEST-request', operation)
    assert calls == [(actor, 'TEST-request', operation)]


def test_automatic_restore_rejects_non_executor_before_rpc():
    remote = RemoteAutomaticResponse(None, transport=object())
    remote.request = lambda *args, **kw: pytest.fail('Unauthorized role reached RPC')
    with pytest.raises(QuarantineError, match='EXECUTOR_REQUIRED'):
        remote.restore(SimpleNamespace(roles=('Analyst',)), 'TEST-request', str(uuid4()))


def test_remote_rejects_wrong_target_and_expired_observation():
    data = {'schema': 'n91-automatic-response-1', 'target_id': 'OTHER-vm',
            'policy': POLICY, 'policy_sha256': POLICY_SHA256, 'armed': True,
            'decisions': [], 'quarantine': {}, 'read_at': datetime.now(timezone.utc).isoformat()}
    remote = RemoteAutomaticResponse(None, transport=SimpleNamespace(rpc=lambda request: (data, None)))
    with pytest.raises(BusinessError, match='RESPONSE_INVALID'):
        remote.status()
    data['target_id'] = CLONE
    data['read_at'] = '2020-01-01T00:00:00Z'
    with pytest.raises(BusinessError, match='RESPONSE_INVALID'):
        remote.status()
