from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.auto_response import (AutomaticResponse, CLONE, IP, POLICY, POLICY_SHA256, STREAM,
                               canon, validate_feed, verify_candidate)


def candidate(now=None):
    now = now or datetime.now(timezone.utc)
    times = [int((now - timedelta(seconds=5)).timestamp() * 1000) + i * 100 for i in range(3)]
    proof = [{'event_id': f'TEST-event-{i}', 'request_id': f'TEST-request-{i}', 'seq': 101 + i,
              'ms': times[i], 'p15': 80, 'risk_status': 'OK', 'identity_complete': True,
              'canonical_hash_verified': True, 'payload_sha256': 'a' * 64,
              'policy_version': POLICY['firewall_policy_version'], 'injection_rules': ['INJ-001']}
             for i in range(3)]
    return {'incident_id': 'INC-' + 'a' * 20, 'stream_id': STREAM, 'source_ip': IP,
            'correlation_rule': 'CORR-002', 'status': 'REVIEW_REQUIRED', 'confidence': 'CANDIDATE_CORRELATED',
            'membership_basis': 'DIRECT_PERSISTED', 'detector_sha256': POLICY['detector_sha256'],
            'detector_version': POLICY['detector_version'], 'snapshot_id': 'b' * 64,
            'created_utc': (now - timedelta(seconds=10)).isoformat(), 'evidence_count_recorded': 3,
            'captured_member_count': 3, 'peak_p15': 80, 'last_event_ms': max(times),
            'evidence': proof, 'feed_reason_codes': []}


def feed(candidates):
    result = {'schema': 'n91-clone-auto-feed-1', 'stream_id': STREAM, 'reader_status': 'RUNNING',
              'generated_at_utc': datetime.now(timezone.utc).isoformat(), 'action_executed': 'NONE',
              'p16h_ack_operation': 'NONE', 'openstack_mutations': 0, 'candidates': candidates,
              'reader_tail': 200, 'worker_cursor': 200}
    result['payload_sha256'] = hashlib.sha256(canon(result)).hexdigest()
    return canon(result)


@pytest.mark.parametrize('field,value', [
    ('source_ip', '10.0.0.30'), ('stream_id', 'TEST-other-stream'), ('correlation_rule', 'CORR-001'),
    ('confidence', 'REVIEW_REQUIRED'), ('status', 'OPERATIONAL_REVIEW'),
    ('membership_basis', 'RECONSTRUCTED_WINDOW'), ('detector_sha256', 'f' * 64),
    ('feed_reason_codes', ['CANONICAL_RECORD_NOT_RETAINED']), ('peak_p15', 59), ('captured_member_count', 4),
])
def test_automatic_policy_rejects_unverified_scope_or_evidence(field, value):
    now = datetime.now(timezone.utc)
    sample = candidate(now)
    sample[field] = value
    with pytest.raises(ValueError):
        verify_candidate(sample, (now - timedelta(seconds=20)).isoformat(), 100, now)


@pytest.mark.parametrize('change', ['duplicate_request', 'duplicate_sequence', 'old_sequence', 'hash_unverified',
                                   'window', 'one_event', 'risk_error', 'wrong_policy', 'historical'])
def test_automatic_policy_rejects_replay_non_distinct_and_failed_risk(change):
    now = datetime.now(timezone.utc)
    c = candidate(now)
    if change == 'duplicate_request': c['evidence'][1]['request_id'] = c['evidence'][0]['request_id']
    if change == 'duplicate_sequence': c['evidence'][1]['seq'] = c['evidence'][0]['seq']
    if change == 'old_sequence': c['evidence'][0]['seq'] = 99
    if change == 'hash_unverified': c['evidence'][0]['canonical_hash_verified'] = False
    if change == 'window': c['evidence'][0]['ms'] -= 60000
    if change == 'one_event': c['evidence'] = c['evidence'][:1]
    if change == 'risk_error': c['evidence'][0]['risk_status'] = 'ERROR'
    if change == 'wrong_policy': c['evidence'][0]['policy_version'] = 'TEST-other-policy'
    if change == 'historical': c['created_utc'] = (now - timedelta(days=1)).isoformat()
    with pytest.raises(ValueError):
        verify_candidate(c, (now - timedelta(seconds=20)).isoformat(), 100, now)


def test_feed_rejects_tampering_and_duplicate_json_keys():
    valid = feed([candidate()])
    assert len(validate_feed(valid)['candidates']) == 1
    invalid = json.loads(valid)
    invalid['reader_tail'] += 1
    with pytest.raises(ValueError, match='HASH'):
        validate_feed(canon(invalid))
    with pytest.raises(ValueError):
        validate_feed(b'{"schema":1,"schema":2}')


class FakeRecovery:
    def __init__(self):
        self.calls = []
        self.state = 'IDLE'
    def status(self, target):
        assert target == CLONE
        return {'allowed': True, 'state': self.state}
    def quarantine(self, target, actor, request_id):
        assert target == CLONE and actor.user_id == 'SYSTEM_AUTO_P17'
        self.calls.append(request_id)
        self.state = 'QUARANTINED'
        return {'state': self.state, 'operation_id': str(uuid4())}


def make_worker(tmp_path, candidates, recovery=None):
    config = {'database_path': str(tmp_path / 'TEST-auto.sqlite3'), 'reader_credential_path': 'TEST-reader',
              'quarantine_credential_path': 'TEST-member', 'auth_url': 'http://TEST-identity/v3',
              'compute_url': 'http://TEST-nova/v2.1', 'network_url': 'http://TEST-neutron'}
    recovery = recovery or FakeRecovery()
    worker = AutomaticResponse(config, recovery=recovery, feed_reader=lambda: feed(candidates))
    with worker.service.connection(write=True) as db:
        db.execute('INSERT OR IGNORE INTO automatic_meta(singleton,armed_at,watermark,policy_sha256) VALUES(1,?,?,?)',
                   ((datetime.now(timezone.utc) - timedelta(seconds=20)).isoformat(), 100, POLICY_SHA256))
    worker.preflight = lambda: {'source_system': 'TEST-Neutron', 'server_id': CLONE, 'snapshot_sha256': 'c' * 64}
    worker.observe_source = lambda: None
    worker.verify_source_history = lambda candidate, mapping: mapping
    worker.recovery_ready = lambda: {'source': 'TEST-watchdog', 'watchdog_timer_active': True}
    return worker, recovery


def test_authorization_commits_before_actuation_and_deduplicates_after_restart(tmp_path):
    c = candidate()
    worker, recovery = make_worker(tmp_path, [c])
    original = recovery.quarantine
    def apply(target, actor, request_id):
        with worker.service.connection() as db:
            row = db.execute('SELECT * FROM automatic_decisions').fetchone()
            assert row['state'] == 'AUTHORIZED'
            evidence = json.loads(row['evidence_json'])
            assert evidence['decision'] == 'AUTHORIZED'
            assert set(evidence['checks'].values()) == {'PASS'}
        return original(target, actor, request_id)
    recovery.quarantine = apply
    worker.tick()
    worker.tick()
    assert len(recovery.calls) == 1
    restarted, second_recovery = make_worker(tmp_path, [c])
    restarted.tick()
    assert second_recovery.calls == []
    assert restarted.status()['decisions'][0]['state'] == 'QUARANTINED'


@pytest.mark.parametrize('failure', ['rule', 'mapping', 'watchdog'])
def test_failed_conditions_are_recorded_without_cloud_action(tmp_path, failure):
    c = candidate()
    worker, recovery = make_worker(tmp_path, [c])
    if failure == 'rule': c['correlation_rule'] = 'CORR-001'
    if failure == 'mapping':
        worker.preflight = lambda: (_ for _ in ()).throw(ValueError('AUTO_CLONE_MAPPING_OR_BASELINE_CHANGED'))
    if failure == 'watchdog':
        worker.recovery_ready = lambda: (_ for _ in ()).throw(ValueError('AUTO_WATCHDOG_NOT_ACTIVE'))
    worker.tick()
    assert recovery.calls == []
    decision = worker.status()['decisions'][0]
    assert decision['state'] == 'REVIEW_REQUIRED'
    assert decision['evidence']['decision'] == 'REVIEW_REQUIRED'
    assert decision['evidence']['reason_codes']
    assert 'FAIL' in decision['evidence']['checks'].values()


def test_temporary_missing_evidence_can_be_reevaluated_without_losing_rejection_history(tmp_path):
    c = candidate()
    c['feed_reason_codes'] = ['CANONICAL_RECORD_NOT_RETAINED']
    worker, recovery = make_worker(tmp_path, [c])
    worker.tick()
    worker.tick()
    assert len(worker.status()['decisions']) == 1 and recovery.calls == []
    c['feed_reason_codes'] = []
    worker.tick()
    worker.tick()
    rows = worker.status()['decisions']
    assert len(rows) == 2 and len(recovery.calls) == 1
    assert {row['evidence']['decision'] for row in rows} == {'AUTHORIZED', 'REVIEW_REQUIRED'}


@pytest.mark.parametrize('problem', [None, 'missing_before', 'old_before', 'changed_revision', 'changed_ip'])
def test_source_ownership_requires_stable_observations_bracketing_actual_event_times(tmp_path, problem):
    from app.auto_response import BASELINE, PORT, PROJECT, NETWORK
    c = candidate()
    worker, _ = make_worker(tmp_path, [c])
    current = {'source_system': 'TEST-Neutron', 'server_id': CLONE, 'project_id': PROJECT,
               'port_id': PORT, 'network_id': NETWORK, 'source_ip': IP, 'device_owner': 'compute:nova',
               'revision_number': 81, 'security_group_ids': sorted(BASELINE)}
    def observation(milliseconds, **changes):
        mapping = {**current, 'observed_at': datetime.fromtimestamp(milliseconds/1000, timezone.utc).isoformat(), **changes}
        mapping['snapshot_sha256'] = hashlib.sha256(canon(mapping)).hexdigest()
        worker.record_mapping(mapping)
        return mapping
    start = c['evidence'][0]['ms']
    end = c['last_event_ms']
    if problem != 'missing_before':
        observation(start - (40000 if problem == 'old_before' else 1000),
                    **({'revision_number': 82} if problem == 'changed_revision' else
                       {'source_ip': 'TEST-other-ip'} if problem == 'changed_ip' else {}))
    after = observation(end+1000)
    if problem:
        with pytest.raises(ValueError, match='OWNERSHIP'):
            AutomaticResponse.verify_source_history(worker, c, after)
    else:
        result = AutomaticResponse.verify_source_history(worker, c, after)
        assert result['ownership_window']['basis'] == 'STABLE_NEUTRON_REVISION_BRACKET'
        assert result['ownership_window']['before']['revision_number'] == result['ownership_window']['after']['revision_number'] == 81
