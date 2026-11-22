"""Controller-owned, durable, clone-only automatic response and bounded RPC.

P17 stays a detector. Owner-approved policy authorizes this service identity.
The existing quarantine engine persists original SGs before any mutation and
verifies revisions/readback. Successful containment has no automatic expiry.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time
from types import SimpleNamespace
from uuid import UUID, uuid4

from .config import Settings
from .n91_business import BusinessConfig, BusinessService
from .openstack_inventory import InventoryError
from .quarantine_recovery import ACTIVE, QuarantineRecovery
from .source_json import unique_object
from .store import Store
from .workload_journal import business_journal
from .workload_quarantine import QuarantineError, WorkloadQuarantine

CLONE = 'fa34f3e8-50ff-467e-a7db-a5cd92613682'
PORT = '31465b2c-d248-4665-ab0c-f704976c8405'
PROJECT = 'd726c27d15cd46c58f83393af47c1e1a'
NETWORK = 'f2674ac5-f47e-4882-9aa9-12c05cb7aca7'
IP = '10.0.0.204'
SG = '6e72bfd2-0b73-47e8-9fe9-7f3b83337892'
BASELINE = {'d0592433-fbe6-4cee-ac27-dc49f45b2440', 'fa86a973-82cf-4ec7-b034-e7d8352bda58'}
STREAM = '5622bcdb-95ad-4a74-8cae-bc6394443a4c'
POLICY = {'version': 'n91-clone-auto-corr002-v2', 'rule': 'CORR-002', 'minimum_events': 3,
          'minimum_peak_score': 60, 'window_ms': 60000, 'max_incident_age_seconds': 90,
          'max_feed_age_seconds': 30, 'restore_mode': 'MANUAL', 'target_id': CLONE,
          'target_ip': IP, 'project_id': PROJECT, 'port_id': PORT,
          'firewall_policy_version': '1.4.1-G03-RC5',
          'detector_sha256': '25e91b0cc565399abe236374d78759a7f89dcdd6e99975afc8a82b565706005e',
          'detector_version': 'p17-incident-g03-dual-v3-20261104',
          'threshold_reference_sha256': '587bfda84d9a00f6d98e3c4bc9c9dd629aac743970029d7accf4f16494087702',
          'threshold_reference': 'existing p17_controller.py verify_incident',
          'source_observation_max_gap_seconds': 30, 'stable_neutron_revision_bracket_required': True,
          'authority': 'OWNER_APPROVED_DEDICATED_CLONE_AUTOMATION'}
INJECTION = {'INJ-001', 'INJ-002', 'INJ-006', 'INJ-007', 'INJ-008'}
SYSTEM = SimpleNamespace(user_id='SYSTEM_AUTO_P17', roles=('Executor',))
MAX_BYTES = 1024 * 1024


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


POLICY_SHA256 = hashlib.sha256(canon(POLICY)).hexdigest()
EXECUTOR_CODE_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def stamp(value):
    date = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if date.tzinfo is None:
        raise ValueError('TIMEZONE_REQUIRED')
    return date.astimezone(timezone.utc)


def now_text():
    return datetime.now(timezone.utc).isoformat()


def age_ok(value, now, maximum):
    return -1 <= (now - stamp(value)).total_seconds() <= maximum


def validate_feed(raw, now=None):
    if len(raw) > MAX_BYTES:
        raise ValueError('AUTO_FEED_LIMIT')
    feed = json.loads(raw, object_pairs_hook=unique_object)
    digest = feed.pop('payload_sha256')
    if digest != hashlib.sha256(canon(feed)).hexdigest():
        raise ValueError('AUTO_FEED_HASH_INVALID')
    if (feed['schema'] != 'n91-clone-auto-feed-1' or feed['stream_id'] != STREAM
            or feed['reader_status'] != 'RUNNING' or feed['action_executed'] != 'NONE'
            or feed['p16h_ack_operation'] != 'NONE' or feed['openstack_mutations'] != 0
            or not age_ok(feed['generated_at_utc'], now or datetime.now(timezone.utc), POLICY['max_feed_age_seconds'])
            or not isinstance(feed['candidates'], list) or len(feed['candidates']) > 30
            or type(feed['reader_tail']) is not int or type(feed['worker_cursor']) is not int
            or feed['worker_cursor'] > feed['reader_tail']):
        raise ValueError('AUTO_FEED_CONTRACT_INVALID')
    return feed


def verify_candidate(candidate, armed_at, watermark, now=None):
    now = now or datetime.now(timezone.utc)
    c = candidate
    if c.get('correlation_rule') != 'CORR-002':
        raise ValueError('AUTO_RULE_NOT_APPROVED')
    if c.get('feed_reason_codes'):
        raise ValueError('AUTO_CANONICAL_EVIDENCE_NOT_VERIFIED')
    if c.get('membership_basis') != 'DIRECT_PERSISTED':
        raise ValueError('AUTO_DIRECT_MEMBERSHIP_REQUIRED')
    if (not re.fullmatch(r'INC-[a-f0-9]{20}', str(c.get('incident_id', '')))
            or c.get('stream_id') != STREAM or c.get('source_ip') != IP
            or c.get('correlation_rule') != 'CORR-002' or c.get('status') != 'REVIEW_REQUIRED'
            or c.get('confidence') != 'CANDIDATE_CORRELATED'
            or c.get('membership_basis') != 'DIRECT_PERSISTED'
            or c.get('detector_sha256') != POLICY['detector_sha256']
            or c.get('detector_version') != POLICY['detector_version']
            or not re.fullmatch(r'[a-f0-9]{64}', str(c.get('snapshot_id', '')))
            or not age_ok(c['created_utc'], now, POLICY['max_incident_age_seconds'])
            or stamp(c['created_utc']) <= stamp(armed_at)):
        raise ValueError('AUTO_INCIDENT_NOT_QUALIFIED')
    evidence = c['evidence']
    if (not isinstance(evidence, list) or not 3 <= len(evidence) <= 100
            or len(evidence) != c.get('captured_member_count')
            or type(c['peak_p15']) is not int or type(c['evidence_count_recorded']) is not int
            or c['evidence_count_recorded'] < len(evidence)):
        raise ValueError('AUTO_EVIDENCE_COUNT_INVALID')
    eids, rids, sequences = set(), set(), set()
    times, scores = [], []
    for event in evidence:
        if (not all(isinstance(event.get(k), str) and event[k] for k in ('event_id', 'request_id'))
                or event['event_id'] in eids or event['request_id'] in rids or event['seq'] in sequences
                or type(event['seq']) is not int or event['seq'] <= watermark
                or type(event['ms']) is not int or event['ms'] <= stamp(armed_at).timestamp() * 1000
                or type(event['p15']) is not int or not 0 <= event['p15'] <= 100
                or event.get('identity_complete') is not True or event.get('risk_status') != 'OK'
                or event.get('canonical_hash_verified') is not True
                or not re.fullmatch(r'[a-f0-9]{64}', str(event.get('payload_sha256', '')))
                or event.get('policy_version') != POLICY['firewall_policy_version']
                or not isinstance(event.get('injection_rules'), list)
                or not set(event['injection_rules']) & INJECTION):
            raise ValueError('AUTO_EVIDENCE_NOT_VERIFIED')
        eids.add(event['event_id']); rids.add(event['request_id']); sequences.add(event['seq'])
        times.append(event['ms']); scores.append(event['p15'])
    latest = datetime.fromtimestamp(max(times) / 1000, timezone.utc)
    if (max(times) - min(times) >= POLICY['window_ms'] or max(times) != c['last_event_ms']
            or max(scores) != c['peak_p15'] or max(scores) < POLICY['minimum_peak_score']
            or not -1 <= (now - latest).total_seconds() <= POLICY['max_incident_age_seconds']):
        raise ValueError('AUTO_WINDOW_OR_THRESHOLD_INVALID')
    return c


class CloneQuarantine(WorkloadQuarantine):
    """Recheck the exact approved port/network/IP on every apply/restore readback."""
    def _verify_port(self, port, server_id):
        super()._verify_port(port, server_id)
        if (server_id != CLONE or port.get('id') != PORT or port.get('network_id') != NETWORK
                or IP not in [row.get('ip_address') for row in port.get('fixed_ips', [])]
                or port.get('device_owner') != 'compute:nova'):
            raise QuarantineError(409, 'AUTO_CLONE_PORT_IDENTITY_CHANGED')

    def _ports(self, network, server_id):
        ports = super()._ports(network, server_id)
        if set(ports) != {PORT}:
            raise QuarantineError(409, 'AUTO_CLONE_PORT_SET_CHANGED')
        return ports


class AutomaticResponse:
    def __init__(self, config, *, recovery=None, feed_reader=None):
        self.config = config
        self.service = BusinessService(BusinessConfig(database_path=Path(config['database_path'])))
        self.service.initialize()
        self.service.initialize_quarantine()
        settings = Settings(Path(config['database_path'] + '.unused-audit'), Path(config['database_path'] + '.unused-cache'),
            openstack_enabled=True, openstack_credential_path=Path(config['reader_credential_path']),
            openstack_quarantine_credential_path=Path(config['quarantine_credential_path']),
            openstack_auth_url=config['auth_url'], openstack_compute_url=config['compute_url'],
            openstack_network_url=config['network_url'], openstack_project_id=PROJECT,
            openstack_quarantine_sg_id=SG, quarantine_allowed_server_ids=(CLONE,), quarantine_ttl_seconds=0)
        history = Store(Path(config['database_path'] + '.network.sqlite3'))
        history.initialize()
        self.recovery = recovery or QuarantineRecovery(CloneQuarantine(settings), self.service, history)
        self.feed_reader = feed_reader or self.read_feed
        with self.service.connection(write=True) as db:
            db.execute('CREATE TABLE IF NOT EXISTS automatic_meta (singleton INTEGER PRIMARY KEY CHECK(singleton=1), '
                       'armed_at TEXT NOT NULL, watermark INTEGER NOT NULL, policy_sha256 TEXT NOT NULL,'
                       'last_attempt TEXT,last_success TEXT,last_error TEXT)')
            db.execute('CREATE TABLE IF NOT EXISTS automatic_decisions (incident_id TEXT PRIMARY KEY,stream_id TEXT NOT NULL,'
                       'request_id TEXT NOT NULL UNIQUE,decided_at TEXT NOT NULL,policy_sha256 TEXT NOT NULL,'
                       'evidence_json TEXT NOT NULL,state TEXT NOT NULL,operation_id TEXT,error_code TEXT)')
            db.execute('CREATE TABLE IF NOT EXISTS automatic_watchdog (singleton INTEGER PRIMARY KEY CHECK(singleton=1), '
                       'last_success TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS automatic_evaluations (request_id TEXT PRIMARY KEY,incident_id TEXT NOT NULL,'
                       'stream_id TEXT NOT NULL,decided_at TEXT NOT NULL,policy_sha256 TEXT NOT NULL,evidence_json TEXT NOT NULL,'
                       'state TEXT NOT NULL,operation_id TEXT,error_code TEXT,fingerprint TEXT NOT NULL UNIQUE)')
            db.execute('CREATE TABLE IF NOT EXISTS automatic_source_observations (observed_ms INTEGER PRIMARY KEY,'
                       'snapshot_sha256 TEXT NOT NULL UNIQUE,mapping_json TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS automatic_policy_history (changed_at TEXT PRIMARY KEY,'
                       'previous_policy_sha256 TEXT,new_policy_sha256 TEXT NOT NULL,watermark INTEGER NOT NULL)')

    def read_feed(self):
        result = subprocess.run(['ssh', '-T', '-i', self.config['feed_ssh_key'], '-o', 'BatchMode=yes',
            '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=5',
            'ubuntu@192.168.253.20', 'N91_AUTO_FEED_V1'], capture_output=True, timeout=15)
        if result.returncode or len(result.stdout) > MAX_BYTES:
            raise ValueError('AUTO_FEED_UNAVAILABLE')
        return result.stdout

    def preflight(self, *, baseline=True):
        cloud = self.recovery.cloud
        cfg = cloud.settings
        cloud.identity.configured()
        server = cloud.identity.get(cfg.openstack_compute_url.rstrip('/') + '/servers/' + CLONE)['server']
        ports = cloud._ports(cfg.openstack_network_url.rstrip('/') + '/v2.0', CLONE)
        unique = cloud.identity.get(cfg.openstack_network_url.rstrip('/') + '/v2.0/ports?fixed_ips=ip_address%3D' + IP)['ports']
        port = ports.get(PORT, {})
        if (server.get('id') != CLONE or server.get('name') != 'p17-lab-clone' or server.get('status') != 'ACTIVE'
                or server.get('project_id', server.get('tenant_id')) != PROJECT or set(ports) != {PORT}
                or len(unique) != 1 or unique[0].get('id') != PORT or port.get('network_id') != NETWORK
                or IP not in [row.get('ip_address') for row in port.get('fixed_ips', [])]
                or baseline and set(port.get('security_groups', [])) != BASELINE):
            raise ValueError('AUTO_CLONE_MAPPING_OR_BASELINE_CHANGED')
        mapping = {'source_system': 'NOVA_NEUTRON_LIVE_READ', 'observed_at': now_text(), 'source_ip': IP,
                   'server_id': CLONE, 'server_name': server['name'], 'nova_status': server['status'],
                   'port_id': PORT, 'project_id': PROJECT, 'network_id': NETWORK,
                   'device_owner': port['device_owner'], 'port_security_enabled': port['port_security_enabled'],
                   'revision_number': port['revision_number'], 'security_group_ids': sorted(port['security_groups']),
                   'fixed_ips': port['fixed_ips'], 'unique_ip_match_count': len(unique)}
        mapping['snapshot_sha256'] = hashlib.sha256(canon(mapping)).hexdigest()
        return mapping

    def record_mapping(self, mapping):
        observed_ms = int(stamp(mapping['observed_at']).timestamp() * 1000)
        with self.service.connection(write=True) as db:
            db.execute('INSERT OR IGNORE INTO automatic_source_observations VALUES(?,?,?)',
                       (observed_ms, mapping['snapshot_sha256'], json.dumps(mapping)))
            db.execute('DELETE FROM automatic_source_observations WHERE observed_ms<?', (observed_ms - 86400000,))

    def observe_source(self):
        self.record_mapping(self.preflight(baseline=False))

    def verify_source_history(self, candidate, current):
        start = min(event['ms'] for event in candidate['evidence'])
        end = max(event['ms'] for event in candidate['evidence'])
        self.record_mapping(current)
        with self.service.connection() as db:
            before = db.execute('SELECT * FROM automatic_source_observations WHERE observed_ms<=? '
                                'ORDER BY observed_ms DESC LIMIT 1', (start,)).fetchone()
            after = db.execute('SELECT * FROM automatic_source_observations WHERE observed_ms>=? '
                               'ORDER BY observed_ms ASC LIMIT 1', (end,)).fetchone()
            between = db.execute('SELECT * FROM automatic_source_observations WHERE observed_ms>? AND observed_ms<? '
                                 'ORDER BY observed_ms', (start, end)).fetchall()
        gap = POLICY['source_observation_max_gap_seconds'] * 1000
        if not before or not after or start - before['observed_ms'] > gap or after['observed_ms'] - end > gap:
            raise ValueError('AUTO_SOURCE_OWNERSHIP_WINDOW_UNPROVEN')
        observations = [before, *between, after]
        stable = ('server_id', 'project_id', 'port_id', 'network_id', 'source_ip', 'device_owner', 'revision_number')
        previous = None
        for row in observations:
            mapping = json.loads(row['mapping_json'])
            if (any(mapping.get(key) != current.get(key) for key in stable)
                    or set(mapping['security_group_ids']) != BASELINE
                    or previous is not None and row['observed_ms'] - previous > gap):
                raise ValueError('AUTO_SOURCE_OWNERSHIP_CHANGED_DURING_EVIDENCE')
            previous = row['observed_ms']
        current['ownership_window'] = {'basis': 'STABLE_NEUTRON_REVISION_BRACKET',
            'evidence_from_ms': start, 'evidence_to_ms': end, 'observations_checked': len(observations),
            'before': json.loads(before['mapping_json']), 'after': json.loads(after['mapping_json'])}
        return current

    def recovery_ready(self):
        with self.service.connection() as db:
            row = db.execute('SELECT last_success FROM automatic_watchdog WHERE singleton=1').fetchone()
        if not row or not age_ok(row['last_success'], datetime.now(timezone.utc), 20):
            raise ValueError('AUTO_WATCHDOG_HEARTBEAT_MISSING_OR_STALE')
        result = subprocess.run(['systemctl', 'is-active', 'n91-auto-watchdog.timer'], capture_output=True, timeout=3)
        if result.returncode or result.stdout.strip() != b'active':
            raise ValueError('AUTO_WATCHDOG_NOT_ACTIVE')
        return {'watchdog_last_success': row['last_success'], 'watchdog_timer_active': True,
                'durable_original_sg_journal_available': True, 'revision_guard_required': True, 'restore_mode': 'MANUAL'}

    def watchdog(self):
        self.recovery.restore_due()
        with self.service.connection(write=True) as db:
            db.execute('INSERT INTO automatic_watchdog VALUES(1,?) ON CONFLICT(singleton) DO UPDATE SET last_success=excluded.last_success',
                       (now_text(),))

    def arm(self, *, rearm=False):
        feed = validate_feed(self.feed_reader())
        self.record_mapping(self.preflight())
        self.recovery_ready()
        with self.service.connection(write=True) as db:
            previous = db.execute('SELECT * FROM automatic_meta WHERE singleton=1').fetchone()
            if previous and not rearm:
                raise ValueError('AUTO_ALREADY_ARMED')
            if db.execute("SELECT 1 FROM workload_quarantine WHERE state IN ('APPLYING','QUARANTINED','RESTORING','RESTORE_FAILED')").fetchone():
                raise ValueError('AUTO_CANNOT_REARM_ACTIVE_QUARANTINE')
            changed = now_text()
            db.execute('INSERT INTO automatic_meta(singleton,armed_at,watermark,policy_sha256) VALUES(1,?,?,?) '
                       'ON CONFLICT(singleton) DO UPDATE SET armed_at=excluded.armed_at,watermark=excluded.watermark,'
                       'policy_sha256=excluded.policy_sha256,last_attempt=NULL,last_success=NULL,last_error=NULL',
                       (changed, feed['reader_tail'], POLICY_SHA256))
            db.execute('INSERT INTO automatic_policy_history VALUES(?,?,?,?)',
                       (changed, previous['policy_sha256'] if previous else None, POLICY_SHA256, feed['reader_tail']))

    def tick(self):
        with self.service.connection() as db:
            meta = db.execute('SELECT * FROM automatic_meta WHERE singleton=1').fetchone()
        if not meta or meta['policy_sha256'] != POLICY_SHA256:
            raise ValueError('AUTO_NOT_ARMED_OR_POLICY_CHANGED')
        attempted = now_text()
        try:
            try:
                self.observe_source()
            except (ValueError, InventoryError, QuarantineError):
                pass  # A missing/changed observation cannot authorize; the per-Incident verifier records the refusal.
            feed = validate_feed(self.feed_reader())
            if feed['reader_tail'] < meta['watermark']:
                raise ValueError('AUTO_STREAM_SEQUENCE_REGRESSED')
            for candidate in feed['candidates']:
                # Historical rows are observations, never queued for reaction on enable/restart.
                try:
                    if (not re.fullmatch(r'INC-[a-f0-9]{20}', str(candidate.get('incident_id', '')))
                            or candidate.get('stream_id') != STREAM or candidate.get('source_ip') != IP
                            or stamp(candidate['created_utc']) <= stamp(meta['armed_at'])
                            or not age_ok(candidate['created_utc'], datetime.now(timezone.utc), POLICY['max_incident_age_seconds'])
                            or candidate['last_event_ms'] <= stamp(meta['armed_at']).timestamp() * 1000):
                        continue
                except (ValueError, KeyError, TypeError, OverflowError):
                    continue
                iid = candidate['incident_id']
                request_id = str(uuid4())
                with self.service.connection(write=True) as db:
                    if db.execute('SELECT 1 FROM automatic_decisions WHERE incident_id=?', (iid,)).fetchone():
                        continue
                evidence = {'incident': candidate, 'policy_version': POLICY['version'], 'policy_sha256': POLICY_SHA256,
                            'executor_code_sha256': EXECUTOR_CODE_SHA256,
                            'authority': POLICY['authority'], 'decision': 'REVIEW_REQUIRED', 'reason_codes': [],
                            'source_verification': None, 'recovery_readiness': None,
                            'checks': {key: 'NOT_EVALUATED' for key in ('incident_policy','evidence_integrity',
                                'source_verification','target_allowlist','policy_authorization','recovery_ready')}}
                state, operation, code = 'REVIEW_REQUIRED', None, None
                try:
                    verify_candidate(candidate, meta['armed_at'], meta['watermark'])
                    evidence['checks'].update(incident_policy='PASS', evidence_integrity='PASS')
                    if self.recovery.status(CLONE).get('state') in ACTIVE:
                        state = 'SUPPRESSED_ALREADY_ISOLATED'
                        evidence['reason_codes'] = ['AUTO_ALREADY_ISOLATED']
                    else:
                        evidence['source_verification'] = self.verify_source_history(candidate, self.preflight())
                        evidence['checks'].update(source_verification='PASS', target_allowlist='PASS')
                        evidence['recovery_readiness'] = self.recovery_ready()
                        evidence['checks'].update(recovery_ready='PASS', policy_authorization='PASS')
                        evidence.update(decision='AUTHORIZED', reason_codes=['CORR002_VERIFIED_DISTINCT_LIVE_INJECTION',
                            'DEDICATED_CLONE_MAPPING_VERIFIED', 'OWNER_POLICY_ALLOWLIST_MATCH', 'DURABLE_RECOVERY_AND_WATCHDOG_READY'])
                        # Authorization and evidence are committed before asking the actuator to write.
                        with self.service.connection(write=True) as db:
                            db.execute('INSERT INTO automatic_decisions VALUES(?,?,?,?,?,?,?,NULL,NULL)',
                                       (iid, STREAM, request_id, now_text(), POLICY_SHA256, json.dumps(evidence), 'AUTHORIZED'))
                            db.execute('INSERT INTO automatic_evaluations VALUES(?,?,?,?,?,?,?,?,?,?)',
                                (request_id, iid, STREAM, now_text(), POLICY_SHA256, json.dumps(evidence),
                                 'AUTHORIZED', None, None, request_id))
                        state = 'FAILED'
                        result = self.recovery.quarantine(CLONE, SYSTEM, request_id)
                        state, operation = result['state'], result.get('operation_id')
                except (ValueError, QuarantineError, InventoryError) as error:
                    code = getattr(error, 'code', None) or (str(error) if isinstance(error, ValueError) else 'AUTO_ACTION_FAILED')
                    evidence['reason_codes'].append(code)
                    if evidence['decision'] != 'AUTHORIZED':
                        failed = ('source_verification' if 'MAPPING' in code or 'BASELINE' in code or 'PORT_' in code or 'OWNERSHIP' in code
                                  else 'recovery_ready' if 'WATCHDOG' in code
                                  else 'incident_policy' if code in {'AUTO_RULE_NOT_APPROVED', 'AUTO_INCIDENT_NOT_QUALIFIED'}
                                  else 'evidence_integrity')
                        evidence['checks'][failed] = 'FAIL'
                if evidence['decision'] != 'AUTHORIZED':
                    fingerprint = hashlib.sha256(canon([candidate, state, code])).hexdigest()
                    with self.service.connection(write=True) as db:
                        db.execute('INSERT OR IGNORE INTO automatic_evaluations VALUES(?,?,?,?,?,?,?,NULL,?,?)',
                                   (request_id, iid, STREAM, now_text(), POLICY_SHA256, json.dumps(evidence), state, code, fingerprint))
                with self.service.connection(write=True) as db:
                    row = db.execute('SELECT operation_id,state FROM workload_quarantine WHERE request_id=?', (request_id,)).fetchone()
                    if row:
                        operation, state = row['operation_id'], row['state']
                    db.execute('UPDATE automatic_decisions SET state=?,operation_id=?,error_code=? WHERE incident_id=?',
                               (state, operation, code, iid))
                    db.execute('UPDATE automatic_evaluations SET state=?,operation_id=?,error_code=? WHERE request_id=?',
                               (state, operation, code, request_id))
            with self.service.connection(write=True) as db:
                db.execute('UPDATE automatic_meta SET last_attempt=?,last_success=?,last_error=NULL WHERE singleton=1',
                           (attempted, now_text()))
        except Exception as error:
            with self.service.connection(write=True) as db:
                db.execute('UPDATE automatic_meta SET last_attempt=?,last_error=? WHERE singleton=1',
                           (attempted, getattr(error, 'code', None) or type(error).__name__))
            raise

    def status(self):
        with self.service.connection() as db:
            row = db.execute('SELECT * FROM automatic_meta WHERE singleton=1').fetchone()
            meta = dict(row) if row else None
            watchdog = db.execute('SELECT last_success FROM automatic_watchdog WHERE singleton=1').fetchone()
            observed = db.execute('SELECT mapping_json FROM automatic_source_observations ORDER BY observed_ms DESC LIMIT 1').fetchone()
            decisions = []
            for row in db.execute('SELECT * FROM automatic_evaluations ORDER BY decided_at DESC LIMIT 50'):
                item = dict(row)
                item.pop('fingerprint')
                item['evidence'] = json.loads(item.pop('evidence_json'))
                operation = db.execute('SELECT operation_id,state,restored_at FROM workload_quarantine WHERE request_id=?',
                                       (item['request_id'],)).fetchone()
                if operation:
                    item.update(operation_id=operation['operation_id'], state=operation['state'], restored_at=operation['restored_at'])
                decisions.append(item)
        return {'schema': 'n91-automatic-response-1', 'read_at': now_text(), 'target_id': CLONE,
                'target_name': 'p17-lab-clone', 'policy': POLICY, 'policy_sha256': POLICY_SHA256,
                'executor_code_sha256': EXECUTOR_CODE_SHA256,
                'latest_source_verification': json.loads(observed['mapping_json']) if observed else None,
                'armed': bool(meta and meta['policy_sha256'] == POLICY_SHA256), 'source': meta,
                'watchdog_last_success': watchdog['last_success'] if watchdog else None,
                'decisions': decisions, 'quarantine': self.recovery.status(CLONE)}

    def rpc(self, request):
        if request.get('server_id', CLONE) != CLONE:
            raise ValueError('AUTO_TARGET_NOT_ALLOWED')
        if request['op'] == 'auto_status':
            return self.status()
        if request['op'] == 'auto_journal':
            return business_journal(self.service, PROJECT, CLONE, now_text())
        if request['op'] == 'auto_restore':
            actor_id = str(UUID(request['actor_id']))
            operation = str(UUID(request['operation_id']))
            request_id = str(UUID(request['request_id']))
            actor = SimpleNamespace(user_id=actor_id, roles=('Executor',))
            return self.recovery.restore(CLONE, actor, request_id, operation)
        raise ValueError('AUTO_OPERATION_NOT_ALLOWED')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('mode', choices=['arm', 'rearm', 'run', 'rpc', 'watchdog'])
    args = parser.parse_args()
    config = json.loads(args.config.read_bytes(), object_pairs_hook=unique_object)
    worker = AutomaticResponse(config)
    if args.mode in {'arm', 'rearm'}:
        worker.arm(rearm=args.mode == 'rearm')
        print(json.dumps(worker.status()))
    elif args.mode == 'watchdog':
        worker.watchdog()
    elif args.mode == 'rpc':
        try:
            raw = sys.stdin.buffer.read(65537)
            if len(raw) > 65536:
                raise ValueError('AUTO_REQUEST_LIMIT')
            result = worker.rpc(json.loads(raw, object_pairs_hook=unique_object))
            print(json.dumps({'data': result, 'subject_token': None, 'error': None}))
        except Exception as error:
            print(json.dumps({'error': {'code': getattr(error, 'code', None) or 'AUTO_RESPONSE_REJECTED'}}))
    else:
        import fcntl
        with open(config['database_path'] + '.auto-worker.lock', 'a') as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            while True:
                try:
                    worker.tick()
                except Exception as error:
                    print('AUTO_RESPONSE_WAIT:' + type(error).__name__, flush=True)
                time.sleep(3)


if __name__ == '__main__':
    main()
