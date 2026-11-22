from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.inventory_export import InventoryExportReader
from app.main import create_app
from app.openstack_inventory import InventoryError
from app.p16h_normalizer import normalize_line, ImportError


def live_document():
    value = json.loads((Path(__file__).parent / 'fixtures/p16h-TEST-delivery.json').read_bytes())
    value.update(schema_version='portal-p16h-live-1', context='LIVE_READONLY')
    envelope = value['delivery']['envelope']
    envelope.update(schema_version='1.2.0-candidate', event_type='AUDIT_EVENT',
                    event_id=envelope['record']['event_id'], timestamp=envelope['record']['timestamp'], stream_role='SHADOW')
    envelope['metadata'].update(backend={'host': '10.0.0.11', 'port': 3306, 'status': 'SELECTED'}, privacy={
        'profile': 'p16h-h2b-restricted-egress-v1', 'query_rendering': 'restricted-template-values-and-unapproved-identifiers-redacted',
        'sql_mode_tracking': 'UNVERIFIED_BACKSLASH_INPUT_WITHHELD', 'backend_status': 'CLEAR_ALLOWED',
        'db_user_status': 'CLEAR_ALLOWED', 'database_status': 'CLEAR_ALLOWED'})
    value['delivery']['payload_sha256'] = hashlib.sha256(json.dumps(envelope, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
    return value


def test_live_hash_rejects_changed_payload_and_normalization_preserves_hash():
    value = live_document()
    first = normalize_line(json.dumps(value).encode())
    assert normalize_line(json.dumps(first).encode()) == first
    value['delivery']['envelope']['record']['risk_score'] = 90
    with pytest.raises(ImportError, match='P16H_PAYLOAD_HASH_MISMATCH'):
        normalize_line(json.dumps(value).encode())


def test_live_api_retains_table_36_source_fields(tmp_path):
    source = tmp_path / 'canonical.jsonl'
    source.write_text(json.dumps(live_document()) + '\n')
    cfg = Settings(source, tmp_path / 'cache.db', p17_local_readonly=True,
                   p17_snapshot_path=tmp_path / 'p17.json', v4_audit_enabled=True, p16h_import_context='LIVE_READONLY')
    with TestClient(create_app(cfg), client=('127.0.0.1', 1)) as client:
        response = client.get('/api/v1/events?source=canonical').json()
        event = response['data']['items'][0]
        assert event['risk']['score'] == 0
        assert event['stream_sequence'] == 7
        assert event['source_provenance']['payload_hash_basis'] == 'H2B_ENVELOPE_SHA256'
        assert event['source_metadata']['backend']['host'] == '10.0.0.11'
        assert response['meta']['source_schema'] == 'portal-p16h-live-1'


def test_inventory_export_does_not_renew_observation_or_accept_other_project(tmp_path):
    now = datetime.now(timezone.utc)
    path = tmp_path / 'inventory.json'
    project = '12345678-1234-1234-1234-123456789abc'
    payload = {'schema': 'portal-openstack-export-1', 'items': [], 'ports': [], 'meta': {
        'source_schema': 'openstack-inventory-1', 'project_id': project, 'scope': 'SINGLE_PROJECT_READONLY',
        'last_success': now.isoformat(), 'last_attempt': now.isoformat()}}
    path.write_text(json.dumps(payload))
    cfg = Settings(tmp_path / 'audit', tmp_path / 'cache', openstack_enabled=True,
                   openstack_project_id=project, openstack_inventory_export_path=path)
    reader = InventoryExportReader(cfg, clock=lambda: now)
    assert reader.read()[1]['freshness_state'] == 'FRESH'
    reader.clock = lambda: now + timedelta(seconds=46)
    assert reader.read()[1]['freshness_state'] == 'STALE'
    payload['meta']['project_id'] = 'other-project'
    path.write_text(json.dumps(payload))
    assert reader.read()[1]['last_error_code'] == 'OPENSTACK_EXPORT_UNAVAILABLE'
    with pytest.raises(InventoryError):
        InventoryExportReader(cfg).read()


def test_ssh_inventory_keeps_a_verified_sample_when_the_next_read_fails(tmp_path, monkeypatch):
    from app import inventory_export

    now = datetime.now(timezone.utc)
    project = '12345678-1234-1234-1234-123456789abc'
    observed = (now - timedelta(seconds=2)).isoformat()
    payload = {'schema': 'portal-openstack-export-1', 'items': [], 'ports': [], 'meta': {
        'source_schema': 'openstack-inventory-1', 'project_id': project, 'scope': 'SINGLE_PROJECT_READONLY',
        'last_success': observed, 'last_attempt': observed}}

    class Relay:
        fail = False

        def rpc(self, request):
            assert request == {'op': 'inventory_export'}
            assert not reader.lock.locked()
            if self.fail:
                raise InventoryError('OPENSTACK_CONNECTION_FAILED')
            return payload, None

    relay = Relay()
    monkeypatch.setattr(inventory_export, 'SSHTransport', lambda path, profile: relay)
    path = tmp_path / 'inventory.json'
    cfg = Settings(tmp_path / 'audit', tmp_path / 'cache', openstack_enabled=True,
                   openstack_project_id=project, openstack_inventory_export_path=path,
                   openstack_inventory_export_ssh_config_path=tmp_path / 'relay.json')
    reader = InventoryExportReader(cfg, clock=lambda: now)
    reader.sample()
    first = path.read_bytes()
    assert reader.read()[1]['last_success'] == observed
    assert reader.read()[1]['freshness_state'] == 'FRESH'

    payload['meta']['project_id'] = 'different-project'
    with pytest.raises(InventoryError, match='OPENSTACK_EXPORT_UNAVAILABLE'):
        reader.sample()
    assert path.read_bytes() == first

    relay.fail = True
    with pytest.raises(InventoryError, match='OPENSTACK_CONNECTION_FAILED'):
        reader.sample()
    meta = reader.read()[1]
    assert meta['last_success'] == observed
    assert meta['freshness_state'] == 'STALE'
    assert meta['last_error_code'] == 'OPENSTACK_CONNECTION_FAILED'

    relay.fail = False
    payload['meta'].update(project_id=project, last_success=now.isoformat(), last_attempt=now.isoformat())
    reader.sample()
    assert reader.read()[1]['last_success'] == now.isoformat()
    assert reader.read()[1]['freshness_state'] == 'FRESH'


def test_ssh_inventory_cannot_publish_over_the_portal_database(tmp_path):
    database = tmp_path / 'cache.db'
    with pytest.raises(ValueError, match='dedicated export file'):
        Settings(tmp_path / 'audit', database, openstack_enabled=True,
                 openstack_inventory_export_path=database,
                 openstack_inventory_export_ssh_config_path=tmp_path / 'relay.json')


def test_session_inventory_never_replaces_live_port_state_with_export_hints(monkeypatch):
    from app.inventory_export import SessionInventoryReader
    from app.openstack_inventory import InventoryReader
    from types import SimpleNamespace
    reader = SessionInventoryReader.__new__(SessionInventoryReader)
    live = [{'server_id':'TEST-vm','project_id':'TEST-project','compute_host':None,
             'network_state':'QUARANTINED','ports':[{'revision_number':8,'security_group_ids':['TEST-quarantine']}]}]
    hint = {'server_id':'TEST-vm','project_id':'TEST-project','compute_host':'TEST-compute',
            'compute_host_source':'NOVA_CONTROLLER_READONLY_PROJECTION','network_state':'NORMAL',
            'ports':[{'revision_number':7,'security_group_ids':['TEST-original']}]}
    monkeypatch.setattr(InventoryReader, 'collect', lambda self: (live, True))
    reader.export = SimpleNamespace(read=lambda: ([hint], {'freshness_state':'FRESH'}, 'TEST-hash'))
    result, classification = reader.collect()
    assert classification is True and result[0]['compute_host']=='TEST-compute'
    assert result[0]['network_state']=='QUARANTINED'
    assert result[0]['ports'][0]['revision_number']==8
    assert result[0]['ports'][0]['security_group_ids']==['TEST-quarantine']


def test_compute_host_projection_requires_fresh_same_project_metadata(tmp_path):
    from integrations.openstack_compute_hosts import SCHEMA, add_compute_hosts

    observed = datetime.now(timezone.utc)
    path = tmp_path / 'compute-hosts.json'
    rows = [
        {'server_id': 'target', 'project_id': 'project', 'compute_host': None, 'network_state': 'QUARANTINED'},
        {'server_id': 'direct', 'project_id': 'project', 'compute_host': 'direct-host'},
        {'server_id': 'outside', 'project_id': 'outside-project', 'compute_host': None},
    ]
    snapshot = {'meta': {'project_id': 'project'}, 'items': rows}
    projection = {'schema': SCHEMA, 'project_id': 'project',
                  'hosts': {'target': 'compute-1', 'direct': 'compute-2', 'outside': 'compute-3'}}

    path.write_text(json.dumps({**projection, 'observed_at': (observed - timedelta(minutes=1)).isoformat()}))
    add_compute_hosts(snapshot, path)
    assert rows[0]['compute_host'] is None

    path.write_text(json.dumps({**projection, 'observed_at': observed.isoformat()}))
    add_compute_hosts(snapshot, path)
    assert [row['compute_host'] for row in rows] == ['compute-1', 'direct-host', None]
    assert rows[0]['compute_host_source'] == 'NOVA_CONTROLLER_READONLY_PROJECTION'
    assert rows[0]['network_state'] == 'QUARANTINED'
