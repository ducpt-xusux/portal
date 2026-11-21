import json
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.inventory_export import InventoryExportReader
from app.openstack_inventory import InventoryError
from app.report_evidence import read_report_evidence
from app.workload_journal import read_journal


def test_report_keeps_historical_scope_and_rejects_credentials_and_duplicate_keys(tmp_path):
    path = tmp_path / 'evidence.json'
    artifact = dict(evidence_id='TEST-restore', title='TEST restore', scope='LAB_ONLY',
        observed_at='2026-01-01T00:00:00Z', source_sha256='a' * 64,
        facts=[{'key': 'FULL_SYSTEM_RTO', 'value': 'NOT_MEASURED'}])
    payload = {'schema_version': 'portal-report-evidence-1', 'artifacts': [artifact]}
    path.write_text(json.dumps(payload))
    result = read_report_evidence(path)['artifacts'][0]
    assert result['scope'] == 'LAB_ONLY'
    assert result['facts'][0]['value'] == 'NOT_MEASURED'
    artifact['facts'] = [{'key': 'DB_PASSWORD', 'value': 'TEST-only'}]
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError):
        read_report_evidence(path)
    path.write_text('{"schema_version":"portal-report-evidence-1","artifacts":[],"artifacts":[]}')
    with pytest.raises(ValueError, match='Duplicate JSON key'):
        read_report_evidence(path)


def test_network_history_filters_project_and_retains_real_transitions(tmp_path):
    path = tmp_path / 'history.json'
    rows = [dict(project_id=project, server_id='TEST-vm', state=state, observed_at=stamp,
                 source='TEST-persisted-observation') for project, state, stamp in [
        ('TEST-project', 'NORMAL', '2026-01-01T00:01:00Z'),
        ('OTHER-project', 'UNKNOWN', '2026-01-02T00:00:00Z'),
        ('TEST-project', 'QUARANTINED', '2026-01-01T00:00:00Z')]]
    payload = {'schema': 'portal-network-history-1', 'items': rows}
    path.write_text(json.dumps(payload))
    cfg = SimpleNamespace(workload_network_history_export_path=path, openstack_project_id='TEST-project')
    reader = InventoryExportReader(cfg, clock=lambda: datetime.now(timezone.utc))
    result = reader.network_history(['TEST-vm'])['TEST-vm']
    assert [row['state'] for row in result] == ['NORMAL', 'QUARANTINED']
    assert result[0]['previous_state'] == 'QUARANTINED'
    assert result[-1]['previous_state'] is None
    rows[0]['state'] = 'INVENTED'
    path.write_text(json.dumps(payload))
    with pytest.raises(InventoryError):
        reader.network_history(['TEST-vm'])


def test_journal_never_joins_other_operation_or_exports_actor_credentials(tmp_path):
    path = tmp_path / 'journal.json'
    operation = dict(operation_id='00000000-0000-4000-8000-000000000001', server_id='TEST-vm', project_id='TEST-project',
        state='RESTORED', ports_json=json.dumps([dict(port_id='TEST-port', revision_number=0,
            security_group_ids=['TEST-original'], quarantine_revision=1)]), actor='TEST-private')
    event = dict(operation_id=operation['operation_id'], target_ref='TEST-vm', action='RESTORE', outcome='SUCCESS',
        timestamp='2026-01-01T00:01:00Z', before=[], after=[dict(port_id='TEST-port',
            revision_number=2, security_group_ids=['TEST-original'], credential='TEST-private')])
    payload = dict(schema='portal-workload-journal-1', collected_at='2026-01-01T00:02:00Z',
        operations=[operation, {**operation, 'project_id': 'OTHER-project'}],
        events=[event, {**event, 'operation_id': 'OTHER-op'}])
    path.write_text(json.dumps(payload))
    result = read_journal(path, 'TEST-project', 'TEST-vm')
    assert result['historical'] is True
    assert len(result['operations']) == len(result['operations'][0]['events']) == 1
    assert result['operations'][0]['ports'][0]['revision_number'] == 0
    assert 'TEST-private' not in json.dumps(result)
