"""Allowlisted read-only projection of the Portal's persisted action journal."""
import json
from .openstack_inventory import identifier
from .proxy_services import unique_object


def read_journal(path, project_id, server_id):
    if path is None:
        return None
    with path.open('rb') as f:
        raw = f.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError('Journal too large')
    value = json.loads(raw, object_pairs_hook=unique_object)
    if value['schema'] != 'portal-workload-journal-1':
        raise ValueError('Invalid journal schema')
    return project_journal(value, project_id, server_id)


def project_journal(value, project_id, server_id):
    operations = []
    for row in value['operations']:
        if row['project_id'] != project_id or row['server_id'] != server_id:
            continue
        identifier(row['operation_id'])
        item = {k: row.get(k) for k in ('operation_id', 'server_id', 'project_id', 'state', 'started_at',
                 'quarantined_at', 'restored_at', 'restore_at', 'restore_trigger', 'error_code', 'quarantine_sg')}
        item['ports'] = [{k: p.get(k) for k in ('port_id', 'revision_number', 'security_group_ids', 'quarantine_revision')}
                         for p in json.loads(row['ports_json'])]
        ids = {p['port_id'] for p in item['ports']}
        events = []
        for event in value['events']:
            if event['target_ref'] != server_id or event.get('operation_id') != row['operation_id']:
                continue
            safe = {k: event.get(k) for k in ('action', 'outcome', 'timestamp')}
            for stage in ('before', 'after'):
                safe[stage] = [{k: p.get(k) for k in ('port_id', 'revision_number', 'security_group_ids')}
                               for p in event.get(stage, []) if p['port_id'] in ids]
            events.append(safe)
        item['events'] = events
        operations.append(item)
    return {'operations': operations, 'source_system': 'PORTAL_PERSISTED_ACTION_JOURNAL',
            'collected_at': value['collected_at'], 'historical': True}


def business_journal(service, project_id, server_id, collected_at):
    """Read local action evidence without exporting users, sessions or audit actors."""
    with service.connection() as db:
        operations = [dict(row) for row in db.execute(
            'SELECT operation_id,server_id,project_id,quarantine_sg,ports_json,state,started_at,'
            'quarantined_at,restore_at,restored_at,restore_trigger,error_code FROM workload_quarantine '
            'WHERE project_id=? AND server_id=? ORDER BY started_at DESC LIMIT 1000', (project_id, server_id))]
        events = []
        for row in db.execute("SELECT action,target_ref,outcome,timestamp,before_json,after_json FROM admin_audit "
                "WHERE target_ref=? AND action IN ('WORKLOAD_QUARANTINE','WORKLOAD_RESTORE') ORDER BY seq DESC LIMIT 2000", (server_id,)):
            before = json.loads(row['before_json']) if row['before_json'] else {}
            after = json.loads(row['after_json']) if row['after_json'] else {}
            before = {'ports': before} if isinstance(before, list) else before or {}
            after = after or {}
            event = {k: row[k] for k in ('action', 'target_ref', 'outcome', 'timestamp')}
            event['operation_id'] = after.get('operation_id') or before.get('operation_id')
            for stage, source in [('before', before), ('after', after)]:
                event[stage] = [{k: p.get(k) for k in ('port_id','revision_number','security_group_ids')}
                    for p in source.get('ports', [])]
            events.append(event)
    return project_journal({'operations': operations, 'events': events, 'collected_at': collected_at}, project_id, server_id)
