"""Read the existing Proxy producers; no ACK, DB write, or cloud action.

Run with the Portal package on PYTHONPATH and the reviewed source environment.
Only the source directory for the already installed P17 worker is imported.
"""
import argparse
import base64
from datetime import datetime, timezone
import gzip
import json
from pathlib import Path
import sqlite3
import sys

from .config import Settings
from .proxy_export import read_p17
from .vnext_export import read_snapshot
from .galera_snapshot import batch_lock


def collect(settings, p17_database, worker_directory, portal_history_database=None):
    sys.path.insert(0, str(worker_directory))
    from p17_durable import reader_request
    now = datetime.now(timezone.utc).isoformat()
    health = reader_request({'op': 'HEALTH'})
    recent = reader_request({'op': 'RECENT', 'limit': 100})
    docs = [{'schema_version': 'portal-p16h-live-1', 'context': 'LIVE_READONLY',
             'delivery': row, 'source': {'artifact_id': 'proxy-canonical-reader',
                                       'source_host': 'proxy', 'collected_at': now}}
            for row in recent]
    result = {'version': 1, 'collected_at': now, 'health': health,
              'canonical': docs, 'p17': read_p17(str(p17_database)),
              'vnext': read_snapshot(str(p17_database)), 'galera': {}, 'quarantine_operations': []}
    if settings.proxy_services_path:
        result['services'] = json.loads(settings.proxy_services_path.read_text())
    if settings.galera_snapshot_dir:
        with batch_lock(settings.galera_snapshot_dir):
            for node in ('galera-1', 'galera-2', 'galera-3'):
                result['galera'][node] = json.loads((settings.galera_snapshot_dir / (node + '.json')).read_text())
    if settings.business_database_path:
        db = sqlite3.connect(settings.business_database_path.as_uri() + '?mode=ro', uri=True, timeout=3)
        db.row_factory = sqlite3.Row
        try:
            db.execute('PRAGMA query_only=ON')
            columns = ('operation_id,server_id,project_id,quarantine_sg,ports_json,state,started_at,'
                       'quarantined_at,restore_at,restored_at,restore_trigger,error_code')
            result['quarantine_operations'] = [dict(row) for row in db.execute(
                'SELECT ' + columns + ' FROM workload_quarantine ORDER BY started_at DESC LIMIT 1000')]
            events = []
            for row in db.execute("SELECT action,target_ref,outcome,timestamp,before_json,after_json FROM admin_audit "
                                  "WHERE action IN ('WORKLOAD_QUARANTINE','WORKLOAD_RESTORE') ORDER BY seq DESC LIMIT 2000"):
                before = (json.loads(row['before_json']) or {}) if row['before_json'] else {}
                after = (json.loads(row['after_json']) or {}) if row['after_json'] else {}
                if isinstance(before, list):
                    before = {'ports': before}
                event = {k: row[k] for k in ('action', 'target_ref', 'outcome', 'timestamp')}
                event['operation_id'] = after.get('operation_id') or before.get('operation_id')
                for phase, value in [('before', before), ('after', after)]:
                    event[phase] = [{k: p[k] for k in ('port_id', 'security_group_ids', 'revision_number') if k in p}
                                    for p in value.get('ports', []) if isinstance(p, dict)]
                events.append(event)
            result['quarantine_events'] = events
        finally:
            db.close()
    if portal_history_database is not None:
        db = sqlite3.connect(portal_history_database.as_uri() + '?mode=ro', uri=True, timeout=3)
        db.row_factory = sqlite3.Row
        try:
            db.execute('PRAGMA query_only=ON')
            result['network_history'] = [dict(row) for row in db.execute(
                'SELECT project_id,server_id,state,observed_at,source FROM workload_network_history '
                'WHERE project_id=? ORDER BY observed_at DESC,id DESC LIMIT 1000', (settings.openstack_project_id,))]
        finally:
            db.close()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env-file', type=Path, required=True)
    parser.add_argument('--p17-db', type=Path, required=True)
    parser.add_argument('--worker-directory', type=Path, required=True)
    parser.add_argument('--portal-history-db', type=Path)
    args = parser.parse_args()
    from dotenv import load_dotenv
    load_dotenv(args.env_file)
    bundle = collect(Settings.from_env(), args.p17_db, args.worker_directory, args.portal_history_db)
    print(base64.b64encode(gzip.compress(json.dumps(bundle, separators=(',', ':')).encode())).decode())


if __name__ == '__main__':
    main()
