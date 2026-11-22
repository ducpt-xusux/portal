"""Validate a real Proxy bundle before updating local API source files."""
import hashlib
import json
import time
from pathlib import Path
from uuid import uuid4

from .p16h_normalizer import LIVE_PROFILE, normalize_line
from .p17_snapshot import Snapshot
from .p17_vnext_api import load_snapshot
from .proxy_services import Export as ServiceExport
from .galera_snapshot import NodeExport, NODES


class RealSourceCache:
    def __init__(self, directory):
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True)

    def write(self, name, value):
        raw = value if isinstance(value, bytes) else json.dumps(value, separators=(',', ':')).encode()
        path = self.directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name('.' + path.name + '.' + uuid4().hex)
        try:
            temporary.write_bytes(raw)
            for attempt in range(20):
                try:
                    temporary.replace(path)
                    break
                except PermissionError:
                    if attempt == 19:
                        raise
                    time.sleep(0.05)
        finally:
            temporary.unlink(missing_ok=True)
        return hashlib.sha256(raw).hexdigest()

    def proxy_bundle(self, bundle):
        if bundle['version'] != 1 or bundle['health']['status'] not in {'RUNNING', 'DEGRADED'}:
            raise ValueError('Invalid source bundle')
        if len(bundle['canonical']) > 100:
            raise ValueError('Canonical export limit exceeded')
        documents = []
        for document in bundle['canonical']:
            if document['schema_version'] != LIVE_PROFILE:
                raise ValueError('A live cache requires a Canonical reader export')
            documents.append(normalize_line(json.dumps(document).encode()))
        canonical = b''.join((json.dumps(row) + '\n').encode() for row in documents)
        if len(canonical) > 8 * 1024 * 1024:
            raise ValueError('Canonical export too large')
        p17_raw = json.dumps(bundle['p17'], separators=(',', ':')).encode()
        snapshot = Snapshot.parse(p17_raw)
        if (snapshot.metadata['stream_id'] != bundle['health']['stream_id'] or
            any(doc['delivery']['stream_id'] != snapshot.metadata['stream_id'] for doc in documents)):
            raise ValueError('Source stream mismatch')
        validation_file = self.directory / ('.validate-vnext-' + uuid4().hex + '.json')
        try:
            validation_file.write_text(json.dumps(bundle['vnext']))
            vnext = load_snapshot(validation_file)
        finally:
            validation_file.unlink(missing_ok=True)
        if vnext['stream_id'] != snapshot.metadata['stream_id']:
            raise ValueError('VNext stream mismatch')
        ServiceExport.model_validate(bundle['services'])
        if set(bundle['galera']) != set(NODES):
            raise ValueError('Unexpected Galera node')
        nodes = [NodeExport.model_validate(row) for row in bundle['galera'].values()]
        if {row.source_host for row in nodes} != set(NODES) or len(nodes) != 3 or len({row.batch_id for row in nodes}) != 1:
            raise ValueError('Galera batch mismatch')
        # All source validation completes before the last good cache is replaced.
        audit_hash = self.write('canonical.jsonl', canonical)
        p17_hash = self.write('p17.json', p17_raw)
        self.write('p17_vnext.json', bundle['vnext'])
        self.write('proxy-services.json', bundle['services'])
        for name, row in bundle['galera'].items():
            if name not in NODES:
                raise ValueError('Unexpected Galera node')
            self.write('galera/' + name + '.json', row)
        self.write('quarantine-journal.json', {'schema':'portal-workload-journal-1',
            'collected_at':bundle['collected_at'], 'operations':bundle.get('quarantine_operations', []),
            'events':bundle.get('quarantine_events', [])})
        self.write('network-history.json', {'schema':'portal-network-history-1',
            'items':bundle.get('network_history', []), 'collected_at':bundle['collected_at']})
        return {'audit': audit_hash, 'p17': p17_hash}
