"""Credential-local Nova/Neutron exporter. Only read operations leave the reader.

Run on the host that can reach Keystone with reviewed OPENSTACK_* settings.
The exported file contains inventory, observation metadata and no credential.
"""
import argparse
import json
import os
from pathlib import Path
import tempfile

from .config import Settings
from .openstack_inventory import InventoryReader, MAX_BYTES, Transport
from .source_json import unique_object


def collect(settings, *, request_timeout=None):
    transport = Transport(request_timeout=request_timeout) if request_timeout is not None else None
    reader = InventoryReader(settings, transport=transport)
    items, meta, fingerprint = reader.read()
    return {'schema': 'portal-openstack-export-1', 'items': items, 'ports': reader.cached_ports,
            'meta': meta, 'fingerprint': fingerprint}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--settings-json', type=Path, required=True,
                        help='Host-local configuration paths/URLs; credential contents stay in their original file')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    raw = args.settings_json.read_bytes()
    if len(raw) > 16384:
        raise ValueError('Source configuration too large')
    settings = json.loads(raw, object_pairs_hook=unique_object)
    for key, value in settings.items():
        if key not in {'OPENSTACK_INVENTORY_ENABLED', 'OPENSTACK_CREDENTIAL_PATH', 'OPENSTACK_AUTH_URL',
                       'OPENSTACK_COMPUTE_URL', 'OPENSTACK_NETWORK_URL', 'OPENSTACK_PROJECT_ID',
                       'OPENSTACK_QUARANTINE_SG_ID'} or not isinstance(value, str):
            raise ValueError('Unsupported source setting')
        os.environ[key] = value
    export = collect(Settings.from_env())
    raw = json.dumps(export, separators=(',', ':')).encode()
    if len(raw) > MAX_BYTES or args.output.is_symlink():
        raise ValueError('Invalid export target or size')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=args.output.parent, delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(raw)
    try:
        temporary.replace(args.output)
    finally:
        temporary.unlink(missing_ok=True)
    print('OPENSTACK_READONLY_EXPORT_PASS items=' + str(len(export['items'])))


if __name__ == '__main__':
    main()
