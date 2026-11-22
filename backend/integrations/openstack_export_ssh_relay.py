"""Return one fresh, reader-role Nova/Neutron snapshot over a forced SSH command."""

import argparse
import json
import os
from pathlib import Path
import sys

from app.config import Settings
from app.openstack_export import collect
from app.openstack_inventory import InventoryError, MAX_BYTES
from app.source_json import unique_object


SOURCE_KEYS = {
    'OPENSTACK_INVENTORY_ENABLED', 'OPENSTACK_CREDENTIAL_PATH', 'OPENSTACK_AUTH_URL',
    'OPENSTACK_COMPUTE_URL', 'OPENSTACK_NETWORK_URL', 'OPENSTACK_PROJECT_ID',
    'OPENSTACK_QUARANTINE_SG_ID',
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    try:
        raw = sys.stdin.buffer.read(1025)
        if len(raw) > 1024 or json.loads(raw, object_pairs_hook=unique_object) != {
            'op': 'inventory_export', 'profile': 'reader',
        }:
            raise ValueError('Invalid inventory request')
        with args.config.open('rb') as stream:
            raw = stream.read(16385)
        if len(raw) > 16384:
            raise ValueError('Oversized source configuration')
        settings = json.loads(raw, object_pairs_hook=unique_object)
        if settings.keys() != SOURCE_KEYS or not all(isinstance(v, str) for v in settings.values()):
            raise ValueError('Invalid source configuration')
        os.environ.update(settings)
        data = collect(Settings.from_env())
        result = json.dumps({'data': data}, separators=(',', ':')).encode()
        if len(result) > MAX_BYTES:
            raise ValueError('Oversized inventory response')
    except InventoryError as error:
        result = json.dumps({'error': {'code': error.code}}).encode()
    except (OSError, TypeError, ValueError, AttributeError):
        result = b'{"error":{"code":"OPENSTACK_RELAY_REQUEST_REJECTED"}}'
    sys.stdout.buffer.write(result + b'\n')


if __name__ == '__main__':
    main()
