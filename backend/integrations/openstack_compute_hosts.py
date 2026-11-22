"""Publish and read project-scoped Nova host names on the Controller."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
from tempfile import NamedTemporaryFile
from uuid import UUID


SCHEMA = 'nova-compute-hosts-1'
MAX_BYTES = 4 * 1024 * 1024
HOST_MAX_AGE_SECONDS = 45
HOST_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,254}')


def publish(project_id, output):
    UUID(project_id)
    if not output.is_absolute() or output.is_symlink():
        raise ValueError('Compute host export requires a dedicated absolute path')

    result = subprocess.run([
        '/usr/bin/openstack', 'server', 'list', '--project', project_id, '--long',
        '-f', 'json', '-c', 'ID', '-c', 'Host',
    ], capture_output=True, check=True, timeout=18)
    observed_at = datetime.now(timezone.utc).isoformat()
    hosts = {}
    for row in json.loads(result.stdout):
        server_id, host = row['ID'], row['Host']
        UUID(server_id)
        if server_id in hosts or (host and not HOST_NAME.fullmatch(host)):
            raise ValueError('Invalid Nova host report')
        hosts[server_id] = host or None

    data = json.dumps({'schema': SCHEMA, 'project_id': project_id,
                       'observed_at': observed_at, 'hosts': hosts}, separators=(',', ':')).encode()
    if len(data) > MAX_BYTES:
        raise ValueError('Compute host report is too large')
    with NamedTemporaryFile(dir=output.parent, prefix='.compute-hosts-', delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(data)
            stream.close()
            temporary.replace(output)
        finally:
            temporary.unlink(missing_ok=True)


def add_compute_hosts(inventory, path):
    """Join fresh host metadata without changing reader-role state or port data."""
    try:
        with path.open('rb') as source:
            raw = source.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            return
        projection = json.loads(raw)
        project_id = inventory['meta']['project_id']
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(projection['observed_at'])).total_seconds()
        if (projection['schema'] != SCHEMA or projection['project_id'] != project_id or
                not -1 <= age <= HOST_MAX_AGE_SECONDS or not isinstance(projection['hosts'], dict)):
            return
    except (OSError, KeyError, TypeError, ValueError):
        return

    for item in inventory['items']:
        host = projection['hosts'].get(item['server_id'])
        if (item['project_id'] == project_id and not item.get('compute_host') and
                isinstance(host, str) and HOST_NAME.fullmatch(host)):
            item['compute_host'] = host
            item['compute_host_source'] = 'NOVA_CONTROLLER_READONLY_PROJECTION'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project-id', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        publish(args.project_id, args.output)
    except (OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError):
        parser.exit(1, 'Nova compute host export failed\n')


if __name__ == '__main__':
    main()
