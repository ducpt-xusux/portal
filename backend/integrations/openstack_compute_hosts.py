"""Publish and read project-scoped Nova host names on the Controller."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from tempfile import NamedTemporaryFile
from urllib.parse import urlencode
from uuid import UUID

from app.openstack_inventory import InventoryError, MAX_RECORDS, PAGE_SIZE, Transport, identifier, rows

SCHEMA = 'nova-compute-hosts-1'
MAX_BYTES = 4 * 1024 * 1024
HOST_MAX_AGE_SECONDS = 45
HOST_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,254}')


def collect_hosts(project_id, auth_url, nova_url, transport):
    user = {'name': os.environ['OS_USERNAME'], 'password': os.environ['OS_PASSWORD'],
            'domain': {'name': os.environ['OS_USER_DOMAIN_NAME']}}
    project = {'name': os.environ['OS_PROJECT_NAME'], 'domain': {'name': os.environ['OS_PROJECT_DOMAIN_NAME']}}
    auth = {'auth': {'identity': {'methods': ['password'], 'password': {'user': user}},
                     'scope': {'project': project}}}
    authorization, token = transport.send('POST', auth_url.rstrip('/') + '/auth/tokens', body=auth)
    if not token or 'admin' not in {role['name'] for role in authorization['token']['roles']}:
        raise ValueError('Nova host projection requires an administrative token on the Controller')

    hosts = {}
    params = {'all_tenants': 1, 'project_id': project_id, 'limit': PAGE_SIZE}
    for _ in range(MAX_RECORDS // PAGE_SIZE + 1):
        data, _ = transport.send('GET', nova_url.rstrip('/') + '/servers/detail?' + urlencode(params),
                                 token=token, nova_version='2.1')
        servers = rows(data['servers'])
        for row in servers:
            server_id = identifier(row['id'])
            host = row.get('OS-EXT-SRV-ATTR:host')
            if (row.get('tenant_id', row.get('project_id')) != project_id or server_id in hosts or
                    (host and not HOST_NAME.fullmatch(host))):
                raise ValueError('Invalid Nova host report')
            hosts[server_id] = host or None
        if len(hosts) > MAX_RECORDS:
            raise ValueError('Nova host report is too large')
        more = any(link.get('rel') == 'next' for link in rows(data.get('servers_links', [])))
        if not more and len(servers) < PAGE_SIZE:
            return hosts
        if not servers:
            break
        params['marker'] = servers[-1]['id']
    raise ValueError('Invalid Nova host pagination')


def publish(project_id, output, config):
    UUID(project_id)
    if not output.is_absolute() or output.is_symlink():
        raise ValueError('Compute host export requires a dedicated absolute path')
    if config['OPENSTACK_PROJECT_ID'] != project_id:
        raise ValueError('Nova host project does not match the inventory')
    hosts = collect_hosts(project_id, config['OPENSTACK_AUTH_URL'], config['OPENSTACK_COMPUTE_URL'],
                          Transport(request_timeout=9))
    observed_at = datetime.now(timezone.utc).isoformat()

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
    parser.add_argument('--source-config', required=True, type=Path)
    args = parser.parse_args()
    try:
        with args.source_config.open('rb') as file:
            raw = file.read(16385)
        if len(raw) > 16384:
            raise ValueError('Oversized Nova source configuration')
        publish(args.project_id, args.output, json.loads(raw))
    except (InventoryError, OSError, KeyError, TypeError, ValueError):
        parser.exit(1, 'Nova compute host export failed\n')


if __name__ == '__main__':
    main()
