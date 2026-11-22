"""Read a bounded Nova/Neutron export without moving cloud credentials to clients.

Observation timestamps belong to the remote collector. Reading a local file never
renews them, and an export can never authorize a cloud mutation.
"""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime
import hashlib
import json
from pathlib import Path
import sqlite3
from tempfile import NamedTemporaryFile

from .openstack_inventory import InventoryReader, InventoryError, identifier, TTL, MAX_BYTES
from .proxy_services import unique_object
from .schemas import iso
from .ssh_openstack import SSHTransport


def stamp(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('Timezone required')
    return parsed


class InventoryExportReader(InventoryReader):
    def __init__(self, settings, **kwargs):
        super().__init__(settings, **kwargs)
        path = getattr(settings, 'openstack_inventory_export_ssh_config_path', None)
        self.export_transport = SSHTransport(path, 'reader') if path else None
        self.export_error = None
        self.export_attempt = None
        if self.export_transport:
            self.refresh_seconds = 8

    def _fetch_export(self):
        data, token = self.export_transport.rpc({'op': 'inventory_export'})
        raw = json.dumps(data, separators=(',', ':')).encode()
        target = self.settings.openstack_inventory_export_path
        if token is not None or len(raw) > MAX_BYTES or target.is_symlink():
            raise InventoryError('OPENSTACK_EXPORT_UNAVAILABLE')
        with NamedTemporaryFile(dir=target.parent, prefix='.inventory-', delete=False) as stream:
            candidate = Path(stream.name)
        try:
            candidate.write_bytes(raw)
            config = replace(self.settings, openstack_inventory_export_path=candidate,
                             openstack_inventory_export_ssh_config_path=None)
            items, meta, _ = InventoryExportReader(config, clock=self.clock).read()
            if meta['freshness_state'] != 'FRESH':
                raise InventoryError(meta['last_error_code'])
            with self.lock:
                if self.last_success and stamp(meta['last_success']) <= self.last_success:
                    raise InventoryError('OPENSTACK_EXPORT_STALE')
                candidate.replace(target)
                self.export_error = None
            return items
        finally:
            candidate.unlink(missing_ok=True)

    def sample(self):
        if not self.export_transport:
            return super().sample()
        with self.lock:
            self.export_attempt = self.clock()
        try:
            items = self._fetch_export()
        except (InventoryError, OSError, ValueError, TypeError) as error:
            with self.lock:
                self.export_error = getattr(error, 'code', 'OPENSTACK_EXPORT_UNAVAILABLE')
            raise InventoryError(self.export_error) from None
        if self.history_store:
            try:
                self.history_store.record_workload_network(
                    self.settings.openstack_project_id,
                    [(item['server_id'], item['network_observed_at'], item['network_state']) for item in items],
                    'NEUTRON_INVENTORY',
                )
                self.history_error = None
            except sqlite3.Error:
                self.history_error = 'WORKLOAD_NETWORK_HISTORY_UNAVAILABLE'

    def network_history(self, server_ids):
        try:
            return self._network_history(server_ids)
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            raise InventoryError('WORKLOAD_NETWORK_HISTORY_UNAVAILABLE') from None

    def _network_history(self, server_ids):
        path = self.settings.workload_network_history_export_path
        if path is None:
            return super().network_history(server_ids)
        with path.open('rb') as source:
            raw = source.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise InventoryError('WORKLOAD_NETWORK_HISTORY_UNAVAILABLE')
        value = json.loads(raw, object_pairs_hook=unique_object)
        if value['schema'] != 'portal-network-history-1':
            raise InventoryError('WORKLOAD_NETWORK_HISTORY_UNAVAILABLE')
        result = {}
        for server_id in server_ids:
            rows = [row for row in value['items'] if row['project_id'] == self.settings.openstack_project_id and row['server_id'] == server_id]
            if self.history_store:
                local = self.history_store.workload_network_history(self.settings.openstack_project_id, [server_id]).get(server_id, [])
                seen = {(row['state'], row['observed_at'], row['source']) for row in rows}
                rows.extend(row for row in local if (row['state'], row['observed_at'], row['source']) not in seen)
            rows.sort(key=lambda row: stamp(row['observed_at']), reverse=True)
            if any(row['state'] not in {'NORMAL','QUARANTINED','MISMATCH','UNKNOWN'} for row in rows):
                raise InventoryError('WORKLOAD_NETWORK_HISTORY_UNAVAILABLE')
            result[server_id] = [{**{k: row[k] for k in ('state','observed_at','source')},
                'previous_state':rows[index+1]['state'] if index+1 < len(rows) else None}
                for index,row in enumerate(rows[:10])]
        return result

    def configured(self):
        if not self.settings.openstack_enabled or not self.settings.openstack_inventory_export_path:
            raise InventoryError('OPENSTACK_NOT_CONFIGURED')
        identifier(self.settings.openstack_project_id)

    def _read_locked(self, *, copy=True):
        self.configured()
        try:
            with self.settings.openstack_inventory_export_path.open('rb') as source:
                raw = source.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise ValueError('Export too large')
            export = json.loads(raw, object_pairs_hook=unique_object)
            meta = export['meta']
            if (export['schema'] != 'portal-openstack-export-1' or
                meta['source_schema'] != 'openstack-inventory-1' or
                meta['project_id'] != self.settings.openstack_project_id or
                meta['scope'] != 'SINGLE_PROJECT_READONLY'):
                raise ValueError('Source scope mismatch')
            observed = stamp(meta['last_success'])
            attempt = stamp(meta['last_attempt'])
            if (observed - self.clock()).total_seconds() > 5:
                raise ValueError('Future observation')
            items, ports = export['items'], export['ports']
            if not isinstance(items, list) or not isinstance(ports, list) or len(items) > 10000 or len(ports) > 10000:
                raise ValueError('Collection invalid')
            ids = set()
            for item in [*items, *ports]:
                if item['project_id'] != self.settings.openstack_project_id:
                    raise ValueError('Project mismatch')
            for item in items:
                server_id = identifier(item['server_id'])
                if server_id in ids:
                    raise ValueError('Duplicate VM')
                ids.add(server_id)
                if not isinstance(item['ports'], list):
                    raise ValueError('Ports invalid')
                for port in item['ports']:
                    identifier(port['port_id'])
                    if port['project_id'] != item['project_id'] or port['device_id'] != server_id:
                        raise ValueError('Port scope mismatch')
            def safe_port(port):
                result = {k: port.get(k) for k in ('port_id', 'project_id', 'device_id', 'device_owner', 'revision_number',
                    'network_id', 'status', 'mac_address', 'security_group_ids', 'port_security_enabled', 'network_state', 'observed_at')}
                for key, fields in [('fixed_ips', ('ip_address', 'subnet_id')), ('floating_ips', ('floating_ip_address',)),
                                    ('security_groups', ('id', 'name'))]:
                    result[key] = [{k: row.get(k) for k in fields} for row in port.get(key, [])]
                return result
            ports = [safe_port(port) for port in ports]
            items = [{**{k: item.get(k) for k in ('server_id', 'name', 'project_id', 'nova_status', 'compute_host',
                       'compute_host_source', 'role', 'protected', 'network_state', 'network_observed_at', 'observed_at')},
                       'ports': [safe_port(port) for port in item['ports']],
                       'network_observation': {k: item['network_observation'].get(k) for k in ('state', 'verification', 'observed_at')}
                           if item.get('network_observation') else None, 'incident_refs': [], 'risk_exposure': None} for item in items]
            meta = {k: meta.get(k) for k in ('source_system', 'source_schema', 'source_mode', 'data_state', 'freshness_state',
                'stale_after_seconds', 'data_as_of', 'observed_at', 'observation_from', 'last_attempt', 'last_success',
                'last_error_code', 'project_id', 'refresh_seconds', 'scope', 'network_classification',
                'network_stale_after_seconds', 'network_history_error')}
            self.cached, self.cached_ports = items, ports
            self.export_meta = meta
            self.last_success, self.last_attempt = observed, attempt
            self.last_error = meta.get('last_error_code')
            self.fingerprint = hashlib.sha256(raw).hexdigest()
        except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
            self.last_error = 'OPENSTACK_EXPORT_UNAVAILABLE'
        error = self.export_error or self.last_error
        if self.cached is None:
            raise InventoryError(error)
        if not copy:
            return
        stale = bool(error) or (self.clock() - self.last_success).total_seconds() > TTL
        meta = {**self.export_meta, 'source_mode': 'REMOTE_READONLY', 'collection_mode': 'SSH_EXPORT',
                'access_mode': 'LOCAL_REMOTE_READONLY', 'read_at': iso(self.clock()),
                'freshness_state': 'STALE' if stale else 'FRESH',
                'data_state': 'CACHED_STALE' if stale else 'CURRENT',
                'last_error_code': error or ('OPENSTACK_EXPORT_STALE' if stale else None),
                'source_ref': 'sha256:' + self.fingerprint}
        if self.export_transport:
            meta.update(refresh_seconds=self.refresh_seconds, network_history_error=self.history_error)
            if self.export_attempt:
                meta['last_attempt'] = iso(self.export_attempt)
        return deepcopy(self.cached), meta, self.fingerprint


class SessionInventoryReader(InventoryReader):
    """Use live reader-role cloud readback after actions, retaining display-only Nova hints."""
    def __init__(self, settings, **kwargs):
        super().__init__(settings, **kwargs)
        self.export = InventoryExportReader(settings, clock=self.clock, history_store=self.history_store)

    def collect(self):
        items, classification = super().collect()
        try:
            hints, meta, _ = self.export.read()
        except InventoryError:
            hints, meta = [], {}
        if meta.get('freshness_state') == 'FRESH':
            by_id = {row['server_id']: row for row in hints}
            for item in items:
                hint = by_id.get(item['server_id'])
                if hint and hint['project_id'] == item['project_id'] and item['compute_host'] is None:
                    item['compute_host'] = hint.get('compute_host')
                    item['compute_host_source'] = hint.get('compute_host_source')
        return items, classification

    def network_history(self, server_ids):
        return self.export.network_history(server_ids)
