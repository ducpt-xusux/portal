"""Bounded, pinned, read-only file readers and explicit adapter boundaries."""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Callable
from pydantic import ValidationError

from .models import ControllerBundle, CurrentObservation, PolicySnapshot, SourceStamp

MAX_BYTES = 2 * 1024 * 1024
MAX_NODES = 24000


class SourceError(Exception):
    def __init__(self, code="INVESTIGATION_SOURCE_UNAVAILABLE", status=503):
        self.code = code if isinstance(code, str) and re.fullmatch(r'[A-Z0-9_]{1,80}', code) else 'INVESTIGATION_SOURCE_INVALID'
        self.status = status if status in {400, 401, 403, 404, 409, 422, 503, 504} else 503
        super().__init__(self.code)


def bounded(value):
    remaining = MAX_NODES
    seen = set()

    def visit(item, depth=0):
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or depth > 12:
            raise SourceError("INVESTIGATION_SOURCE_LIMIT")
        if isinstance(item, (dict, list)):
            if id(item) in seen:
                raise SourceError("INVESTIGATION_SOURCE_ALIAS")
            seen.add(id(item))
        if isinstance(item, dict):
            if len(item) > 100:
                raise SourceError("INVESTIGATION_SOURCE_LIMIT")
            for key, child in item.items():
                if not isinstance(key, str) or len(key) > 160:
                    raise SourceError("INVESTIGATION_SOURCE_INVALID")
                if key.lower() in {"raw_sql", "query_raw", "query", "sql", "original_sql", "password", "token", "private_key", "authorization", "openrc"}:
                    raise SourceError("INVESTIGATION_PRIVACY_REJECTED")
                visit(child, depth + 1)
        elif isinstance(item, list):
            if len(item) > 512:
                raise SourceError("INVESTIGATION_SOURCE_LIMIT")
            for child in item:
                visit(child, depth + 1)
        elif isinstance(item, str):
            if len(item) > 16384 or any(ord(c) < 32 and c not in '\r\n\t' for c in item):
                raise SourceError("INVESTIGATION_SOURCE_LIMIT")
        elif item is not None and type(item) not in {bool, int, float}:
            raise SourceError("INVESTIGATION_SOURCE_INVALID")
        elif isinstance(item, float):
            import math
            if not math.isfinite(item):
                raise SourceError("INVESTIGATION_SOURCE_INVALID")
    visit(value)
    return value


def pairs_unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SourceError("INVESTIGATION_DUPLICATE_KEY")
        result[key] = value
    return result


def decode_json(raw):
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise SourceError("INVESTIGATION_SOURCE_LIMIT")
    try:
        value = json.loads(raw, object_pairs_hook=pairs_unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        return bounded(value)
    except SourceError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise SourceError("INVESTIGATION_SOURCE_INVALID") from None


def decode_yaml(raw):
    """Safe YAML if PyYAML is supplied by the host; JSON-compatible YAML otherwise.

    No repo dependency is modified. Ordinary YAML without that decoder is typed
    unavailable. Alias/tags/duplicate keys fail closed; no YAML object construction.
    """
    try:
        return decode_json(raw)
    except SourceError as error:
        if error.code != "INVESTIGATION_SOURCE_INVALID":
            raise
    try:
        import yaml
    except ImportError:
        raise SourceError("POLICY_YAML_DECODER_UNAVAILABLE") from None
    try:
        for index, token in enumerate(yaml.scan(raw)):
            if index >= MAX_NODES * 2:
                raise SourceError("INVESTIGATION_SOURCE_LIMIT")
            if isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken, yaml.tokens.TagToken)):
                raise SourceError("POLICY_YAML_UNSUPPORTED")

        class UniqueSafeLoader(yaml.SafeLoader):
            pass

        def mapping(loader, node):
            return pairs_unique([(loader.construct_object(k), loader.construct_object(v)) for k, v in node.value])
        UniqueSafeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
        return bounded(yaml.load(raw, Loader=UniqueSafeLoader))
    except SourceError:
        raise
    except Exception:
        raise SourceError("POLICY_YAML_INVALID") from None


def validate(model, value):
    try:
        bounded(value)
        return model.model_validate(value)
    except SourceError:
        raise
    except (ValidationError, ValueError, TypeError, RecursionError):
        raise SourceError("INVESTIGATION_SCHEMA_UNSUPPORTED") from None


@dataclass(frozen=True)
class PinnedFile:
    path: Path
    sha256: str
    max_bytes: int = MAX_BYTES

    def read(self):
        if len(self.sha256) != 64 or any(c not in '0123456789abcdef' for c in self.sha256):
            raise SourceError("INVESTIGATION_PIN_REQUIRED")
        if type(self.max_bytes) is not int or self.max_bytes < 1:
            raise SourceError("INVESTIGATION_SOURCE_LIMIT")
        try:
            if self.path.is_symlink() or not self.path.is_file():
                raise SourceError("INVESTIGATION_SOURCE_UNAVAILABLE")
            with self.path.open('rb') as handle:
                raw = handle.read(min(MAX_BYTES, self.max_bytes) + 1)
        except OSError:
            raise SourceError("INVESTIGATION_SOURCE_UNAVAILABLE") from None
        if len(raw) > min(MAX_BYTES, self.max_bytes):
            raise SourceError("INVESTIGATION_SOURCE_LIMIT")
        if hashlib.sha256(raw).hexdigest() != self.sha256:
            raise SourceError("CURRENT_VERSION_MISMATCH")
        return raw


@dataclass(frozen=True)
class PolicyReader:
    pinned: PinnedFile
    expected_version: str
    expected_rule_count: int = 40
    # Real native YAML adapter must be reviewed against actual bytes. The default
    # accepts only the published sanitized investigation-policy-1 local profile.
    adapter: Callable = decode_yaml

    def read(self):
        snapshot = validate(PolicySnapshot, self.adapter(self.pinned.read()))
        if snapshot.policy_version != self.expected_version or len(snapshot.rules) != self.expected_rule_count:
            raise SourceError("CURRENT_VERSION_MISMATCH")
        return snapshot, self.pinned.sha256


@dataclass(frozen=True)
class ControllerReader:
    pinned: PinnedFile
    adapter: Callable = decode_json

    def read(self):
        return validate(ControllerBundle, self.adapter(self.pinned.read()))


def canonical_event_loader(request, event_id, stream_id):
    """Reuse agent 1's canonical normalizer/store; never read raw audit ourselves."""
    from ..canonical_audit import detail
    return detail(request, event_id, stream_id)['data']


def snapshot_incident_loader(request, incident_id):
    """Reuse existing P17 reader and its typed source rows; no direct DB access."""
    from ..p17_snapshot import SnapshotError
    try:
        snapshot, _ = request.app.state.p17_reader.read()
    except (SnapshotError, AttributeError):
        raise SourceError("P17_SOURCE_UNAVAILABLE") from None
    rows = [row for row in snapshot.incidents if row.incident_id == incident_id]
    if not rows:
        raise SourceError("INCIDENT_NOT_FOUND", 404)
    if len(rows) != 1:
        raise SourceError("INCIDENT_ID_AMBIGUOUS", 409)
    return rows[0].model_dump(mode='json')


def inventory_observation_loader(request, cycle):
    """Adapt existing read-only InventoryReader; accept one exact project/port/VM.

    read_mapping_inventory includes detached ports. Stale cache is not current.
    No OpenStack transport, token or mutation method is exposed to this module.
    """
    try:
        _, ports, meta, _ = request.app.state.openstack_inventory.read_mapping_inventory()
        if meta.get('freshness_state') != 'FRESH' or meta.get('source_mode') != 'LIVE':
            raise SourceError("NEUTRON_CURRENT_UNAVAILABLE")
        matches = [p for p in ports if p.get('port_id') == cycle.containment.port_id]
        if len(matches) != 1:
            raise SourceError("NEUTRON_PORT_AMBIGUOUS")
        port = matches[0]
        observed = datetime.fromisoformat(port['observed_at'].replace('Z', '+00:00'))
        # Use earliest collection time to bound a multi-request observation.
        started = datetime.fromisoformat(meta['observation_from'].replace('Z', '+00:00'))
        ttl = meta['stale_after_seconds']
        if type(ttl) is not int or ttl < 1 or ttl > 300:
            raise SourceError("NEUTRON_CURRENT_UNAVAILABLE")
        return CurrentObservation(schema_version='investigation-neutron-1',
            source=SourceStamp(source_system='NEUTRON', source_ref=meta['source_ref'],
                source_schema='openstack-inventory-1', execution_mode='LIVE',
                observed_at=observed, freshness_state='FRESH', verification='SOURCE_REPORTED'),
            project_id=port['project_id'], port_id=port['port_id'], server_id=port['device_id'],
            security_group_ids=port['security_group_ids'], observed_at=observed,
            fixed_ips=[row['ip_address'] for row in port['fixed_ips']],
            floating_ips=[row['floating_ip_address'] for row in port['floating_ips']],
            expires_at=started + timedelta(seconds=ttl)).model_dump(mode='json')
    except SourceError:
        raise
    except Exception:
        raise SourceError("NEUTRON_CURRENT_UNAVAILABLE") from None
