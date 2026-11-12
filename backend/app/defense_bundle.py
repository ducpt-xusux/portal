"""Bounded, metadata-only intake of pinned 07D archives. No extraction or upstream calls."""
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import tarfile
import tempfile
import time
import zlib

from pydantic import ValidationError

from .defense_bundle_models import (
    HOSTS, BundleIndex, ControllerManifest, DefenseArchive, DefenseArtifact,
    DefensePins, DefenseRegistrySummary, DefenseSourceRegistry, FixtureCatalog,
    ProxyManifest, VmManifest,
)
from .evidence_registry import EvidenceError, json_bytes, no_links, read_bytes


MAX_REGISTRY = 2 * 1024 * 1024
LABELS = {
    'app': ('APP_SQL', 'APP_CANARY', 'APP_AVAILABILITY'),
    'controller': ('CLONE_BEFORE', 'APP_BEFORE', 'QUARANTINE_RULES_BEFORE', 'SG_SAMPLER',
                   'CONTROLLER_WATCH', 'CLONE_AFTER', 'APP_AFTER', 'QUARANTINE_RULES_AFTER',
                   'RESTORE_VERIFICATION', 'CONTAINMENT'),
    'g07-restore-c1': ('G07_RECOVERY', 'G07_SOURCE_REPORT'),
    'galera-1': ('GALERA_HEALTH',), 'galera-2': ('GALERA_HEALTH',),
    'galera-3': ('GALERA_HEALTH',),
    'p17-lab-clone': ('CLONE_BLOCK', 'CLONE_TCP', 'CLONE_SQLI'),
    'proxy': ('PROXY_PREFLIGHT', 'APP_ALLOW_AUDIT', 'CLONE_BLOCK_AUDIT', 'HISTORICAL_CORR002',
              'NEW_CORR002_AUDIT', 'TWO_LEG_TLS', 'FAILCLOSED_HA_REPORT', 'SIXTY_FIXTURES',
              'BACKEND_HA_ISOLATED', 'F01_F02_STAGING', 'F02_AUDIT_ISOLATED'),
}
MODES = {
    'LIVE_LAB': ('LIVE', 'LAB', 'UNKNOWN'),
    'HISTORICAL_LAB': ('HISTORICAL', 'LAB', 'UNKNOWN'),
    'LIVE_PREFLIGHT': ('LIVE', 'UNKNOWN', 'PREFLIGHT'),
}
ROLES = {'app': 'APP', 'p17-lab-clone': 'CLONE', 'g07-restore-c1': 'G07_C1',
         'galera-1': 'GALERA', 'galera-2': 'GALERA', 'galera-3': 'GALERA'}


class DefenseBundleError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def fail(code):
    raise DefenseBundleError('DEFENSE_' + code)


@dataclass(frozen=True)
class Limits:
    compressed_bytes: int = 16 * 1024 * 1024
    expanded_bytes: int = 64 * 1024 * 1024
    member_bytes: int = 8 * 1024 * 1024
    metadata_bytes: int = 2 * 1024 * 1024
    member_count: int = 256
    seconds: float = 20


@dataclass(frozen=True)
class PreparedImport:
    registry: DefenseSourceRegistry
    source_root: Path
    # Operator-only paths. This object must never be serialized to an HTTP response.
    protected_inputs: tuple[tuple[Path, str, int], ...]


def utc_now():
    return datetime.now(timezone.utc)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def parse_model(raw, model):
    try:
        return model.model_validate_json(json_bytes(raw))
    except (EvidenceError, ValidationError, ValueError, TypeError, RecursionError):
        fail('INVALID_SCHEMA')


def local_path(value):
    text = str(value)
    if text.startswith(('\\\\', '//')) or '://' in text:
        fail('LOCAL_PATH_REQUIRED')
    return Path(value).absolute()


def checked_read(path, maximum):
    try:
        return read_bytes(path, maximum)
    except (EvidenceError, OSError, ValueError, RuntimeError):
        fail('SOURCE_UNAVAILABLE_OR_CHANGED')


def check_deadline(deadline):
    if time.monotonic() > deadline:
        fail('TIME_LIMIT')


def safe_member(name):
    return (bool(name) and len(name) <= 240 and '\\' not in name and ':' not in name
            and '\x00' not in name and not PurePosixPath(name).is_absolute()
            and not PureWindowsPath(name).is_absolute() and len(name.split('/')) <= 6
            and all(part not in ('', '.', '..') for part in name.split('/')))


def expand_archive(raw, limits, deadline):
    """Count every decompressed byte, including headers, padding and rejected PAX data."""
    inflater = zlib.decompressobj(31)
    chunks, size = [], 0
    try:
        for offset in range(0, len(raw), 65536):
            check_deadline(deadline)
            chunk = inflater.decompress(raw[offset:offset + 65536], limits.expanded_bytes - size + 1)
            size += len(chunk)
            if size > limits.expanded_bytes or inflater.unconsumed_tail:
                fail('EXPANDED_SIZE_LIMIT')
            chunks.append(chunk)
            if inflater.unused_data:
                fail('TRAILING_OR_CONCATENATED_GZIP')
        if not inflater.eof:
            fail('TRUNCATED_GZIP')
    except zlib.error:
        fail('INVALID_GZIP')
    check_deadline(deadline)
    return b''.join(chunks)


def archive_members(expanded, limits, deadline):
    """Read plain regular-file tar only. PAX/GNU extension records fail before expansion."""
    result, names, position = {}, set(), 0
    if len(expanded) % 512:
        fail('INVALID_TAR')
    while position + 512 <= len(expanded):
        check_deadline(deadline)
        header = expanded[position:position + 512]
        if header == b'\0' * 512:
            if position + 1024 > len(expanded) or any(expanded[position:]):
                fail('TRAILING_OR_TRUNCATED_TAR')
            return result
        try:
            info = tarfile.TarInfo.frombuf(header, 'utf-8', 'strict')
        except (tarfile.HeaderError, UnicodeError, ValueError):
            fail('INVALID_TAR_HEADER')
        if info.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or info.linkname:
            fail('TAR_MEMBER_TYPE_DENIED')
        if not safe_member(info.name):
            fail('UNSAFE_MEMBER_PATH')
        if info.name.casefold() in names:
            fail('DUPLICATE_MEMBER')
        if len(result) >= limits.member_count:
            fail('MEMBER_COUNT_LIMIT')
        if info.size < 0 or info.size > limits.member_bytes:
            fail('MEMBER_SIZE_LIMIT')
        begin, finish = position + 512, position + 512 + info.size
        position = begin + ((info.size + 511) // 512) * 512
        if position > len(expanded):
            fail('TRUNCATED_TAR_MEMBER')
        names.add(info.name.casefold())
        result[info.name] = expanded[begin:finish]
    fail('MISSING_TAR_TERMINATOR')


def artifact_id(run_id, host, label):
    key = json.dumps([run_id, host, label], ensure_ascii=True, separators=(',', ':')).encode()
    return 'EVD-' + digest(key)


def generation(registry):
    value = registry.model_dump(mode='json', exclude={'generation', 'imported_at'})
    return digest(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())


def fixture_catalog(raw, deadline):
    lines = raw.splitlines()
    if not 1 <= len(lines) <= 5000:
        fail('FIXTURE_ROW_LIMIT')
    for line in lines:
        check_deadline(deadline)
        if not line.strip() or len(line) > 65536:
            fail('FIXTURE_ROW_INVALID')
        try:
            row = json.loads(json_bytes(line))
        except EvidenceError:
            fail('FIXTURE_ROW_INVALID')
        if (not isinstance(row, dict) or row.get('fixture_execution_status') != 'NOT_EXECUTED'
                or row.get('fixture_review_status') != 'PENDING'):
            fail('FIXTURE_STATUS_UNSUPPORTED')
    return FixtureCatalog(record_count=len(lines), not_executed_count=len(lines), pending_review_count=len(lines))


def normalize_archive(raw, host, pins, limits, deadline):
    expanded = expand_archive(raw, limits, deadline)
    members = archive_members(expanded, limits, deadline)
    archive, artifacts, _, _ = _normalize_members(raw, len(expanded), members, host, pins, limits, deadline)
    return archive, artifacts


def _normalize_members(raw, expanded_size, members, host, pins, limits, deadline):
    manifest_key, index_key = host + '/manifest.json', host + '/bundle_index.json'
    if manifest_key not in members or index_key not in members:
        fail('METADATA_MISSING')
    if max(len(members[manifest_key]), len(members[index_key])) > limits.metadata_bytes:
        fail('METADATA_SIZE_LIMIT')
    index = parse_model(members[index_key], BundleIndex)
    manifest_type = {'proxy': ProxyManifest, 'controller': ControllerManifest}.get(host, VmManifest)
    manifest = parse_model(members[manifest_key], manifest_type)
    declared_host = manifest.source_vm if host in ('proxy', 'controller') else manifest.host
    if index.host != host or declared_host != host or index.run_id != pins.run_id or manifest.run_id != pins.run_id:
        fail('RUN_OR_HOST_MISMATCH')
    if manifest.result != index.manifest_result:
        fail('MANIFEST_INDEX_CONFLICT')
    if isinstance(manifest, VmManifest) and manifest.role != ROLES[host]:
        fail('ROLE_MISMATCH')
    if getattr(manifest, 'missing', []):
        fail('MANIFEST_REPORTED_MISSING')
    if isinstance(manifest, ProxyManifest):
        claims = {entry.label: entry for entry in manifest.evidence}
        if len(claims) != len(manifest.evidence):
            fail('DUPLICATE_CLAIM')
    else:
        claims = manifest.evidence
    labels = [entry.label for entry in index.files]
    paths = [entry.bundle_member.casefold() for entry in index.files]
    if len(set(labels)) != len(labels) or len(set(paths)) != len(paths):
        fail('DUPLICATE_CLAIM')
    if set(claims) != set(labels) or set(labels) != set(LABELS[host]):
        fail('ARTIFACT_SET_MISMATCH')
    if set(members) != {manifest_key, index_key, *(entry.bundle_member for entry in index.files)}:
        fail('UNLISTED_OR_MISSING_MEMBER')
    created = getattr(manifest, 'generated_at_utc', getattr(manifest, 'generated_utc', None))
    artifacts = []
    for entry in sorted(index.files, key=lambda value: value.label):
        check_deadline(deadline)
        claim = claims[entry.label]
        if not entry.bundle_member.startswith(host + '/evidence/'):
            fail('ARTIFACT_PATH_SCOPE')
        content = members[entry.bundle_member]
        if (entry.sha256 != claim.sha256 or entry.bytes != claim.bytes or entry.source_path != claim.path
                or digest(content) != entry.sha256 or len(content) != entry.bytes):
            fail('HASH_SIZE_OR_CLAIM_MISMATCH')
        if host == 'proxy' and claim.source_vm != host:
            fail('ARTIFACT_HOST_MISMATCH')
        origin = claim.execution_mode if host == 'proxy' else manifest.execution_mode
        execution, scope, kind = MODES.get(origin, (origin, 'UNKNOWN', 'UNKNOWN'))
        reasons = ['CONTENT_REVIEW_REQUIRED', 'TIMESTAMP_UNAVAILABLE']
        if created is None:
            reasons.append('MANIFEST_TIME_UNAVAILABLE')
        artifacts.append(DefenseArtifact(
            artifact_id=artifact_id(pins.run_id, host, entry.label), run_id=pins.run_id,
            source_host=host, label=entry.label, source_schema=manifest.schema_version,
            sha256=entry.sha256, size_bytes=entry.bytes, origin_mode=origin,
            execution_mode=execution, scope=scope, observation_kind=kind,
            run_context=pins.run_context, manifest_created_at=created, reason_codes=reasons,
            fixture_catalog=fixture_catalog(content, deadline) if entry.label == 'SIXTY_FIXTURES' else None,
        ))
    archive = DefenseArchive(source_host=host, archive_sha256=digest(raw), archive_size_bytes=len(raw),
                             expanded_size_bytes=expanded_size, manifest_sha256=digest(members[manifest_key]),
                             index_sha256=digest(members[index_key]), manifest_created_at=created,
                             artifact_ids=[artifact.artifact_id for artifact in artifacts])
    return archive, artifacts, manifest, index


def verified_archive_artifacts(path, registry, host, limits=Limits()):
    """Internal byte access for semantic adapters after full P0-01 receipt verification."""
    receipt = next((archive for archive in registry.archives if archive.source_host == host), None)
    if receipt is None:
        fail('ARCHIVE_RECEIPT_UNAVAILABLE')
    raw = checked_read(local_path(path), limits.compressed_bytes)
    if digest(raw) != receipt.archive_sha256:
        fail('ARCHIVE_PIN_MISMATCH')
    deadline = time.monotonic() + limits.seconds
    expanded = expand_archive(raw, limits, deadline)
    members = archive_members(expanded, limits, deadline)
    pins = DefensePins(schema_version='n91-defense-pins-1', run_id=registry.run_id,
                       run_context=registry.run_context, archives=[{'host': host, 'sha256': receipt.archive_sha256}])
    archive, artifacts, manifest, index = _normalize_members(raw, len(expanded), members, host, pins, limits, deadline)
    recorded = {a.label: a for a in registry.artifacts if a.source_host == host}
    if archive != receipt or {a.label: a for a in artifacts} != recorded:
        fail('ARCHIVE_RECEIPT_MISMATCH')
    return manifest, {entry.label: (recorded[entry.label], members[entry.bundle_member]) for entry in index.files}


def verify_inputs(prepared):
    for path, expected, maximum in prepared.protected_inputs:
        if digest(checked_read(path, maximum)) != expected:
            fail('SOURCE_CHANGED')


def build_registry(source_root, pins_path, limits=Limits()):
    root, pin_path = local_path(source_root), local_path(pins_path)
    deadline = time.monotonic() + limits.seconds
    try:
        no_links(root)
        root = root.resolve(strict=True)
        if not root.is_dir():
            fail('SOURCE_ROOT_REQUIRED')
        pin_raw = checked_read(pin_path, 128 * 1024)
        pins = parse_model(pin_raw, DefensePins)
        archives, artifacts, total = [], [], 0
        protected = [(pin_path, digest(pin_raw), 128 * 1024)]
        for pin in sorted(pins.archives, key=lambda value: value.host):
            check_deadline(deadline)
            path = root / ('07D_bundle_' + pin.host + '.tar.gz')
            raw = checked_read(path, limits.compressed_bytes)
            if digest(raw) != pin.sha256:
                fail('ARCHIVE_PIN_MISMATCH')
            archive, rows = normalize_archive(raw, pin.host, pins, limits, deadline)
            total += archive.expanded_size_bytes
            if total > limits.expanded_bytes:
                fail('TOTAL_EXPANDED_SIZE_LIMIT')
            archives.append(archive)
            artifacts.extend(rows)
            protected.append((path, pin.sha256, limits.compressed_bytes))
        missing = sorted(set(HOSTS) - {archive.source_host for archive in archives})
        model = DefenseSourceRegistry(
            generation='0' * 64, run_id=pins.run_id, run_context=pins.run_context,
            imported_at=utc_now(), archives=archives, artifacts=artifacts, missing_hosts=missing,
            overall_status='PARTIAL' if missing else 'COMPLETE',
        )
        model = model.model_copy(update={'generation': generation(model)})
        prepared = PreparedImport(model, root, tuple(protected))
        verify_inputs(prepared)
        check_deadline(deadline)
        return prepared
    except (EvidenceError, OSError, ValueError, RuntimeError, KeyError, TypeError):
        fail('SOURCE_UNAVAILABLE_OR_INVALID')


def validate_registry(raw):
    registry = parse_model(raw, DefenseSourceRegistry)
    if generation(registry) != registry.generation:
        fail('GENERATION_MISMATCH')
    for archive in registry.archives:
        rows = [a for a in registry.artifacts if a.source_host == archive.source_host]
        if {row.label for row in rows} != set(LABELS[archive.source_host]):
            fail('ARTIFACT_SET_MISMATCH')
        if any(row.manifest_created_at != archive.manifest_created_at for row in rows):
            fail('MANIFEST_TIME_CONFLICT')
        schema = {'proxy': 'n91-cli-evidence-manifest-v1', 'controller': 'n91-controller-evidence-v1'}.get(
            archive.source_host, 'n91-vm-evidence-manifest-v1')
        if any(row.source_schema != schema for row in rows):
            fail('MANIFEST_SCHEMA_CONFLICT')
    for artifact in registry.artifacts:
        if (artifact.label == 'SIXTY_FIXTURES') != (artifact.fixture_catalog is not None):
            fail('FIXTURE_CATALOG_CONFLICT')
        if artifact.artifact_id != artifact_id(artifact.run_id, artifact.source_host, artifact.label):
            fail('ARTIFACT_ID_MISMATCH')
        execution, scope, kind = MODES.get(artifact.origin_mode, (artifact.origin_mode, 'UNKNOWN', 'UNKNOWN'))
        if (artifact.execution_mode, artifact.scope, artifact.observation_kind) != (execution, scope, kind):
            fail('MODE_MAPPING_MISMATCH')
        reasons = ['CONTENT_REVIEW_REQUIRED', 'TIMESTAMP_UNAVAILABLE']
        if artifact.manifest_created_at is None:
            reasons.append('MANIFEST_TIME_UNAVAILABLE')
        if artifact.reason_codes != reasons:
            fail('TEMPORAL_REASON_MISMATCH')
    return registry


def destination_path(prepared, destination):
    path = local_path(destination)
    try:
        no_links(path.parent)
        parent = path.parent.resolve(strict=True)
        path = parent / path.name
        if path.is_relative_to(prepared.source_root) or prepared.source_root.is_relative_to(parent):
            fail('DESTINATION_SOURCE_OVERLAP')
        if path.exists() or path.is_symlink():
            no_links(path)
        for source, _, _ in prepared.protected_inputs:
            if path == source.resolve() or (path.exists() and path.samefile(source)):
                fail('DESTINATION_SOURCE_ALIAS')
        return path
    except (EvidenceError, OSError, ValueError, RuntimeError):
        fail('DESTINATION_UNAVAILABLE')


def publish_registry(prepared, destination):
    """Publish one full snapshot. Failure preserves last good; input paths stay operator-only."""
    path = destination_path(prepared, destination)
    lock = path.with_name(path.name + '.import-lock')
    temporary, descriptor = None, None
    try:
        try:
            descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            fail('IMPORT_BUSY')
        model = validate_registry(prepared.registry.model_dump_json().encode())
        verify_inputs(prepared)
        if path.exists():
            old, _ = DefenseRegistry(path).read()
            if old.run_id != model.run_id or old.run_context != model.run_context:
                fail('RUN_CONFLICT')
            new_artifacts = {row.artifact_id: row for row in model.artifacts}
            new_archives = {row.source_host: row for row in model.archives}
            for row in old.artifacts:
                if row.artifact_id not in new_artifacts:
                    fail('PARTIAL_REPLACEMENT')
                if row != new_artifacts[row.artifact_id]:
                    fail('ARTIFACT_CONFLICT')
            for row in old.archives:
                if row.source_host not in new_archives:
                    fail('PARTIAL_REPLACEMENT')
                if row != new_archives[row.source_host]:
                    fail('ARCHIVE_CONFLICT')
            if old.generation == model.generation:
                return 'UNCHANGED'
        encoded = model.model_dump_json(indent=2).encode()
        if len(encoded) > MAX_REGISTRY:
            fail('REGISTRY_SIZE_LIMIT')
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.defense-', delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        destination_path(prepared, path)
        verify_inputs(prepared)
        os.replace(temporary, path)
        return 'PUBLISHED'
    except OSError:
        fail('PUBLISH_UNAVAILABLE')
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
        if descriptor is not None:
            try:
                os.close(descriptor)
                lock.unlink(missing_ok=True)
            except OSError:
                pass  # A leftover lock fails the next import closed; never expose cleanup paths.


class DefenseRegistry:
    def __init__(self, path):
        self.path = path

    def read(self):
        if self.path is None:
            fail('REGISTRY_NOT_CONFIGURED')
        raw = checked_read(local_path(self.path), MAX_REGISTRY)
        return validate_registry(raw), digest(raw)


def summarize_registry(registry, registry_sha256, read_at=None):
    reasons = ['CONTENT_REVIEW_REQUIRED', 'TIMESTAMP_UNAVAILABLE']
    if registry.missing_hosts:
        reasons.append('HOST_BUNDLE_MISSING')
    return DefenseRegistrySummary(
        source_ref='sha256:' + registry_sha256, generation=registry.generation,
        run_id=registry.run_id, run_context=registry.run_context, overall_status=registry.overall_status,
        archive_count=len(registry.archives), artifact_count=len(registry.artifacts),
        missing_hosts=registry.missing_hosts, read_at=read_at or utc_now(),
        imported_at=registry.imported_at, reason_codes=reasons,
    )
