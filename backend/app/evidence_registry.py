"""Offline import and metadata registry; never writes to the source bundle."""
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import stat
import tempfile
from pydantic import ValidationError
from .evidence_models import Manifest, Summary, Index, IndexedArtifact

MAX_JSON = 2 * 1024 * 1024
MAX_TOTAL = 16 * 1024 * 1024


class EvidenceError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)  # Never include source content or paths.


def now():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def no_links(path):
    """Reject symlinks and Windows junction/reparse components, including ancestors."""
    path = Path(path).absolute()
    for part in [*reversed(path.parents), path]:
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise EvidenceError('EVIDENCE_UNSAFE_PATH')
    return path


def bounded_path(root, relative):
    if not isinstance(relative, str) or '\\' in relative or ':' in relative or '\x00' in relative:
        raise EvidenceError('EVIDENCE_UNSAFE_PATH')
    rel = Path(relative)
    if rel.is_absolute() or PureWindowsPath(relative).is_absolute() or any(p in ('', '.', '..') for p in relative.split('/')):
        raise EvidenceError('EVIDENCE_UNSAFE_PATH')
    base = no_links(root).resolve(strict=True)
    candidate = no_links(base / rel).resolve(strict=True)
    if not candidate.is_relative_to(base) or not candidate.is_file():
        raise EvidenceError('EVIDENCE_UNSAFE_PATH')
    return candidate


def read_bytes(path, limit):
    # Read through a bounded handle; reject source rotation during validation.
    path = no_links(path)
    with path.open('rb') as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise EvidenceError('EVIDENCE_SIZE_LIMIT')
        value = handle.read(limit + 1)
        after = os.fstat(handle.fileno())
    no_links(path)
    current = path.stat()
    if len(value) > limit:
        raise EvidenceError('EVIDENCE_SIZE_LIMIT')
    if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns) or (current.st_ino, current.st_size, current.st_mtime_ns) != (before.st_ino, before.st_size, before.st_mtime_ns):
        raise EvidenceError('EVIDENCE_SOURCE_CHANGED')
    return value


def json_bytes(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise EvidenceError('EVIDENCE_DUPLICATE_KEY')
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        def depth(item, level=0):
            if level > 12:
                raise EvidenceError('EVIDENCE_DEPTH_LIMIT')
            if isinstance(item, dict):
                for child in item.values():
                    depth(child, level + 1)
            elif isinstance(item, list):
                for child in item:
                    depth(child, level + 1)
        depth(value)
        return json.dumps(value, separators=(',', ':'), ensure_ascii=True)
    except (ValueError, UnicodeError, RecursionError):
        raise EvidenceError('EVIDENCE_INVALID_JSON') from None


def load_model(raw, model):
    try:
        return model.model_validate_json(json_bytes(raw))
    except ValidationError:
        raise EvidenceError('EVIDENCE_INVALID_SCHEMA') from None


def build_index(root, manifest_relative='manifest.json'):
    try:
        manifest_raw = read_bytes(bounded_path(root, manifest_relative), MAX_JSON)
        manifest = load_model(manifest_raw, Manifest)
        imported_at = now()
        artifacts, total = [], len(manifest_raw)
        for artifact in manifest.artifacts:
            raw = read_bytes(bounded_path(root, artifact.relative_path), 1024 * 1024)
            total += len(raw)
            if total > MAX_TOTAL:
                raise EvidenceError('EVIDENCE_BUNDLE_SIZE_LIMIT')
            if len(raw) != artifact.size_bytes or digest(raw) != artifact.sha256:
                raise EvidenceError('EVIDENCE_HASH_MISMATCH')
            summary = None
            if artifact.sanitization_state == 'SANITIZED':
                if artifact.evidence_kind not in {'SCENE_SUMMARY', 'ACTION_SUMMARY', 'RECOVERY_SUMMARY'}:
                    raise EvidenceError('EVIDENCE_SANITIZATION_UNSUPPORTED')
                summary = load_model(raw, Summary)
                if summary.run_id != artifact.run_id or summary.entity != artifact.entity or set(summary.scene_ids) != set(artifact.scene_ids):
                    raise EvidenceError('EVIDENCE_SCOPE_MISMATCH')
            artifacts.append({**artifact.model_dump(mode='json', exclude={'relative_path'}),
                              'integrity': 'BYTE_HASH_MATCH', 'imported_at': imported_at,
                              'summary': summary.model_dump(mode='json') if summary else None})
        return load_model(json.dumps({'schema_version': 'portal-evidence-index-1',
            'manifest_sha256': digest(manifest_raw), 'imported_at': imported_at,
            'runs': [r.model_dump(mode='json') for r in manifest.runs], 'artifacts': artifacts,
            'observations': [o.model_dump(mode='json') for o in manifest.observations]}).encode(), Index)
    except (OSError, ValueError, RuntimeError):
        raise EvidenceError('EVIDENCE_SOURCE_UNAVAILABLE') from None


def publish(index, destination):
    """One publisher per index. A concurrent import fails closed instead of losing a generation."""
    destination = Path(destination).absolute()
    lock = destination.with_name(destination.name + '.import-lock')
    descriptor = None
    try:
        no_links(destination.parent)
        try:
            descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            raise EvidenceError('EVIDENCE_IMPORT_BUSY') from None
        return _publish(index, destination)
    except OSError:
        raise EvidenceError('EVIDENCE_PUBLISH_UNAVAILABLE') from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
                lock.unlink()
            except OSError:
                pass  # Do not leak cleanup paths; a leftover lock fails the next import closed.


def _publish(index, destination):
    """Complete validated snapshot, atomic replacement, immutable identities, idempotent repeat."""
    destination = Path(destination).absolute()
    temporary = None
    try:
        no_links(destination.parent)
        if destination.exists():
            old = load_model(read_bytes(destination, MAX_JSON), Index)
            old_ids = {a.evidence_id: a for a in old.artifacts}
            old_runs = {r.run_id: r for r in old.runs}
            old_observations = {(o.run_id, o.scenario_id): o for o in old.observations}
            new_observations = {(o.run_id, o.scenario_id): o for o in index.observations}
            for artifact in index.artifacts:
                previous = old_ids.get(artifact.evidence_id)
                if previous and previous.model_dump(exclude={'imported_at'}) != artifact.model_dump(exclude={'imported_at'}):
                    raise EvidenceError('EVIDENCE_ID_CONFLICT')
            if any(r.run_id in old_runs and old_runs[r.run_id] != r for r in index.runs):
                raise EvidenceError('EVIDENCE_RUN_CONFLICT')
            if any(key not in new_observations or new_observations[key] != value for key, value in old_observations.items()):
                raise EvidenceError('EVIDENCE_OBSERVATION_CONFLICT')
            # A publish is a full snapshot; accidental partial bundles cannot remove last-good.
            if not set(old_ids).issubset(a.evidence_id for a in index.artifacts) or not set(old_runs).issubset(r.run_id for r in index.runs):
                raise EvidenceError('EVIDENCE_PARTIAL_REPLACEMENT')
            if old.manifest_sha256 == index.manifest_sha256:
                return 'UNCHANGED'
        encoded = index.model_dump_json(indent=2).encode()
        if len(encoded) > MAX_JSON:
            raise EvidenceError('EVIDENCE_SIZE_LIMIT')
        with tempfile.NamedTemporaryFile(dir=destination.parent, prefix='.evidence-', delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        no_links(destination.parent)
        if destination.exists():
            no_links(destination)
        os.replace(temporary, destination)
        return 'PUBLISHED'
    except OSError:
        raise EvidenceError('EVIDENCE_PUBLISH_UNAVAILABLE') from None
    finally:
        if temporary is not None and temporary.exists():
            try:
                temporary.unlink()
            except OSError:
                pass


@dataclass(frozen=True)
class EvidenceConfig:
    index_path: Path | None = None
    local_readonly: bool = False


class EvidenceRegistry:
    def __init__(self, config):
        self.config = config

    def read(self):
        if self.config.index_path is None:
            raise EvidenceError('EVIDENCE_SOURCE_NOT_CONFIGURED')
        try:
            raw = read_bytes(self.config.index_path, MAX_JSON)
            return load_model(raw, Index), digest(raw)
        except (OSError, ValueError, RuntimeError):
            raise EvidenceError('EVIDENCE_SOURCE_UNAVAILABLE') from None
