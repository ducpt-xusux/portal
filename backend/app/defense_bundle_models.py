"""Closed metadata contracts for operator-side N91 defense evidence intake."""
from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, model_validator

from .evidence_models import Closed, Id, Sha

Host = Literal['app', 'controller', 'g07-restore-c1', 'galera-1', 'galera-2',
               'galera-3', 'p17-lab-clone', 'proxy']
HOSTS = ('app', 'controller', 'g07-restore-c1', 'galera-1', 'galera-2', 'galera-3',
         'p17-lab-clone', 'proxy')
OriginMode = Literal['LIVE', 'LIVE_LAB', 'HISTORICAL', 'HISTORICAL_LAB',
                     'LIVE_PREFLIGHT', 'ISOLATED', 'STAGING', 'OFFLINE', 'UNKNOWN']
Context = Literal['TEST', 'IMPORTED_UNVERIFIED']
Label = Annotated[str, Field(pattern=r'^[A-Z][A-Z0-9_]{0,79}$')]
SmallPath = Annotated[str, Field(min_length=1, max_length=1024)]


class ArchivePin(Closed):
    host: Host
    sha256: Sha


class DefensePins(Closed):
    schema_version: Literal['n91-defense-pins-1']
    run_id: Id
    run_context: Context
    archives: list[ArchivePin] = Field(min_length=1, max_length=8)

    @model_validator(mode='after')
    def unique(self):
        if len({entry.host for entry in self.archives}) != len(self.archives):
            raise ValueError('DUPLICATE_HOST')
        if self.run_context != 'TEST' and self.run_id.upper().startswith('TEST'):
            raise ValueError('TEST_CONTEXT_REQUIRED')
        return self


class FileClaim(Closed):
    path: SmallPath
    bytes: int = Field(ge=0, le=8 * 1024 * 1024)
    sha256: Sha


class IndexedClaim(Closed):
    label: Label
    source_path: SmallPath
    bundle_member: SmallPath
    bytes: int = Field(ge=0, le=8 * 1024 * 1024)
    sha256: Sha


class BundleIndex(Closed):
    schema_version: Literal['n91-evidence-bundle-v1'] = Field(alias='schema')
    host: Host
    run_id: Id
    manifest_result: Literal['PASS', 'FAIL', 'INCOMPLETE', 'UNKNOWN']
    files: list[IndexedClaim] = Field(min_length=1, max_length=128)


class VmManifest(Closed):
    schema_version: Literal['n91-vm-evidence-manifest-v1'] = Field(alias='schema')
    run_id: Id
    host: Host
    role: Literal['APP', 'CLONE', 'GALERA', 'G07_C1']
    execution_mode: OriginMode
    generated_at_utc: AwareDatetime
    evidence: dict[Label, FileClaim] = Field(min_length=1, max_length=128)
    checks: dict[Label, bool] = Field(max_length=64)
    missing: list[Label] = Field(max_length=128)
    result: Literal['PASS', 'FAIL', 'INCOMPLETE', 'UNKNOWN']


class ControllerManifest(Closed):
    schema_version: Literal['n91-controller-evidence-v1'] = Field(alias='schema')
    run_id: Id
    source_vm: Literal['controller']
    incident_id: Id
    execution_mode: OriginMode
    evidence: dict[Label, FileClaim] = Field(min_length=1, max_length=128)
    checks: dict[Label, bool] = Field(max_length=64)
    sg_transitions: list[Annotated[str, Field(max_length=256)]] = Field(max_length=32)
    quarantine_duration_seconds: float = Field(ge=0, le=86400, allow_inf_nan=False)
    result: Literal['PASS', 'FAIL', 'INCOMPLETE', 'UNKNOWN']


class ProxyClaim(FileClaim):
    label: Label
    source_vm: Literal['proxy']
    execution_mode: OriginMode


class ProxyManifest(Closed):
    schema_version: Literal['n91-cli-evidence-manifest-v1'] = Field(alias='schema')
    run_id: Id
    generated_utc: AwareDatetime
    source_vm: Literal['proxy']
    incident_id: Id
    correlation_rule: Literal['CORR-002']
    event_sequences: list[Annotated[int, Field(ge=0)]] = Field(max_length=128)
    event_link_type: Literal['RECONSTRUCTED_WINDOW']
    checks: dict[Label, bool] = Field(max_length=64)
    evidence: list[ProxyClaim] = Field(min_length=1, max_length=128)
    missing: list[Label] = Field(max_length=128)
    result: Literal['PASS', 'FAIL', 'INCOMPLETE', 'UNKNOWN']
    remote_vm_evidence: Annotated[str, Field(max_length=1024)]


class FixtureCatalog(Closed):
    record_count: int = Field(ge=1, le=5000)
    not_executed_count: int = Field(ge=0, le=5000)
    pending_review_count: int = Field(ge=0, le=5000)

    @model_validator(mode='after')
    def unexecuted_only(self):
        if self.record_count != self.not_executed_count or self.record_count != self.pending_review_count:
            raise ValueError('FIXTURE_EXECUTION_UNSUPPORTED')
        return self


class DefenseArtifact(Closed):
    artifact_id: Annotated[str, Field(pattern=r'^EVD-[a-f0-9]{64}$')]
    run_id: Id
    source_host: Host
    label: Label
    source_schema: Literal['n91-vm-evidence-manifest-v1', 'n91-controller-evidence-v1',
                           'n91-cli-evidence-manifest-v1']
    sha256: Sha
    size_bytes: int = Field(ge=0, le=8 * 1024 * 1024)
    origin_mode: OriginMode
    execution_mode: Literal['LIVE', 'HISTORICAL', 'ISOLATED', 'STAGING', 'OFFLINE', 'UNKNOWN']
    scope: Literal['LAB', 'UNKNOWN']
    observation_kind: Literal['PREFLIGHT', 'UNKNOWN']
    run_context: Context
    manifest_created_at: AwareDatetime | None
    captured_at: None = None
    observed_at: None = None
    data_as_of: None = None
    timestamp_basis: Literal['UNAVAILABLE'] = 'UNAVAILABLE'
    integrity: Literal['BYTE_HASH_MATCH'] = 'BYTE_HASH_MATCH'
    sanitization_state: Literal['WITHHELD'] = 'WITHHELD'
    content_review: Literal['REQUIRED'] = 'REQUIRED'
    reason_codes: list[Literal['TIMESTAMP_UNAVAILABLE', 'MANIFEST_TIME_UNAVAILABLE',
                               'CONTENT_REVIEW_REQUIRED']] = Field(min_length=2, max_length=3)
    fixture_catalog: FixtureCatalog | None = None


class DefenseArchive(Closed):
    source_host: Host
    archive_sha256: Sha
    archive_size_bytes: int = Field(ge=0, le=16 * 1024 * 1024)
    expanded_size_bytes: int = Field(ge=0, le=64 * 1024 * 1024)
    manifest_sha256: Sha
    index_sha256: Sha
    manifest_created_at: AwareDatetime | None
    artifact_ids: list[Annotated[str, Field(pattern=r'^EVD-[a-f0-9]{64}$')]] = Field(min_length=1, max_length=128)


class DefenseSourceRegistry(Closed):
    schema_version: Literal['n91-defense-source-registry-1'] = 'n91-defense-source-registry-1'
    generation: Sha
    run_id: Id
    run_context: Context
    imported_at: AwareDatetime
    archives: list[DefenseArchive] = Field(min_length=1, max_length=8)
    artifacts: list[DefenseArtifact] = Field(min_length=1, max_length=1024)
    missing_hosts: list[Host] = Field(max_length=8)
    overall_status: Literal['COMPLETE', 'PARTIAL']
    source_access: Literal['HISTORICAL'] = 'HISTORICAL'
    coverage_kind: Literal['SUPPLIED_BUNDLES_ONLY'] = 'SUPPLIED_BUNDLES_ONLY'
    content_review: Literal['REQUIRED'] = 'REQUIRED'
    scene_observation_count: Literal[0] = 0

    @model_validator(mode='after')
    def population(self):
        hosts = [archive.source_host for archive in self.archives]
        ids = [artifact.artifact_id for artifact in self.artifacts]
        identities = [(a.run_id, a.source_host, a.label) for a in self.artifacts]
        if len(set(hosts)) != len(hosts) or len(set(ids)) != len(ids) or len(set(identities)) != len(identities):
            raise ValueError('DUPLICATE_SOURCE')
        if self.missing_hosts != sorted(set(HOSTS) - set(hosts)):
            raise ValueError('MISSING_HOSTS_CONFLICT')
        if self.overall_status != ('PARTIAL' if self.missing_hosts else 'COMPLETE'):
            raise ValueError('COVERAGE_CONFLICT')
        for archive in self.archives:
            members = [a.artifact_id for a in self.artifacts if a.source_host == archive.source_host]
            if members != archive.artifact_ids:
                raise ValueError('ARCHIVE_ARTIFACT_CONFLICT')
        if any(a.source_host not in hosts or a.run_id != self.run_id or a.run_context != self.run_context for a in self.artifacts):
            raise ValueError('ARTIFACT_SCOPE_CONFLICT')
        return self


class DefenseRegistrySummary(Closed):
    source_system: Literal['N91 defense source registry'] = 'N91 defense source registry'
    source_schema: Literal['n91-defense-source-registry-1'] = 'n91-defense-source-registry-1'
    source_mode: Literal['OFFLINE_METADATA_ONLY'] = 'OFFLINE_METADATA_ONLY'
    source_ref: str
    generation: Sha
    run_id: Id
    run_context: Context
    freshness_state: Literal['HISTORICAL'] = 'HISTORICAL'
    overall_status: Literal['COMPLETE', 'PARTIAL']
    archive_count: int
    artifact_count: int
    missing_hosts: list[Host]
    coverage_complete: Literal[False] = False
    content_review: Literal['REQUIRED'] = 'REQUIRED'
    data_as_of: None = None
    observed_at: None = None
    read_at: AwareDatetime
    imported_at: AwareDatetime
    reason_codes: list[Literal['CONTENT_REVIEW_REQUIRED', 'TIMESTAMP_UNAVAILABLE', 'HOST_BUNDLE_MISSING']]
