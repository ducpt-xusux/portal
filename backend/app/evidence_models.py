"""Bounded, closed schemas for offline evidence. No free-form source payloads."""
from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field, AwareDatetime, model_validator

Id = Annotated[str, Field(min_length=1, max_length=100, pattern=r'^[A-Za-z0-9][A-Za-z0-9_.:-]*$')]
Sha = Annotated[str, Field(pattern=r'^[a-f0-9]{64}$')]
Scene = Annotated[str, Field(pattern=r'^SC-(0[1-9]|1[0-6])$')]
Mode = Literal['LIVE', 'ISOLATED', 'STAGING', 'HISTORICAL', 'DESIGN_ONLY', 'OFFLINE']
Verdict = Literal['PASS', 'FAIL', 'INCOMPLETE', 'NOT_EXECUTED', 'UNKNOWN', 'NA']
Outcome = Literal['ALLOW', 'BLOCK', 'REVIEW_REQUIRED', 'QUARANTINED', 'RESTORED', 'VERIFIED', 'FAILED', 'NOT_VERIFIED', 'NOT_CAPTURED']


class Closed(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)


class Run(Closed):
    run_id: Id
    context: Literal['TEST', 'EVALUATION', 'LIVE']
    data_as_of: AwareDatetime


class Entity(Closed):
    entity_type: Literal['RUN', 'EVENT', 'INCIDENT', 'ACTION', 'RESTORE']
    entity_id: Id


class Artifact(Closed):
    evidence_id: Id
    run_id: Id
    source_system: Literal['PROXY', 'CONTROLLER', 'G07', 'TEST']
    source_host: Id
    evidence_kind: Literal['SCENE_SUMMARY', 'ACTION_SUMMARY', 'RECOVERY_SUMMARY', 'SCREENSHOT', 'OTHER_WITHHELD']
    entity: Entity
    scene_ids: list[Scene] = Field(max_length=16)
    captured_at: AwareDatetime
    sanitization_state: Literal['SANITIZED', 'WITHHELD']
    sha256: Sha
    original_sha256: Sha | None = None
    size_bytes: int = Field(ge=0, le=1024 * 1024)


class InputArtifact(Artifact):
    relative_path: str = Field(min_length=1, max_length=240)


class Summary(Closed):
    schema_version: Literal['portal-sanitized-summary-1']
    run_id: Id
    scene_ids: list[Scene] = Field(max_length=16)
    entity: Entity
    outcome: Outcome
    execution_mode: Mode


class Observation(Closed):
    run_id: Id
    scenario_id: Scene
    execution_modes: list[Mode] = Field(min_length=1, max_length=6)
    outcome: Outcome
    verdict: Verdict
    evidence_refs: list[Id] = Field(max_length=30)
    evaluated_at: AwareDatetime


class Manifest(Closed):
    schema_version: Literal['portal-evidence-bundle-1']
    runs: list[Run] = Field(min_length=1, max_length=32)
    artifacts: list[InputArtifact] = Field(max_length=1000)
    observations: list[Observation] = Field(max_length=512)

    @model_validator(mode='after')
    def unique_and_scoped(self):
        run_ids = [r.run_id for r in self.runs]
        ids = [a.evidence_id for a in self.artifacts]
        keys = [(o.run_id, o.scenario_id) for o in self.observations]
        if len(set(run_ids)) != len(run_ids) or len(set(ids)) != len(ids) or len(set(keys)) != len(keys):
            raise ValueError('DUPLICATE_ID')
        if any(a.run_id not in run_ids for a in self.artifacts) or any(o.run_id not in run_ids for o in self.observations):
            raise ValueError('UNKNOWN_RUN')
        if any(len(set(a.scene_ids)) != len(a.scene_ids) for a in self.artifacts):
            raise ValueError('DUPLICATE_SCENE')
        if any(len(set(o.evidence_refs)) != len(o.evidence_refs) or len(set(o.execution_modes)) != len(o.execution_modes) for o in self.observations):
            raise ValueError('DUPLICATE_REF')
        return self


class IndexedArtifact(Artifact):
    integrity: Literal['BYTE_HASH_MATCH']
    imported_at: AwareDatetime
    summary: Summary | None = None


class Index(Closed):
    schema_version: Literal['portal-evidence-index-1']
    manifest_sha256: Sha
    imported_at: AwareDatetime
    runs: list[Run] = Field(min_length=1, max_length=32)
    artifacts: list[IndexedArtifact] = Field(max_length=1000)
    observations: list[Observation] = Field(max_length=512)

    @model_validator(mode='after')
    def validate_index(self):
        # Reuse the scope/uniqueness rules without allowing filesystem paths in an index.
        Manifest.model_validate_json(__import__('json').dumps({
            'schema_version': 'portal-evidence-bundle-1',
            'runs': [r.model_dump(mode='json') for r in self.runs],
            'artifacts': [{**a.model_dump(mode='json', exclude={'integrity', 'imported_at', 'summary'}), 'relative_path': 'internal'} for a in self.artifacts],
            'observations': [o.model_dump(mode='json') for o in self.observations],
        }))
        for a in self.artifacts:
            if a.sanitization_state == 'SANITIZED':
                if a.summary is None or a.summary.run_id != a.run_id or a.summary.entity != a.entity or set(a.summary.scene_ids) != set(a.scene_ids):
                    raise ValueError('SUMMARY_SCOPE_MISMATCH')
            elif a.summary is not None:
                raise ValueError('WITHHELD_CONTENT')
        return self


class Source(Closed):
    source_system: str
    source_ref: str | None = None
    source_schema: str | None = None
    data_as_of: AwareDatetime | None = None
    observed_at: AwareDatetime | None = None
    read_at: AwareDatetime
    freshness_state: Literal['HISTORICAL', 'PARTIAL', 'UNAVAILABLE', 'UNKNOWN']
    coverage_kind: Literal['CACHE_ONLY', 'NOT_PROVEN'] = 'NOT_PROVEN'


class Meta(Closed):
    request_id: str
    read_at: AwareDatetime
    data_as_of: AwareDatetime | None = None
    source_system: str = 'OFFLINE_EVIDENCE_REGISTRY'
    source_schema: str = 'portal-evidence-index-1'
    freshness_state: Literal['HISTORICAL', 'PARTIAL', 'UNAVAILABLE', 'UNKNOWN']
    sources: list[Source]
    coverage_note: str


class EvidenceArtifact(Closed):
    evidence_id: Id
    evidence_kind: str
    related_entity_type: str
    related_entity_id: Id
    sha256: Sha | None
    size_bytes: int | None
    captured_at: AwareDatetime | None
    source_system: str
    sanitization_state: Literal['SANITIZED', 'WITHHELD', 'UNAVAILABLE']
    download_allowed: Literal[False] = False
    access_method: Literal['METADATA_ONLY'] = 'METADATA_ONLY'
    notes: list[str]
    provenance: Source


class DemoItem(Closed):
    scenario_id: Scene
    group: str
    title: str
    mode: Literal['LIVE', 'OFFLINE', 'HISTORICAL', 'MIXED'] | None
    expected_outcome: str
    observed_outcome: Outcome | None
    verdict: Verdict
    portal_section: str
    api_refs: list[str]
    evidence_refs: list[Id]
    last_evaluated_at: AwareDatetime | None
    run_id: Id | None
    context: Literal['TEST', 'EVALUATION', 'LIVE', 'DESIGN']
    execution_modes: list[Mode]
    expected_modes: list[str]
    reason_codes: list[str]
    missing_evidence_refs: list[Id]
    basis: Literal['DESIGN_EXPECTED', 'IMPORTED_OBSERVATION']
    portal_route: str | None


class DemoPage(Closed):
    schema_version: Literal['portal-demo-coverage-2'] = 'portal-demo-coverage-2'
    runs: list[Run]
    items: list[DemoItem]
    has_more: Literal[False] = False
    next_cursor: None = None
    expected_scene_count: Literal[16] = 16
    observed_scene_count: int
    strict_ready: Literal['UNKNOWN'] = 'UNKNOWN'
    strict_reason: Literal['P19_SOURCE_NOT_CONNECTED'] = 'P19_SOURCE_NOT_CONNECTED'


class EvidenceResponse(Closed):
    data: EvidenceArtifact
    meta: Meta
    error: None = None


class DemoResponse(Closed):
    data: DemoPage
    meta: Meta
    error: None = None
