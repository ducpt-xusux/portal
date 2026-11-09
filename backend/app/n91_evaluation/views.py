"""Frozen v4.1 response DTOs; precision/mode additions use separate schemas."""
from typing import Generic, Literal, TypeVar
from pydantic import BaseModel, ConfigDict, AwareDatetime
from ..dashboard_funnel import Source


class View(BaseModel):
    model_config=ConfigDict(extra='forbid')


class EvaluationCaseView(View):
    case_id: str
    run_id: str
    fixture_id: str
    partition: str
    scenario: str | None = None
    execution_mode: Literal['LIVE_READ_ONLY','OFFLINE_POLICY','P17_OFFLINE','PROTOCOL_OFFLINE','OTHER']
    input_excerpt: str | None = None
    input_visibility: Literal['MASKED','WITHHELD','NOT_CAPTURED']
    expected_action: str | None = None
    expected_rule_ids: list[str]
    observed_action: str | None = None
    observed_rule_ids: list[str]
    verdict: Literal['PASS','FAIL','INCOMPLETE','NOT_EXECUTED','NA','UNKNOWN']
    label_status: Literal['CANDIDATE','OWNER_REVIEWED','INDEPENDENT_REVIEWED','UNREVIEWED']
    event_refs: list[str]
    incident_refs: list[str]
    evidence_refs: list[str]
    review_notes: list[str] = []
    provenance: Source


class CorrelationScenarioView(View):
    scenario_id: str
    run_id: str
    signal_rule: str
    input_event_count: int
    expected_incident: bool
    observed_incident: bool | None
    expected_reason: str | None = None
    observed_reason: str | None = None
    verdict: Literal['PASS','FAIL','INCOMPLETE','NOT_EXECUTED','UNKNOWN']
    execution_mode: Literal['P17_OFFLINE','LIVE_OBSERVED','HISTORICAL']
    related_event_refs: list[str]
    incident_refs: list[str]
    source_label: Literal['OBSERVED','CANDIDATE_REFERENCE','UNREVIEWED']
    provenance: Source


class BackupArtifact(View):
    backup_id: str
    source_node: str
    backup_type: Literal['LOGICAL','PHYSICAL','UNKNOWN']
    created_at: AwareDatetime | None = None
    size_bytes: int | None = None
    sha256: str | None = None
    sha256_verified: bool | None = None
    storage_location_status: Literal['WITHHELD','SANITIZED_REFERENCE','UNAVAILABLE']
    evidence_refs: list[str]
    provenance: Source


class RestoreRunView(View):
    restore_run_id: str
    backup_id: str
    target_server_id: str | None = None
    target_name: str
    started_at: AwareDatetime | None = None
    completed_at: AwareDatetime | None = None
    mariadb_status: Literal['RUNNING','STOPPED','UNKNOWN','UNAVAILABLE']
    cluster_membership: Literal['INDEPENDENT','GALERA_MEMBER','UNKNOWN']
    schema_verified: bool | None = None
    row_count_verified: bool | None = None
    content_checksum_verified: bool | None = None
    rpo_seconds: int | None = None
    rto_seconds: int | None = None
    verification_state: Literal['PASS','FAIL','PARTIAL','NOT_VERIFIED','UNKNOWN']
    run_kind: Literal['LIVE','HISTORICAL']
    evidence_refs: list[str]
    limitations: list[str] = []
    provenance: Source


class ResilienceRunView(View):
    run_id: str
    gate: Literal['G05','G06','G07','G08','G09','OTHER']
    scenario: str
    run_kind: Literal['LIVE','HISTORICAL','OFFLINE']
    started_at: AwareDatetime | None = None
    finished_at: AwareDatetime | None = None
    expected_outcome: str
    observed_outcome: str | None = None
    verdict: Literal['PASS','FAIL','PARTIAL','UNKNOWN','NOT_EXECUTED']
    affected_workload_ids: list[str]
    evidence_refs: list[str]
    limitations: list[str] = []
    provenance: Source


class TlsRouteHealth(View):
    route_id: str
    source: str
    destination: str
    negotiated_version: str | None = None
    certificate_expires_at: AwareDatetime | None = None
    peer_verified: bool | None = None
    status: Literal['VERIFIED','FAILED','UNKNOWN','STALE','UNAVAILABLE']
    observed_at: AwareDatetime | None = None
    evidence_refs: list[str]
    provenance: Source


class P19LabGate(View):
    lab_scope_status: Literal['ACCEPTED_WITH_EXCEPTIONS','NOT_ACCEPTED','UNKNOWN']
    strict_ready: bool
    owner_attestation: Literal['RECORDED_UNVERIFIED','VERIFIED_DOCUMENT','UNAVAILABLE']
    ack_disposition: Literal['ACCEPTED_UNVERIFIABLE_NOT_COMMITTED','UNRESOLVED','UNKNOWN']
    exceptions: list[str] = []
    evidence_ref: str | None = None
    updated_at: AwareDatetime | None = None


class Meta(View):
    request_id: str
    read_at: AwareDatetime
    source_system: str
    source_schema: str | None = None
    freshness_state: Literal['FRESH','STALE','PARTIAL','UNKNOWN','UNAVAILABLE','HISTORICAL']
    sources: list[Source]
    coverage_note: str | None = None


T=TypeVar('T')


class Page(View,Generic[T]):
    items: list[T]
    has_more: Literal[False] = False
    next_cursor: None = None


class Response(View,Generic[T]):
    data: T
    meta: Meta
    error: None = None


FROZEN_MODELS=dict(cases=EvaluationCaseView,correlations=CorrelationScenarioView,backups=BackupArtifact,
    recoveries=RestoreRunView,resilience=ResilienceRunView,tls=TlsRouteHealth,p19=P19LabGate)
