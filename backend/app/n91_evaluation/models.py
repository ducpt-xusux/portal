"""Closed sanitized import DTOs. Nothing here executes SQL or alters sources."""
from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field, AwareDatetime, model_validator

Id = Annotated[str, Field(min_length=1, max_length=100, pattern=r'^[A-Za-z0-9][A-Za-z0-9_.:-]*$')]
Sha = Annotated[str, Field(pattern=r'^[a-f0-9]{64}$')]
Count = Annotated[int, Field(strict=True, ge=0, le=100000)]
Seconds = Annotated[float, Field(ge=0, le=31536000, allow_inf_nan=False)]
Mode = Literal['LIVE', 'ISOLATED', 'STAGING', 'HISTORICAL']
Context = Literal['TEST', 'EVALUATION', 'LIVE']
Partition = Literal['LIVE_READ_ONLY', 'OFFLINE_POLICY', 'PROTOCOL_OFFLINE', 'P17_OFFLINE']
Verdict = Literal['PASS', 'FAIL', 'INCOMPLETE', 'NOT_EXECUTED', 'UNKNOWN', 'NA']
Review = Literal['CANDIDATE', 'OWNER_REVIEWED', 'INDEPENDENT_REVIEWED', 'UNREVIEWED']
Refs = Annotated[list[Id], Field(max_length=100)]


class Closed(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)


class Scope(Closed):
    run_id: Id
    context: Context
    execution_mode: Mode
    source_system: Id
    data_as_of: AwareDatetime
    observed_at: AwareDatetime
    # Local files are frozen observations regardless of original execution mode.
    freshness_state: Literal['HISTORICAL'] = 'HISTORICAL'


class Linked(Closed):
    scope: Scope
    evidence_refs: Refs

    @model_validator(mode='after')
    def distinct_refs(self):
        for key in ('evidence_refs', 'request_refs', 'event_refs', 'incident_refs'):
            refs = getattr(self, key, [])
            if len(refs) != len(set(refs)):
                raise ValueError('DUPLICATE_REF')
        return self


class CaseObservation(Linked):
    case_id: Annotated[str, Field(pattern=r'^C-0(0[1-9]|[1-5][0-9]|60)$')]
    partition: Partition
    observed_action: Literal['ALLOW', 'BLOCK', 'ERROR', 'REVIEW_REQUIRED'] | None
    observed_rule_ids: Refs
    verdict: Verdict
    label_status: Review
    request_refs: Refs
    request_count: Count | None
    event_refs: Refs
    incident_refs: Refs

    @model_validator(mode='after')
    def coherent(self):
        if self.request_count is not None and self.request_count != len(self.request_refs):
            raise ValueError('REQUEST_COUNT_MISMATCH')
        if self.verdict == 'PASS' and (self.observed_action is None or not self.evidence_refs):
            raise ValueError('PASS_REQUIRES_OBSERVATION')
        if self.verdict == 'NOT_EXECUTED' and (self.observed_action or self.request_refs or self.event_refs or self.incident_refs):
            raise ValueError('NOT_EXECUTED_HAS_OBSERVATION')
        if self.scope.execution_mode == 'LIVE' and self.partition != 'LIVE_READ_ONLY':
            raise ValueError('OFFLINE_PARTITION_IS_NOT_LIVE')
        return self


class CorrelationObservation(Linked):
    scenario_id: Id
    input_event_count: Count
    observed_incident: bool | None
    verdict: Literal['PASS', 'FAIL', 'INCOMPLETE', 'NOT_EXECUTED', 'UNKNOWN']
    event_refs: Refs
    incident_refs: Refs

    @model_validator(mode='after')
    def coherent(self):
        if len(self.event_refs)>self.input_event_count:
            raise ValueError('EVENT_COUNT_MISMATCH')
        if self.scope.execution_mode not in {'ISOLATED', 'HISTORICAL'}:
            raise ValueError('FROZEN_CORRELATION_NOT_LIVE')
        if self.verdict == 'PASS' and (self.observed_incident is None or not self.evidence_refs):
            raise ValueError('PASS_REQUIRES_OBSERVATION')
        if self.observed_incident is False and self.incident_refs:
            raise ValueError('NEGATIVE_HAS_INCIDENT')
        if self.observed_incident is True and not self.incident_refs:
            raise ValueError('POSITIVE_MISSING_INCIDENT')
        if self.verdict == 'NOT_EXECUTED' and (self.observed_incident is not None or self.incident_refs or self.event_refs):
            raise ValueError('NOT_EXECUTED_HAS_OBSERVATION')
        return self


class EvaluationObservations(Closed):
    schema_version: Literal['n91-evaluation-observations-1']
    run_hashes: dict[Id, Sha] = Field(max_length=100)
    cases: list[CaseObservation] = Field(max_length=6000)
    correlations: list[CorrelationObservation] = Field(max_length=1300)

    @model_validator(mode='after')
    def unique_scopes(self):
        for rows, field in ((self.cases, 'case_id'), (self.correlations, 'scenario_id')):
            keys = [(r.scope.run_id, getattr(r, field)) for r in rows]
            if len(keys) != len(set(keys)) or any(k[0] not in self.run_hashes for k in keys):
                raise ValueError('INVALID_OBSERVATION_SCOPE')
        return self


class Backup(Linked):
    backup_id: Id
    source_node: Id
    backup_type: Literal['LOGICAL', 'PHYSICAL', 'UNKNOWN']
    created_at: AwareDatetime | None
    size_bytes: Annotated[int, Field(strict=True, ge=0, le=2**63-1)] | None
    sha256: Sha | None
    sha256_verified: bool | None

    @model_validator(mode='after')
    def hash_evidence(self):
        if self.sha256_verified and (not self.sha256 or not self.evidence_refs):
            raise ValueError('BACKUP_HASH_UNPROVEN')
        return self


class Recovery(Linked):
    restore_run_id: Id
    backup_id: Id
    target_name: Id
    observation_kind: Literal['LAB_DRILL', 'CURRENT_READBACK']
    mariadb_status: Literal['RUNNING', 'STOPPED', 'UNKNOWN', 'UNAVAILABLE']
    cluster_membership: Literal['INDEPENDENT', 'GALERA_MEMBER', 'UNKNOWN']
    schema_verified: bool | None
    row_count_verified: bool | None
    content_checksum_verified: bool | None
    verification_state: Literal['PASS', 'FAIL', 'PARTIAL', 'NOT_VERIFIED', 'UNKNOWN']
    committed_marker_ids: Refs
    restored_marker_ids: Refs
    lost_marker_ids: Refs
    marker_capture_complete: bool
    fault_utc: AwareDatetime | None
    recovery_query_verified_utc: AwareDatetime | None
    clock_basis: Literal['SAME_CLOCK', 'UNKNOWN']
    rpo_gap_seconds: Seconds | None
    # This module intentionally cannot claim production service measurements.
    production_rpo_seconds: None = None
    production_rto_seconds: None = None
    production_rpo_measured: Literal[False] = False
    full_app_proxy_galera_rto_measured: Literal[False] = False

    @model_validator(mode='after')
    def markers_and_clock(self):
        committed, restored, lost = map(set, (self.committed_marker_ids, self.restored_marker_ids, self.lost_marker_ids))
        if any(len(getattr(self, key)) != len(set(getattr(self, key))) for key in ('committed_marker_ids','restored_marker_ids','lost_marker_ids')):
            raise ValueError('DUPLICATE_MARKER')
        if restored & lost or not (restored | lost) <= committed:
            raise ValueError('MARKER_SCOPE_MISMATCH')
        if self.marker_capture_complete and committed != restored | lost:
            raise ValueError('MARKER_PARTITION_MISMATCH')
        if self.fault_utc and self.recovery_query_verified_utc and self.recovery_query_verified_utc < self.fault_utc:
            raise ValueError('RECOVERY_TIME_REVERSED')
        if self.verification_state == 'PASS' and (self.schema_verified is not True or self.row_count_verified is not True or self.content_checksum_verified is not True or not self.evidence_refs):
            raise ValueError('RESTORE_PASS_UNPROVEN')
        if lost and self.rpo_gap_seconds == 0:
            raise ValueError('LOST_MARKER_WITH_ZERO_RPO')
        if self.observation_kind == 'CURRENT_READBACK' and (committed or restored or lost or self.rpo_gap_seconds is not None or self.fault_utc or self.recovery_query_verified_utc):
            raise ValueError('CURRENT_READBACK_IS_NOT_DRILL')
        return self


class Resilience(Linked):
    resilience_id: Id
    gate: Literal['G05','G06','G07','G08','G09','OTHER']
    scenario: Id
    expected_outcome: Id
    observed_outcome: Id | None
    verdict: Literal['PASS','FAIL','PARTIAL','UNKNOWN','NOT_EXECUTED']
    affected_workload_ids: Refs

    @model_validator(mode='after')
    def observation(self):
        if self.verdict == 'PASS' and (not self.observed_outcome or not self.evidence_refs):
            raise ValueError('PASS_UNPROVEN')
        return self


class Tls(Linked):
    route_id: Id
    source: Id
    destination: Id
    negotiated_version: Literal['TLSv1.2','TLSv1.3'] | None
    certificate_expires_at: AwareDatetime | None
    peer_verified: bool | None
    status: Literal['VERIFIED','FAILED','UNKNOWN','STALE','UNAVAILABLE']
    handshake_retry_limitation: Literal['OPEN','UNKNOWN']

    @model_validator(mode='after')
    def negotiated(self):
        if self.status == 'VERIFIED' and (not self.negotiated_version or self.peer_verified is not True or not self.evidence_refs):
            raise ValueError('TLS_VERIFIED_UNPROVEN')
        return self


class Privacy(Linked):
    privacy_id: Id
    coverage_kind: Literal['RECENT_SAMPLE','ISOLATED_CANARY']
    sample_count: Count
    masked_count: Count
    canary_count: Count | None
    leaked_count: Count | None
    unknown_family_count: Count | None
    verification: Literal['OBSERVED_SAMPLE','UNKNOWN','NOT_EXECUTED']

    @model_validator(mode='after')
    def bounded_sample(self):
        if self.masked_count > self.sample_count or (self.leaked_count is not None and self.leaked_count > self.sample_count):
            raise ValueError('SAMPLE_COUNT_MISMATCH')
        if self.coverage_kind == 'ISOLATED_CANARY' and self.scope.execution_mode == 'LIVE':
            raise ValueError('CANARY_IS_NOT_LIVE_SAMPLE')
        return self


class Staging(Linked):
    finding_id: Literal['F01','F02']
    staging_sha256: Sha
    production_sha256: Sha | None
    passed: Count
    total: Count
    production_status: Literal['OPEN','UNKNOWN']
    production_cutover_verified: Literal[False] = False

    @model_validator(mode='after')
    def staging_only(self):
        if self.scope.execution_mode != 'STAGING' or self.passed > self.total:
            raise ValueError('STAGING_SCOPE_MISMATCH')
        return self


class P19(Linked):
    lab_scope_status: Literal['ACCEPTED_WITH_EXCEPTIONS','NOT_ACCEPTED','UNKNOWN']
    strict_ready: Literal[False] = False
    owner_attestation: Literal['RECORDED_UNVERIFIED','VERIFIED_DOCUMENT','UNAVAILABLE']
    ack_disposition: Literal['ACCEPTED_UNVERIFIABLE_NOT_COMMITTED','UNRESOLVED','UNKNOWN']
    exceptions: Refs
    authority: Literal['SIGNED_LAB_SCOPE','UNAVAILABLE']

    @model_validator(mode='after')
    def authority_required(self):
        if self.authority == 'UNAVAILABLE' and (self.lab_scope_status != 'UNKNOWN' or self.owner_attestation != 'UNAVAILABLE'):
            raise ValueError('P19_AUTHORITY_UNAVAILABLE')
        return self


class SystemObservations(Closed):
    schema_version: Literal['n91-system-observations-1']
    backups: list[Backup] = Field(max_length=100)
    recoveries: list[Recovery] = Field(max_length=100)
    resilience: list[Resilience] = Field(max_length=100)
    tls: list[Tls] = Field(max_length=100)
    privacy: list[Privacy] = Field(max_length=100)
    staging: list[Staging] = Field(max_length=100)
    p19: P19 | None

    @model_validator(mode='after')
    def identities(self):
        fields = {'backups':'backup_id','recoveries':'restore_run_id','resilience':'resilience_id','tls':'route_id','privacy':'privacy_id','staging':'finding_id'}
        for collection, key in fields.items():
            rows = getattr(self, collection)
            # Every item must have a distinct frozen observation identity across this snapshot.
            if len({getattr(row,key) for row in rows}) != len(rows):
                raise ValueError('DUPLICATE_OBSERVATION')
        backups = {b.backup_id:b for b in self.backups}
        for row in self.recoveries:
            if row.observation_kind == 'LAB_DRILL':
                backup = backups.get(row.backup_id)
                if not backup or backup.scope.run_id != row.scope.run_id or backup.scope.context != row.scope.context:
                    raise ValueError('BACKUP_LINK_MISMATCH')
        return self
