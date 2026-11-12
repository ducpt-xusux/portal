"""Additive, read-only investigation contract. Provisional handoff profile."""
from typing import Annotated, Literal
from datetime import datetime

from pydantic import AwareDatetime, Field, IPvAnyAddress, StrictBool, StrictInt, field_validator

from ..defense_bundle_models import DefenseRegistrySummary
from ..n91_business.dto import Meta as SessionMeta, Overlay
from .models import DTO, ID, Hash, Freshness, ApiError
from .response_history import ResponseHistory


Count = Annotated[StrictInt, Field(ge=0)]
Score = Annotated[StrictInt, Field(ge=0, le=100)]


class Identity(DTO):
    stream_id: ID
    incident_id: ID


class SourceAvailability(DTO):
    source_system: ID
    availability: Literal['AVAILABLE', 'PARTIAL', 'UNAVAILABLE']
    freshness_state: Freshness
    read_at: AwareDatetime
    data_as_of: AwareDatetime | None = None
    observed_at: AwareDatetime | None = None
    captured_at: AwareDatetime | None = None
    source_ref: ID | None = None
    generation: Hash | None = None
    source_schema: Annotated[str, Field(strict=True, min_length=1, max_length=160,
        pattern=r'^[A-Za-z0-9][A-Za-z0-9_.:+-]*$')] | None = None
    context: ID | None = None
    error_code: ID | None = None
    coverage_complete: Literal[False] = False
    reason_codes: list[ID] = Field(default_factory=list)


class RecordedIncident(Identity):
    signal_rule: ID
    source_ip: IPvAnyAddress
    source_key_hash: Hash
    source_key_hash_basis: Literal['PORTAL_HASH_OF_SOURCE_KEY'] = 'PORTAL_HASH_OF_SOURCE_KEY'
    severity: ID
    status: ID
    confidence: ID
    evidence_count: Count
    peak_p15: Score | None
    source_verified: StrictBool
    isolation_authorized: StrictBool
    first_seen: AwareDatetime
    last_seen: AwareDatetime
    created_at: AwareDatetime
    updated_at: AwareDatetime


class EventReference(DTO):
    stream_id: ID
    event_id: ID
    request_id: ID


class EventRisk(DTO):
    status: ID | None
    score: Score | None
    severity: ID | None = None


class P17Projection(DTO):
    stream_sequence: Count
    occurred_at: AwareDatetime
    ingested_at: AwareDatetime
    blocked: StrictBool
    event_class: ID
    live_eligible: StrictBool
    matched_rules: list[ID]
    risk: EventRisk
    payload_sha256: Hash
    payload_hash_basis: Literal['P17_RECORDED_UPSTREAM_HASH'] = 'P17_RECORDED_UPSTREAM_HASH'


class CanonicalProjection(DTO):
    stream_id: ID
    event_id: ID
    request_id: ID | None
    occurred_at: AwareDatetime
    decision: Literal['ALLOW', 'BLOCK']
    effective_action: Literal['ALLOW', 'BLOCK']
    action_result: Literal['FORWARDED', 'BLOCKED', 'ERROR']
    policy_id: ID
    policy_version: ID
    runtime_mode: Literal['monitor', 'enforce']
    matched_rules: list[ID]
    blocking_rules: list[ID]
    monitor_rules: list[ID]
    risk: EventRisk
    source_ref: ID
    payload_sha256: Hash | None
    payload_hash_basis: Literal['UPSTREAM_UNVERIFIED'] | None


class EventMember(DTO):
    event_ref: EventReference
    projection: P17Projection
    canonical: CanonicalProjection | None
    canonical_availability: Literal['AVAILABLE', 'UNAVAILABLE', 'MISMATCH']
    join_state: Literal['RECONSTRUCTED_WINDOW', 'MISMATCH', 'UNAVAILABLE']
    candidate_basis: Literal['LEGACY_UNPINNED'] = 'LEGACY_UNPINNED'
    hash_comparability: Literal['NOT_PROVEN', 'UNAVAILABLE']
    eligible_for_corr: None = None
    reason_codes: list[ID]


class MembersPage(DTO):
    available: StrictBool
    items: list[EventMember]
    authoritative_count: Count
    total_candidates: Count | None
    verified_linked_count: Literal[0] | None = None
    direct_membership_supported: Literal[False] = False
    membership: Literal['RECONSTRUCTED_WINDOW', 'UNAVAILABLE']
    candidate_basis: Literal['LEGACY_UNPINNED'] = 'LEGACY_UNPINNED'
    matches_recorded_count: StrictBool | None
    limit: Annotated[StrictInt, Field(ge=1, le=100)]
    has_more: StrictBool
    next_cursor: str | None


class ScopedAlert(DTO):
    alert_id: ID
    incident_id: ID
    stream_id: ID
    created_at: AwareDatetime
    signal_code: ID
    severity: ID
    trigger_event: EventReference
    link_basis: Literal['P17_OUTBOX_INCIDENT_ID_IN_STREAM'] = 'P17_OUTBOX_INCIDENT_ID_IN_STREAM'
    delivered_is_review: Literal[False] = False


class AlertsSection(DTO):
    availability: Literal['AVAILABLE', 'UNAVAILABLE']
    items: list[ScopedAlert]
    total_count: Count | None
    has_more: StrictBool = False
    reason_codes: list[ID]


class DependentSection(DTO):
    availability: Literal['UNAVAILABLE'] = 'UNAVAILABLE'
    outcome: None = None
    reason_codes: list[ID]


class AnalystCase(DTO):
    availability: Literal['AVAILABLE', 'UNAVAILABLE']
    overlay: Overlay | None = None
    write_enabled: Literal[False] = False
    reason_codes: list[ID]


class RegistrySummary(DefenseRegistrySummary):
    """Retain A's closed summary; accept its ISO dates inside an aggregate wire DTO."""
    @field_validator('read_at', 'imported_at', mode='before')
    @classmethod
    def wire_timestamp(cls, value):
        if isinstance(value, str):
            return datetime.fromisoformat(value.replace('Z', '+00:00'))
        return value


class InvestigationData(DTO):
    schema_version: Literal['portal-investigation-1'] = 'portal-investigation-1'
    identity: Identity
    incident: RecordedIncident
    event_members: MembersPage
    alerts: AlertsSection
    detection: DependentSection
    decision: DependentSection
    response: DependentSection | ResponseHistory
    analyst_case: AnalystCase
    defense_registry: RegistrySummary | None = None


class InvestigationMeta(DTO):
    request_id: ID
    read_at: AwareDatetime
    data_as_of: AwareDatetime | None = None
    source_system: Literal['PORTAL_INVESTIGATION'] = 'PORTAL_INVESTIGATION'
    source_schema: Literal['portal-investigation-1'] = 'portal-investigation-1'
    overall_status: Literal['PARTIAL'] = 'PARTIAL'
    freshness_state: Literal['FRESH', 'HISTORICAL', 'STALE']
    execution_mode: Literal['HISTORICAL'] = 'HISTORICAL'
    source_context: Literal['TEST', 'IMPORTED_UNVERIFIED']
    sources: list[SourceAvailability]
    missing_fields: list[ID]
    limitations: list[str]
    coverage_complete: Literal[False] = False
    next_cursor: str | None = None


class InvestigationResponse(DTO):
    data: InvestigationData
    meta: InvestigationMeta
    error: ApiError | None = None


class InvestigationErrorMeta(DTO):
    request_id: ID
    read_at: AwareDatetime
    source_schema: Literal['portal-investigation-1'] = 'portal-investigation-1'
    source_system: Literal['PORTAL_INVESTIGATION'] = 'PORTAL_INVESTIGATION'
    overall_status: Literal['UNAVAILABLE'] = 'UNAVAILABLE'
    freshness_state: Literal['UNAVAILABLE'] = 'UNAVAILABLE'
    data_as_of: None = None
    coverage_complete: Literal[False] = False


class InvestigationErrorResponse(DTO):
    data: None = None
    meta: InvestigationErrorMeta
    error: ApiError


class InvestigationSessionErrorResponse(DTO):
    """The unchanged outer SESSION boundary owns its authentication envelope."""
    data: None = None
    meta: SessionMeta
    error: ApiError
