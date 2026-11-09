"""Local canonical DTO extension. Frozen v4.1 is intentionally unchanged."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt
from .p16h_normalizer import Metadata, Sequence
from .schemas import ScoreComponent, Severity


class DTO(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Risk(DTO):
    status: Literal["OK", "ERROR"] | None
    score: StrictInt | None = Field(ge=0, le=100)
    severity: Severity | None
    version: str | None = None


class Provenance(DTO):
    source_system: str
    source_schema: str
    source_ref: str
    source_host: str | None
    source_run_id: str | None
    collected_at: str | None
    imported_at: str | None
    payload_sha256: str | None
    payload_hash_basis: Literal["UPSTREAM_UNVERIFIED"] | None
    artifact_sha256: str | None
    original_artifact_sha256: str | None
    verification: Literal["IMPORTED_UNVERIFIED"]
    human_review: Literal["UNAVAILABLE"]
    context: Literal["TEST", "EVALUATION", "IMPORTED_UNVERIFIED"] | None
    coverage_kind: Literal["RECENT_SAMPLE", "NOT_PROVEN"]
    delivery_version: Literal["p16h-local-1"] | None
    event_role: str | None
    journal_stream_id: str | None
    journal_sequence: Sequence | None
    segment_index: Sequence | None


class CanonicalEventView(DTO):
    event_id: str
    stream_id: str | None
    request_id: str | None
    stream_sequence: Sequence | None
    occurred_at: str
    ingested_at: None
    request_received_at: str | None
    storage_recorded_at: str | None
    imported_at: str | None
    time_basis: dict[str, str | None]
    identity_status: Literal["STREAM_EVENT", "LEGACY_EVENT_ONLY"]
    missing_fields_reason: str
    source_ip: str
    db_user: str | None
    database_name: str | None
    mysql_command: str
    decision: Literal["ALLOW", "BLOCK"]
    decision_basis: Literal["P14_POLICY_DECISION"]
    effective_action: Literal["ALLOW", "BLOCK"]
    runtime_mode: Literal["monitor", "enforce"]
    would_block: StrictBool
    action_result: Literal["FORWARDED", "BLOCKED", "ERROR"]
    matched_rules: list[str]
    blocking_rules: list[str]
    monitor_rules: list[str]
    policy_id: str
    policy_version: str
    reasons: list[str]
    raw_score: StrictInt | None
    score_breakdown: list[ScoreComponent] | None
    risk: Risk
    masked_query: str | None
    sql_text_status: Literal["MASKED", "WITHHELD"]
    source_metadata: Metadata | None
    view_kind: Literal["P16H_CANONICAL_AUDIT"]
    canonical_complete: StrictBool
    p17_event_class: None
    incident_refs: list[str]
    incident_membership: Literal["UNAVAILABLE"]
    source_provenance: Provenance
