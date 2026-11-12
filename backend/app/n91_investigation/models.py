"""Frozen v4.1 DTOs plus explicit investigation-1 source/SG extension DTOs.

The local input profiles describe sanitized adapters, not guessed producer formats.
"""
from datetime import datetime
from typing import Annotated, Generic, Literal, TypeVar
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, IPvAnyAddress, StrictBool, StrictInt, field_validator, model_validator

ID = Annotated[str, Field(strict=True, min_length=1, max_length=160, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")]
Text = Annotated[str, Field(strict=True, max_length=2048)]
Hash = Annotated[str, Field(strict=True, pattern=r"^[a-f0-9]{64}$")]
Refs = Annotated[list[ID], Field(max_length=256)]
Freshness = Literal["FRESH", "STALE", "PARTIAL", "UNKNOWN", "UNAVAILABLE", "HISTORICAL"]
Mode = Literal["TEST", "EVALUATION", "LIVE", "ISOLATED", "STAGING", "HISTORICAL", "DESIGN_ONLY"]
StageName = Literal["SQL_PARSE", "P14_POLICY", "P15_RISK", "P16H_AUDIT", "P17_DETECTION", "P17_DECISION", "P17_5_RESPONSE"]
STAGES = ("SQL_PARSE", "P14_POLICY", "P15_RISK", "P16H_AUDIT", "P17_DETECTION", "P17_DECISION", "P17_5_RESPONSE")


class DTO(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    @field_validator('*', mode='before')
    @classmethod
    def input_types(cls, value, info):
        if value is not None and (info.field_name.endswith('_at') or info.field_name in {'timestamp', 'quarantined_at_utc', 'restored_at_utc'}):
            if not isinstance(value, (str, datetime)):
                raise ValueError('Timestamp needs ISO8601 offset; numeric epoch not accepted')
        if info.field_name in {'security_group_ids', 'original_sgs'} and isinstance(value, list):
            if any(not isinstance(v, str) for v in value) or len(value) != len(set(value)):
                raise ValueError('Security group identities must be unique strings')
        return value


class SourceStamp(DTO):
    source_system: ID
    source_ref: ID
    source_schema: ID
    execution_mode: Mode
    observed_at: AwareDatetime | None = None
    collected_at: AwareDatetime | None = None
    source_sha256: Hash | None = None
    verification: Literal["SOURCE_REPORTED", "IMPORTED_UNVERIFIED", "UNAVAILABLE"] = "IMPORTED_UNVERIFIED"
    human_review: Literal["UNAVAILABLE"] = "UNAVAILABLE"
    freshness_state: Freshness = "HISTORICAL"
    limitations: Annotated[list[Text], Field(max_length=40)] = Field(default_factory=list)


class SourceFreshness(DTO):
    source_system: Text
    source_ref: Text | None = None
    source_schema: Text | None = None
    data_as_of: AwareDatetime | None = None
    observed_at: AwareDatetime | None = None
    read_at: AwareDatetime
    freshness_state: Freshness
    age_seconds: Annotated[StrictInt, Field(ge=0)] | None = None
    error_code: ID | None = None
    coverage_kind: Literal["COMPLETE_QUERY_WINDOW", "RECENT_SAMPLE", "P17_PROJECTION", "CACHE_ONLY", "NOT_PROVEN"] = "NOT_PROVEN"


class Condition(DTO):
    path: Text
    op: ID
    value_redacted: Text | None


class Rule(DTO):
    rule_id: ID
    category: ID
    mode: Literal["enforce", "monitor"]
    action: Literal["ALLOW", "BLOCK"]
    priority: StrictInt
    enabled: StrictBool
    description: Text
    all_conditions: Annotated[list[Condition], Field(max_length=64)]
    any_conditions: Annotated[list[Condition], Field(max_length=64)]


class PolicySnapshot(DTO):
    schema_version: Literal["investigation-policy-1"]
    policy_version: ID
    risk_algorithm_version: ID | None = None
    source: SourceStamp
    rules: Annotated[list[Rule], Field(min_length=1, max_length=100)]

    @model_validator(mode="after")
    def unique_rules(self):
        if len({r.rule_id for r in self.rules}) != len(self.rules):
            raise ValueError("Duplicate rule IDs")
        return self


class RuleHit(DTO):
    rule_id: ID
    name: Text | None = None
    category: Text | None = None
    effect: Literal["BLOCK", "ALLOW", "MONITOR", "UNKNOWN"]
    explanation: Text | None = None
    policy_version: Text | None = None
    source_ref: Text | None = None


class PolicyCatalog(DTO):
    policy_version: Text
    sha256: Hash | None = None
    rules: list[RuleHit]
    risk_algorithm_version: Text | None = None
    captured_at: AwareDatetime | None = None


class PolicyRuleDetail(Rule):
    policy_version: ID
    policy_sha256: Hash
    source_ref: ID
    captured_at: AwareDatetime | None = None


class Reason(DTO):
    code: ID
    title: Text = ''
    description: Text
    source_system: Text
    source_ref: Text | None = None
    evidence_refs: Refs = Field(default_factory=list)
    verification: Literal["VERIFIED_SOURCE", "RECONSTRUCTED", "DERIVED", "UNAVAILABLE"] = "UNAVAILABLE"
    observed_at: AwareDatetime | None = None


class TraceFact(DTO):
    name: ID
    value_summary: Text | None = None
    status: Literal["PRESENT", "WITHHELD", "UNAVAILABLE", "RECONSTRUCTED"]
    source_ref: Text | None = None
    observed_at: AwareDatetime | None = None
    verification: Literal["VERIFIED_SOURCE", "SOURCE_REPORTED", "RECONSTRUCTED", "UNAVAILABLE"]

    @model_validator(mode='after')
    def withheld_value(self):
        if self.status in {'WITHHELD', 'UNAVAILABLE'} and self.value_summary is not None:
            raise ValueError('Unavailable or withheld facts cannot carry a value')
        return self


class DecisionStage(DTO):
    stage_id: ID
    stage: StageName
    status: Literal["EVALUATED", "NOT_TRIGGERED", "NOT_APPLICABLE", "UNAVAILABLE", "HISTORICAL"]
    outcome: Text | None
    reason_codes: Refs = Field(default_factory=list)
    reasons: Annotated[list[Reason], Field(max_length=64)] = Field(default_factory=list)
    facts: Annotated[list[TraceFact], Field(max_length=64)] = Field(default_factory=list)
    input_refs: Refs = Field(default_factory=list)
    output_refs: Refs = Field(default_factory=list)
    source_system: Text
    source_ref: Text | None = None
    evaluated_at: AwareDatetime | None = None
    verification: Literal["VERIFIED_SOURCE", "SOURCE_REPORTED", "RECONSTRUCTED", "UNAVAILABLE"]

    @model_validator(mode='after')
    def unavailable_outcome(self):
        if self.status == 'UNAVAILABLE' and self.outcome is not None:
            raise ValueError('Unavailable stage cannot declare an outcome')
        return self


class DecisionTrace(DTO):
    trace_id: ID
    event_id: ID | None = None
    incident_id: ID | None = None
    trace_kind: Literal["LIVE_EVENT", "OFFLINE_CASE", "CORRELATION_SCENARIO", "INCIDENT"]
    stages: list[DecisionStage]
    overall_outcome: Text
    link_quality: Literal["DIRECT_IDS", "RECONSTRUCTED", "PARTIAL", "UNAVAILABLE"]
    evidence_refs: Refs = Field(default_factory=list)
    limitations: list[Text] = Field(default_factory=list)
    provenance: SourceFreshness


class StageEvidence(DTO):
    schema_version: Literal["investigation-stage-1"]
    stream_id: ID | None = None
    event_id: ID | None = None
    incident_id: ID | None = None
    source: SourceStamp
    stage: DecisionStage


class ControllerAction(DTO):
    # Actual documented top-level actions.jsonl fields. Detail is never returned.
    kind: ID
    timestamp: AwareDatetime | None = None
    incident_id: ID | None = None
    detail: dict | Text | None = None


class Containment(DTO):
    # Actual documented containment fields. Unknown layouts require an adapter.
    incident_id: ID
    original_sgs: Refs | None = None
    port_id: ID
    quarantine_sg: ID | None = None
    quarantined_at_utc: AwareDatetime | None = None
    restored_at_utc: AwareDatetime | None = None
    status: ID
    vm_id: ID
    source_ip: IPvAnyAddress | None = None


class SgSnapshot(DTO):
    phase: Literal["BEFORE", "DURING", "AFTER"]
    incident_id: ID
    cycle_id: ID
    project_id: ID
    port_id: ID
    server_id: ID
    security_group_ids: Refs
    observed_at: AwareDatetime | None
    source_ref: ID


class ClockMark(DTO):
    incident_id: ID
    cycle_id: ID
    kind: Literal["EVENT_OCCURRED", "REQUEST_RECEIVED", "AUDIT_STORED", "DETECTED", "TRIGGER_ACCEPTED", "PREPARED", "QUARANTINE_APPLIED", "RESTORE_SUCCESS"]
    timestamp: AwareDatetime
    clock_id: ID
    time_basis: ID
    source_ref: ID


class ControllerCycle(DTO):
    schema_version: Literal["investigation-controller-1"]
    action_id: ID
    incident_id: ID
    cycle_id: ID
    project_id: ID | None = None
    source: SourceStamp
    containment: Containment
    actions: Annotated[list[ControllerAction], Field(max_length=256)]
    snapshots: Annotated[list[SgSnapshot], Field(max_length=3)] = Field(default_factory=list)
    clock_marks: Annotated[list[ClockMark], Field(max_length=32)] = Field(default_factory=list)

    @model_validator(mode="after")
    def same_identity(self):
        if self.containment.incident_id != self.incident_id:
            raise ValueError("Containment identity mismatch")
        if len({s.phase for s in self.snapshots}) != len(self.snapshots):
            raise ValueError("Duplicate SG phases")
        for s in self.snapshots:
            if (s.incident_id, s.cycle_id, s.project_id, s.port_id, s.server_id) != (
                self.incident_id, self.cycle_id, self.project_id, self.containment.port_id, self.containment.vm_id
            ):
                raise ValueError("Snapshot identity mismatch")
        for mark in self.clock_marks:
            if (mark.incident_id, mark.cycle_id) != (self.incident_id, self.cycle_id):
                raise ValueError("Clock identity mismatch")
        return self


class ControllerBundle(DTO):
    schema_version: Literal["investigation-controller-bundle-1"]
    source: SourceStamp
    cycles: Annotated[list[ControllerCycle], Field(max_length=256)]

    @model_validator(mode="after")
    def unique_cycles(self):
        if len({c.action_id for c in self.cycles}) != len(self.cycles):
            raise ValueError("Duplicate action ID")
        if len({(c.incident_id, c.cycle_id) for c in self.cycles}) != len(self.cycles):
            raise ValueError("Duplicate cycle")
        if any(c.source.execution_mode != self.source.execution_mode for c in self.cycles):
            raise ValueError("Mixed execution modes")
        return self


class CurrentObservation(DTO):
    schema_version: Literal["investigation-neutron-1"]
    source: SourceStamp
    project_id: ID
    port_id: ID
    server_id: ID
    security_group_ids: Refs
    fixed_ips: Annotated[list[IPvAnyAddress], Field(max_length=64)] | None = None
    floating_ips: Annotated[list[IPvAnyAddress], Field(max_length=64)] | None = None
    observed_at: AwareDatetime
    expires_at: AwareDatetime
    source_system: Literal["NEUTRON_LIVE"] = "NEUTRON_LIVE"


class Mapping(DTO):
    verified: StrictBool
    source_ip: Text | None = None
    server_id: ID | None = None
    port_id: ID | None = None
    project_id: ID | None = None
    network_id: ID | None = None
    fixed_ip: Text | None = None
    observed_at: AwareDatetime | None = None
    expires_at: AwareDatetime | None = None
    verification_state: Literal["VERIFIED", "STALE", "AMBIGUOUS", "MISMATCH", "UNAVAILABLE"]
    reason: Text | None = None
    source_system: Literal["NEUTRON_LIVE", "OPENSTACK_SNAPSHOT", "UNAVAILABLE"]


class ActionView(DTO):
    action_id: ID
    incident_id: ID
    action_state: ID
    approval_ref: Text | None = None
    target: Mapping | None = None
    before_sgs: Refs | None = None
    during_sgs: Refs | None = None
    after_sgs: Refs | None = None
    network_verified: StrictBool
    started_at: AwareDatetime | None = None
    finished_at: AwareDatetime | None = None
    evidence_refs: Refs = Field(default_factory=list)
    warnings: list[Text] = Field(default_factory=list)


class TimelineItem(DTO):
    item_id: ID
    type: ID
    occurred_at: AwareDatetime | None = None
    source_system: Text
    source_ref: Text | None = None
    description: Text
    verification: Literal["VERIFIED", "SOURCE_REPORTED", "UNVERIFIED", "UNKNOWN"]
    actor: Text | None = None
    request_id: Text | None = None


class TimelineView(DTO):
    incident_id: ID
    incident_status: ID
    response_state: ID
    network_observation: Mapping | None = None
    items: list[TimelineItem]
    limitations: list[Text] = Field(default_factory=list)


class DurationMetric(DTO):
    metric: ID
    seconds: float | None
    unit: Literal["seconds"] = "seconds"
    start_kind: ID
    end_kind: ID
    incident_id: ID
    cycle_id: ID
    clock_id: ID | None = None
    time_basis: ID | None = None
    source_refs: Refs = Field(default_factory=list)
    unavailable_reason: ID | None = None


class SgHistory(DTO):
    BEFORE: SgSnapshot | None
    DURING: SgSnapshot | None
    AFTER: SgSnapshot | None


class ArmContext(DTO):
    kind: ID
    timestamp: AwareDatetime | None
    link_quality: Literal['CONTEXT_ONLY']
    source_ref: ID


class SgLifecycleView(DTO):
    schema_version: Literal['investigation-sg-lifecycle-1']
    action: ActionView
    incident_id: ID
    cycle_id: ID
    source: SourceStamp
    history: SgHistory
    current: CurrentObservation | None
    current_state: Literal['UNKNOWN', 'RESTORED', 'QUARANTINED', 'DRIFT']
    metrics: list[DurationMetric]
    clock_marks: list[ClockMark]
    arm_context: list[ArmContext]
    limitations: list[Text]


class ActionsPage(DTO):
    items: list[ActionView]
    has_more: StrictBool
    next_cursor: Text | None = None
    total_count: StrictInt | None = None


class Meta(DTO):
    request_id: Text
    read_at: AwareDatetime
    data_as_of: AwareDatetime | None = None
    source_system: Text
    source_schema: Text | None = None
    freshness_state: Freshness
    next_cursor: Text | None = None
    sources: list[SourceFreshness]
    coverage_note: Text | None = None


class ApiError(DTO):
    code: ID
    message: Text
    request_id: Text | None = None


Data = TypeVar('Data')


class Response(DTO, Generic[Data]):
    data: Data | None
    meta: Meta
    error: ApiError | None = None
