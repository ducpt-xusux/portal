from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Generic, Literal, TypeVar
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StrictBool, StrictInt, model_validator


Severity = Literal["LOW", "WARNING", "HIGH", "CRITICAL"]
Decision = Literal["ALLOW", "BLOCK"]


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def utc_now() -> str:
    return iso(datetime.now(timezone.utc))


class ScoreComponent(BaseModel):
    model_config = ConfigDict(extra="ignore")
    source: str
    rule_id: str | None
    score: StrictInt = Field(ge=0)
    category: str
    reason: str


class AuditEvent(BaseModel):
    """P16 audit-v1.0. Only these fields are stored and exposed."""

    model_config = ConfigDict(extra="ignore")
    event_id: UUID
    timestamp: AwareDatetime
    event_type: Literal["AUDIT_EVENT"]
    client_ip: IPv4Address | IPv6Address
    client_port: StrictInt = Field(ge=0, le=65535)
    db_user: str
    session_database: str | None
    mysql_command: str
    query_mask_status: Literal["MASKED", "NOT_APPLICABLE", "ERROR"]
    query_masked: str | None
    query_mask_error: str | None
    policy_id: str
    policy_version: str
    runtime_mode: Literal["monitor", "enforce"]
    policy_decision: Decision
    effective_action: Decision
    would_block: StrictBool
    defaulted: StrictBool
    matched_rules: list[str]
    blocking_rules: list[str]
    monitor_rules: list[str]
    allow_rules: list[str]
    reasons: list[str]
    risk_status: Literal["OK", "ERROR"]
    risk_error: str | None
    risk_id: str | None
    risk_version: str | None
    raw_score: StrictInt | None = Field(ge=0)
    risk_score: StrictInt | None = Field(ge=0, le=100)
    severity: Severity | None
    score_breakdown: list[ScoreComponent] | None
    dominant_rule: str | None
    recommended_action: str | None
    default_deny_applied: StrictBool | None
    matched_rule_count: StrictInt | None = Field(ge=0)
    score_component_count: StrictInt | None = Field(ge=0)
    action: Decision
    action_result: Literal["FORWARDED", "BLOCKED", "ERROR"]
    action_error: str | None

    @model_validator(mode="before")
    @classmethod
    def reject_raw_sql(cls, value):
        if isinstance(value, dict) and any(k in value for k in ("raw_sql", "query_raw", "original_sql")):
            raise ValueError("Raw SQL must never be imported")
        return value

    @model_validator(mode="after")
    def validate_risk(self):
        if self.query_mask_status == "MASKED" and not self.query_masked:
            raise ValueError("Masked queries require query_masked")
        if self.query_mask_status == "MASKED" and self.query_mask_error is not None:
            raise ValueError("Successful masking must not contain query_mask_error")
        if self.query_mask_status == "ERROR" and self.query_masked is not None:
            raise ValueError("Failed masking must not expose query text")
        allowed_results = {"ALLOW": {"FORWARDED", "ERROR"}, "BLOCK": {"BLOCKED", "ERROR"}}
        if self.action_result not in allowed_results[self.action]:
            raise ValueError("Action result contradicts the audit action")
        if self.risk_status == "OK":
            if any(v is None for v in (
                self.risk_id, self.risk_version, self.raw_score, self.risk_score, self.severity,
                self.score_breakdown, self.default_deny_applied, self.matched_rule_count,
                self.score_component_count,
            )):
                raise ValueError("Successful risk evaluation requires all result fields")
            if self.risk_error is not None:
                raise ValueError("Successful risk evaluation must not contain risk_error")
            if self.raw_score != sum(x.score for x in self.score_breakdown):
                raise ValueError("Score breakdown does not match raw_score")
            if self.risk_score != min(100, self.raw_score):
                raise ValueError("Invalid score cap")
            expected = ("CRITICAL" if self.risk_score >= 60 else "HIGH" if self.risk_score >= 40
                        else "WARNING" if self.risk_score >= 20 else "LOW")
            if self.severity != expected:
                raise ValueError("Severity does not match risk-v1.0 thresholds")
        elif any(v is not None for v in (
            self.raw_score, self.risk_score, self.severity, self.score_breakdown,
            self.dominant_rule, self.recommended_action, self.default_deny_applied,
            self.matched_rule_count, self.score_component_count,
        )):
            raise ValueError("Failed risk evaluation must not contain fabricated scores")
        return self

    def record(self) -> dict[str, Any]:
        record = self.model_dump(mode="json")
        record["timestamp"] = iso(self.timestamp)
        return record


T = TypeVar("T")


class Envelope(BaseModel, Generic[T]):
    data: T | None
    meta: dict[str, Any]
    error: dict[str, Any] | None = None


class Counts(BaseModel):
    total: int
    allowed: int
    blocked: int
    high_risk: int
    by_severity: dict[str, int]


class EventPage(BaseModel):
    events: list[AuditEvent]
    total: int
    page: int
    page_size: int
    page_count: int
    summary: Counts


class DashboardSummary(BaseModel):
    events: Counts
    unique_client_ips: int
    last_event_at: str | None
    scope: Literal["audit_events_only"] = "audit_events_only"


class EventSeries(BaseModel):
    start: str
    end: str
    bucket: str
    points: list[dict[str, Any]]
