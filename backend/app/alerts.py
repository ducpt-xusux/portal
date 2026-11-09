"""Read P17 outbox records; never generate, acknowledge or deliver alerts."""
from datetime import datetime
from ipaddress import ip_address
import json
from typing import Annotated, Any, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StrictBool, StrictInt, ValidationError

from .p17_snapshot import unique_object
from .schemas import iso, utc_now

Identifier = Annotated[str, Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")]
Code = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Z0-9][A-Z0-9_.:-]*$")]
Kind = Literal["SINGLE_P15_HIGH", "CORRELATED", "OPERATIONAL", "POLICY_VIOLATION", "AUDIT_HEALTH", "SYSTEM_HEALTH", "OTHER"]


class AlertError(Exception):
    pass


class Payload(BaseModel):
    # Unknown upstream properties never leave the adapter, including SQL/secrets.
    model_config = ConfigDict(extra="ignore")
    schema_version: Literal["p17-alert-1"] = Field(alias="schema")
    alert_id: Identifier
    event_id: Identifier
    incident_id: Identifier | None
    rule: Code
    alert_category: Code
    severity: Code
    status: Code
    identity_complete: StrictBool
    source_ip: str | None = Field(default=None, max_length=45)
    evidence_request_count: StrictInt | None = Field(default=None, ge=0)
    p15_peak_risk_score: StrictInt | None = Field(default=None, ge=0, le=100)


class ViewModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AlertProvenance(ViewModel):
    source_system: str
    source_schema: str
    source_ref: str
    read_at: AwareDatetime
    data_as_of: AwareDatetime
    observed_at: AwareDatetime
    freshness_state: Literal["FRESH", "STALE", "HISTORICAL"]
    coverage_kind: Literal["NOT_PROVEN", "CACHE_ONLY"]
    error_code: str | None


class AlertView(ViewModel):
    alert_id: Identifier
    created_at: AwareDatetime
    signal_code: Code
    kind: Kind
    severity: Code
    title: str
    summary: str
    source_ip: str | None
    incident_id: Identifier | None
    event_refs: list[Identifier]
    risk_peak: StrictInt | None = Field(ge=0, le=100)
    review_state: Literal["UNAVAILABLE"] = "UNAVAILABLE"
    review_state_owner: Literal["UNAVAILABLE"] = "UNAVAILABLE"
    source_record_ref: str
    dedup_key: str
    provenance: AlertProvenance


class AlertsPage(ViewModel):
    items: list[AlertView]
    next_cursor: str | None
    has_more: bool
    total_count: int = Field(ge=0)


class AlertsResponse(ViewModel):
    data: AlertsPage
    meta: dict[str, Any]
    error: None = None


class AlertResponse(ViewModel):
    data: AlertView
    meta: dict[str, Any]
    error: None = None


def descriptions(payload):
    if payload.rule == "SINGLE_P15_HIGH":
        return "SINGLE_P15_HIGH", "P15 cao trên một request", "P17 ghi cảnh báo P15 cao cho một request; chưa tự chứng minh có incident tương quan."
    if payload.rule in {"CORR-001", "CORR-002", "CORR-003", "CORR-004", "CORR-005"}:
        title = {"CORR-002": "P17 tương quan SQL injection", "CORR-003": "P17 tương quan truy cập dữ liệu nhạy cảm"}.get(payload.rule, "Cảnh báo tương quan P17")
        summary = f"P17 ghi signal {payload.rule}."
        if payload.evidence_request_count is not None:
            summary += f" Số request evidence theo alert: {payload.evidence_request_count}."
        return "CORRELATED", title, summary
    category = {"OPERATIONAL_REVIEW": "OPERATIONAL", "OPERATIONAL": "OPERATIONAL",
                "POLICY_VIOLATION": "POLICY_VIOLATION", "AUDIT_HEALTH": "AUDIT_HEALTH",
                "SYSTEM_HEALTH": "SYSTEM_HEALTH"}.get(payload.alert_category, "OTHER")
    return category, "Cảnh báo từ P17", f"P17 ghi signal {payload.rule}; nhóm {payload.alert_category}."


def read_alerts(snapshot, error):
    """Validate the recorded identity; do not infer links/counts from incidents."""
    events = {row.event_id: row for row in snapshot.events}
    result = []
    read_at = utc_now()
    state = "STALE" if error else "HISTORICAL" if snapshot.remote_status is None else "FRESH"
    try:
        for row in snapshot.export.tables.outbox:
            payload = Payload.model_validate(json.loads(row.alert_json, object_pairs_hook=unique_object))
            if (payload.alert_id != row.alert_id or payload.event_id != row.event_id
                    or payload.incident_id != row.incident_id):
                raise ValueError("Outbox identity mismatch")
            event = events[row.event_id]
            address = None
            if payload.identity_complete:
                if not event.identity_complete or ip_address(payload.source_ip) != ip_address(event.client_ip):
                    raise ValueError("Source identity mismatch")
                address = str(ip_address(payload.source_ip))
            kind, title, summary = descriptions(payload)
            source_ref = f"p17:{snapshot.metadata['stream_id']}:alert:{row.alert_id}"
            result.append(AlertView(
                alert_id=row.alert_id, created_at=row.created_utc, signal_code=payload.rule,
                kind=kind, severity=payload.severity, title=title, summary=summary,
                source_ip=address, incident_id=row.incident_id, event_refs=[row.event_id],
                risk_peak=payload.p15_peak_risk_score if event.risk_status == "OK" else None,
                source_record_ref=source_ref, dedup_key=row.alert_id,
                provenance=AlertProvenance(
                    source_system="P17 outbox", source_schema="p17-alert-1", source_ref=source_ref,
                    read_at=read_at, data_as_of=snapshot.export.exported_at, observed_at=row.created_utc,
                    freshness_state=state, coverage_kind="CACHE_ONLY" if error else "NOT_PROVEN", error_code=error,
                ),
            ).model_dump(mode="json"))
    except (ValidationError, ValueError, TypeError, KeyError, RecursionError):
        raise AlertError("P17_ALERT_SOURCE_INVALID") from None
    return result


def alert_key(item):
    # Normalize timezone/precision before lexical sorting and cursor comparison.
    return iso(datetime.fromisoformat(item["created_at"].replace("Z", "+00:00"))), item["alert_id"]


def alert_meta(snapshot, error):
    historical = snapshot.remote_status is None
    return {
        "source_system": "P17 outbox", "source_schema": "p17-alert-1",
        "coverage_kind": "CACHE_ONLY" if error else "NOT_PROVEN",
        "coverage_complete": False, "coverage_note": "CURRENT_EXPORTED_OUTBOX_ONLY_NOT_FULL_ALERT_HISTORY",
        "outbox_records": len(snapshot.export.tables.outbox), "alert_review_supported": False,
        "unread_supported": False, "refresh_seconds": 5,
        "data_state": "STALE" if error else "HISTORICAL" if historical else "CURRENT",
    }
