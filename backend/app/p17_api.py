"""Local, explicitly enabled P17 snapshot read API for Portal v4."""
import base64
from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from ipaddress import ip_address
import json
import math
import secrets
import time
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from pydantic import AwareDatetime, IPvAnyAddress, BaseModel, ConfigDict
from .remote_console import ConsoleError

from .api import duration, require_key
from .p17_snapshot import SnapshotError, ms_iso, snapshot_meta
from .schemas import iso, utc_now
from .sync_status import read_sync_status
from . import canonical_audit
from .proxy_services import read_services
from .galera_snapshot import read_galera
from .openstack_inventory import InventoryError
from .incident_mapping import IncidentMapping
from .alerts import AlertError, AlertResponse, AlertsResponse, Kind, alert_key, alert_meta, read_alerts
from .dashboard_funnel import (FunnelResponse, RunsResponse, RunResponse, build_funnel, evaluation_response)


def fail(status, code, message="The requested source or capability is unavailable."):
    raise HTTPException(status, {"code": code, "message": message})


def require_snapshot_access(request: Request):
    settings = request.app.state.settings
    if settings.p17_snapshot_path is None:
        fail(503, "P17_SOURCE_NOT_CONFIGURED")
    require_read_access(request)


def require_read_access(request: Request):
    settings = request.app.state.settings
    if getattr(request.state, "business_principal", None) is not None:
        return
    # An existing configured API key is always checked by require_key first.
    if settings.api_key:
        return
    if not settings.p17_local_readonly:
        fail(503, "P17_ACCESS_NOT_CONFIGURED")
    try:
        local = request.client is not None and ip_address(request.client.host).is_loopback
    except ValueError:
        local = False
    if not local:
        fail(403, "LOCAL_SNAPSHOT_ONLY")


router = APIRouter(prefix="/api/v1", tags=["P17 snapshot"],
                   dependencies=[Depends(require_key), Depends(require_snapshot_access)])
observation_auth_router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_key), Depends(require_snapshot_access)])
evaluation_run_router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_key), Depends(require_read_access)])
IdPath = Annotated[str, Path(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")]


class CursorCodec:
    def __init__(self):
        self.key = secrets.token_bytes(32)

    def encode(self, scope, fingerprint, after):
        raw = json.dumps({"v": 1, "scope": scope, "source": fingerprint,
                          "after": after, "exp": int(time.time()) + 600}, separators=(",", ":")).encode()
        token = base64.urlsafe_b64encode(raw).rstrip(b"=")
        signature = hmac.new(self.key, token, hashlib.sha256).hexdigest().encode()
        return (token + b"." + signature).decode()

    def decode(self, token, scope, fingerprint, types):
        try:
            encoded, signature = token.encode().split(b".")
            expected = hmac.new(self.key, encoded, hashlib.sha256).hexdigest().encode()
            if not hmac.compare_digest(signature, expected):
                raise ValueError("Signature")
            value = json.loads(base64.b64decode(encoded + b"=" * (-len(encoded) % 4), altchars=b"-_", validate=True))
            if value.get("v") != 1 or value.get("scope") != scope or type(value.get("exp")) is not int or value["exp"] < time.time():
                raise ValueError("Scope or expiry")
            after = value.get("after")
            if not isinstance(after, list) or len(after) != len(types) or any(type(x) is not kind for x, kind in zip(after, types)):
                raise ValueError("Position")
            if value.get("source") != fingerprint:
                fail(412, "SOURCE_SNAPSHOT_CHANGED", "Source changed; restart pagination.")
            return tuple(after)
        except (ValueError, TypeError, KeyError, UnicodeError, AttributeError):
            fail(400, "INVALID_CURSOR", "Cursor is invalid, expired or belongs to different filters.")


def read(request):
    try:
        return request.app.state.p17_reader.read()
    except SnapshotError as error:
        fail(503, error.code)


def envelope(request, snapshot, error, data, **meta):
    return {"data": data, "meta": {"request_id": request.state.request_id, **snapshot_meta(snapshot, error, **meta)}, "error": None}


def incident_or_404(snapshot, incident_id):
    result = snapshot.get_incident(incident_id)
    if result is None:
        fail(404, "INCIDENT_NOT_FOUND", "Incident was not found in this snapshot.")
    return result


def check_range(start, finish):
    if start and finish and start > finish:
        fail(400, "INVALID_TIME_RANGE", "from must not exceed to.")
    if start and finish and finish - start > timedelta(days=30):
        fail(422, "WINDOW_TOO_LARGE", "Maximum explicit time range is 30 days.")


def in_range(ms, start, finish):
    return (start is None or ms >= start.timestamp() * 1000) and (finish is None or ms <= finish.timestamp() * 1000)


def page(request, snapshot, error, rows, key, view, limit, cursor, endpoint, filters):
    material = json.dumps([endpoint, filters, limit], sort_keys=True, separators=(",", ":"))
    scope = hashlib.sha256(material.encode()).hexdigest()
    codec = request.app.state.p17_cursors
    ordered = sorted(rows, key=key, reverse=True)
    total = len(ordered)
    if cursor:
        types = (int, str) if endpoint == "incidents" else (int, int, str)
        after = codec.decode(cursor, scope, snapshot.cursor_fingerprint, types)
        ordered = [row for row in ordered if key(row) < after]
    selected = ordered[:limit]
    more = len(ordered) > limit
    next_cursor = codec.encode(scope, snapshot.cursor_fingerprint, key(selected[-1])) if more else None
    return envelope(request, snapshot, error, {"items": [view(row) for row in selected]},
                    next_cursor=next_cursor, has_more=more, total_count=total,
                    time_scope="EXPLICIT_FILTER" if filters.get("from") or filters.get("to") else "ALL_SNAPSHOT")


@observation_auth_router.get("/auth/me")
def local_capabilities(request: Request):
    snapshot, error = read(request)
    remote = snapshot.remote_status is not None
    return envelope(request, snapshot, error, {"user": None, "access_mode": "LOCAL_REMOTE_READONLY" if remote else "LOCAL_SNAPSHOT_READONLY",
        "capabilities": ["incidents:read", "events:read", "timeline:read", "sources:read", "workloads:read", "alerts:read"],
        "incident_filters": {"review_state": False, "response_states": ["UNKNOWN"]},
        "source_mode": "REMOTE_READONLY" if remote else "SNAPSHOT", "exported_at": iso(snapshot.export.exported_at),
        "session_supported": False, "write_enabled": False})


def alert_source(request):
    snapshot, error = read(request)
    try:
        return snapshot, error, read_alerts(snapshot, error)
    except AlertError:
        fail(503, "P17_ALERT_SOURCE_INVALID", "P17 outbox records are unavailable or incompatible.")


@router.get("/alerts", response_model=AlertsResponse)
def alerts(
    request: Request,
    limit: Annotated[int, Query(ge=1, le=100)] = 10,
    cursor: Annotated[str | None, Query(max_length=2048)] = None,
    source_ip: IPvAnyAddress | None = None,
    signal_code: Annotated[str | None, Query(max_length=64, pattern=r"^[A-Z0-9][A-Z0-9_.:-]*$")] = None,
    severity: Annotated[str | None, Query(max_length=64, pattern=r"^[A-Z0-9][A-Z0-9_.:-]*$")] = None,
    kind: Kind | None = None,
    from_: Annotated[AwareDatetime | None, Query(alias="from")] = None,
    to: AwareDatetime | None = None,
):
    check_range(from_, to)
    snapshot, error, items = alert_source(request)
    items = [item for item in items if
             (not source_ip or item["source_ip"] == str(source_ip))
             and (not signal_code or item["signal_code"] == signal_code)
             and (not severity or item["severity"] == severity) and (not kind or item["kind"] == kind)
             and (from_ is None or alert_key(item)[0] >= iso(from_))
             and (to is None or alert_key(item)[0] <= iso(to))]
    ordered = sorted(items, key=alert_key, reverse=True)
    total = len(ordered)
    scope = hashlib.sha256(json.dumps(["alerts", limit, str(source_ip) if source_ip else None,
        signal_code, severity, kind, iso(from_) if from_ else None, iso(to) if to else None]).encode()).hexdigest()
    codec = request.app.state.p17_cursors
    if cursor:
        after = codec.decode(cursor, scope, snapshot.cursor_fingerprint, (str, str))
        ordered = [item for item in ordered if alert_key(item) < after]
    selected, more = ordered[:limit], len(ordered) > limit
    next_cursor = codec.encode(scope, snapshot.cursor_fingerprint, alert_key(selected[-1])) if more else None
    return envelope(request, snapshot, error,
        {"items": selected, "has_more": more, "next_cursor": next_cursor, "total_count": total},
        **alert_meta(snapshot, error), next_cursor=next_cursor, has_more=more, total_count=total)


@router.get("/alerts/{alert_id}", response_model=AlertResponse)
def alert_detail(request: Request, alert_id: IdPath):
    snapshot, error, items = alert_source(request)
    item = next((item for item in items if item["alert_id"] == alert_id), None)
    if item is None:
        fail(404, "ALERT_NOT_FOUND", "Alert was not found in the collected P17 outbox.")
    return envelope(request, snapshot, error, item, **alert_meta(snapshot, error))


@router.get("/incidents")
def incidents(
    request: Request,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    cursor: Annotated[str | None, Query(max_length=2048)] = None,
    source_ip: IPvAnyAddress | None = None,
    signal_rule: Literal["CORR-001", "CORR-002", "CORR-003", "CORR-004", "CORR-005"] | None = None,
    severity: Annotated[str | None, Query(max_length=64)] = None,
    status: Annotated[str | None, Query(max_length=128)] = None,
    from_: Annotated[AwareDatetime | None, Query(alias="from")] = None,
    to: AwareDatetime | None = None,
    review_state: Annotated[str | None, Query(max_length=64)] = None,
    response_state: Annotated[str | None, Query(max_length=64)] = None,
):
    check_range(from_, to)
    if review_state:
        fail(503, "PORTAL_REVIEW_NOT_CONFIGURED")
    if response_state and response_state != "UNKNOWN":
        fail(503, "P17_5_NOT_CONFIGURED")
    snapshot, error = read(request)
    rows = [row for row in snapshot.incidents if
            (not source_ip or row.client_ip == str(source_ip)) and (not signal_rule or row.signal_rule == signal_rule)
            and (not severity or row.severity == severity) and (not status or row.status == status)
            and in_range(row.last_ms, from_, to)]
    filters = {"source_ip": str(source_ip) if source_ip else None, "signal_rule": signal_rule, "severity": severity,
               "status": status, "from": iso(from_) if from_ else None, "to": iso(to) if to else None,
               "review_state": review_state, "response_state": response_state}
    mapping = IncidentMapping(request.app.state.openstack_inventory)
    return page(request, snapshot, error, rows, lambda row: (row.last_ms, row.incident_id),
                lambda row: mapping.view(snapshot, row), limit, cursor, "incidents", filters)


@router.get("/incidents/{incident_id}")
def incident_detail(request: Request, incident_id: IdPath):
    snapshot, error = read(request)
    incident = incident_or_404(snapshot, incident_id)
    mapping = IncidentMapping(request.app.state.openstack_inventory)
    return envelope(request, snapshot, error, mapping.view(snapshot, incident))


@router.get("/incidents/{incident_id}/evidence")
def incident_evidence(request: Request, incident_id: IdPath, limit: Annotated[int, Query(ge=1, le=100)] = 100):
    snapshot, error = read(request)
    incident = incident_or_404(snapshot, incident_id)
    rows = snapshot.evidence(incident)
    return envelope(request, snapshot, error, {
        "items": [snapshot.event_view(row) for row in (rows or [])[:limit]],
        "evidence_membership": "RECONSTRUCTED_WINDOW" if rows is not None else "UNAVAILABLE",
        "recorded_evidence_count": incident.evidence_count, "reconstructed_request_count": len(rows) if rows is not None else None,
        "matches_recorded_count": len(rows) == incident.evidence_count if rows is not None else None,
        "has_more": len(rows or []) > limit,
    })


@router.get("/incidents/{incident_id}/decision")
def decision_unavailable(request: Request, incident_id: IdPath):
    snapshot, _ = read(request)
    incident_or_404(snapshot, incident_id)
    fail(503, "P17_3_DECISION_NOT_PROVIDED", "A snapshot is not a live P17.3 decision or action authorization.")


@router.get("/events")
def events(
    request: Request,
    source: Literal["p17", "canonical"] = "p17",
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    cursor: Annotated[str | None, Query(max_length=2048)] = None,
    source_ip: IPvAnyAddress | None = None,
    decision: Literal["ALLOW", "BLOCK", "UNKNOWN"] | None = None,
    rule: Annotated[str | None, Query(max_length=128)] = None,
    incident_ref: Annotated[str | None, Query(max_length=160)] = None,
    event_class: Annotated[str | None, Query(max_length=64)] = None,
    risk_status: Annotated[str | None, Query(max_length=64)] = None,
    risk_min: Annotated[int | None, Query(ge=0, le=100)] = None,
    risk_max: Annotated[int | None, Query(ge=0, le=100)] = None,
    db_user: Annotated[str | None, Query(max_length=128)] = None,
    stream_id: Annotated[str | None, Query(max_length=160)] = None,
    from_: Annotated[AwareDatetime | None, Query(alias="from")] = None,
    to: AwareDatetime | None = None,
):
    check_range(from_, to)
    if risk_min is not None and risk_max is not None and risk_min > risk_max:
        fail(400, "INVALID_RISK_RANGE")
    if source == "canonical":
        return canonical_audit.events(request, limit, cursor, {
            "source_ip": str(source_ip) if source_ip else None, "decision": decision, "rule": rule,
            "incident_ref": incident_ref, "event_class": event_class, "risk_status": risk_status,
            "risk_min": risk_min, "risk_max": risk_max, "db_user": db_user, "stream_id": stream_id,
            "from": iso(from_) if from_ else None, "to": iso(to) if to else None,
        })
    snapshot, error = read(request)
    member_ids = None
    if incident_ref:
        incident = incident_or_404(snapshot, incident_ref)
        evidence = snapshot.evidence(incident)
        if evidence is None:
            fail(503, "EVIDENCE_MEMBERSHIP_UNAVAILABLE")
        member_ids = {row.event_id for row in evidence}
    rows = []
    for row in snapshot.events:
        if source_ip and row.client_ip != str(source_ip): continue
        if stream_id and row.stream_id != stream_id: continue
        if decision and decision != ("BLOCK" if row.blocked else "ALLOW"): continue
        if rule and rule not in snapshot.rules[row.event_id]: continue
        if member_ids is not None and row.event_id not in member_ids: continue
        if event_class and row.event_class != event_class: continue
        if risk_status and row.risk_status != risk_status: continue
        if db_user and (not row.identity_complete or row.db_user != db_user): continue
        if (risk_min is not None or risk_max is not None) and (row.risk_status != "OK" or row.risk_score is None): continue
        if risk_min is not None and row.risk_score < risk_min: continue
        if risk_max is not None and row.risk_score > risk_max: continue
        if not in_range(row.event_ms, from_, to): continue
        rows.append(row)
    filters = {"source_ip": str(source_ip) if source_ip else None, "decision": decision, "rule": rule,
               "incident_ref": incident_ref, "event_class": event_class, "risk_status": risk_status,
               "risk_min": risk_min, "risk_max": risk_max, "db_user": db_user, "stream_id": stream_id,
               "from": iso(from_) if from_ else None, "to": iso(to) if to else None}
    return page(request, snapshot, error, rows, lambda row: (row.event_ms, row.stream_sequence, row.event_id),
                snapshot.event_view, limit, cursor, "events", filters)


@router.get("/events/{event_id}")
def event_detail(request: Request, event_id: IdPath, stream_id: Annotated[str | None, Query(max_length=160)] = None,
                 source: Literal["p17", "canonical"] = "p17"):
    if source == "canonical":
        return canonical_audit.detail(request, event_id, stream_id)
    snapshot, error = read(request)
    row = next((row for row in snapshot.events if row.event_id == event_id and (not stream_id or row.stream_id == stream_id)), None)
    if row is None:
        fail(404, "EVENT_NOT_FOUND", "Event was not found in this stream and snapshot.")
    return envelope(request, snapshot, error, snapshot.event_view(row))


def snapshot_window(snapshot, window, end):
    period = duration(window)
    if period > timedelta(days=30): fail(422, "WINDOW_TOO_LARGE")
    last = max((row.event_ms for row in snapshot.events), default=None)
    finish = end or (datetime.now(timezone.utc) if snapshot.remote_status is not None else
                    datetime.fromtimestamp(last / 1000, timezone.utc) if last is not None else snapshot.export.exported_at)
    return finish - period, finish


def incident_breakdown(snapshot):
    # Snapshot validation enforces unique incident IDs. Never join events/outbox
    # here: multiple requests or alerts do not create extra incidents.
    severities = Counter(row.severity for row in snapshot.incidents)
    signals = Counter(row.signal_rule for row in snapshot.incidents)
    ordered_severities = ["CRITICAL", "HIGH", "WARNING", "LOW"]
    ordered_severities += sorted(set(severities) - set(ordered_severities))
    return {
        "total": len(snapshot.incidents), "scope": "ALL_P17_INCIDENTS",
        "basis": "DISTINCT_INCIDENT_IDS",
        "by_severity": [{"severity": severity, "count": severities[severity]} for severity in ordered_severities],
        "by_signal": [{"signal_rule": f"CORR-00{n}", "count": signals[f"CORR-00{n}"]} for n in range(1, 6)],
    }


@router.get("/dashboard/summary")
def dashboard_summary(request: Request, window: Annotated[str, Query(max_length=12)] = "15m", end: AwareDatetime | None = None):
    if request.app.state.settings.v4_audit_enabled:
        result = canonical_audit.aggregate(request, window, end)
        data = result["data"]
        data.update(incident_counts={"review_required": None, "critical": None}, incident_breakdown=None, quarantined_workloads=None,
                    sources={"audit": result["meta"].copy(), "p17": {"freshness_state": "UNKNOWN"},
                             "neutron": {"freshness_state": "UNKNOWN"}},
                    protection_path=[{"name": name, "status": "UNKNOWN", "observed_at": None}
                                     for name in ("SQL clients", "DB Firewall", "Galera Cluster")])
        try:
            snapshot, error = request.app.state.p17_reader.read()
            data["incident_counts"] = {"review_required": sum(row.status == "REVIEW_REQUIRED" for row in snapshot.incidents),
                                       "critical": sum(row.severity == "CRITICAL" for row in snapshot.incidents)}
            data["incident_breakdown"] = incident_breakdown(snapshot)
            data["sources"]["p17"] = snapshot_meta(snapshot, error)
        except SnapshotError as error:
            data["sources"]["p17"]["last_error_code"] = error.code
        return result
    snapshot, error = read(request)
    start, finish = snapshot_window(snapshot, window, end)
    rows = [row for row in snapshot.events if in_range(row.event_ms, start, finish)]
    return envelope(request, snapshot, error, {
        "window_from": iso(start), "window_to": iso(finish), "window_anchor": "EXPLICIT" if end else "CURRENT_TIME" if snapshot.remote_status is not None else "LAST_P17_EVENT",
        "event_counts": {"allow": sum(row.blocked == 0 for row in rows), "block": sum(row.blocked == 1 for row in rows),
                         "unknown": 0, "risk_errors": sum(row.risk_status != "OK" for row in rows)},
        "incident_counts": {"review_required": sum(row.status == "REVIEW_REQUIRED" for row in snapshot.incidents),
                            "critical": sum(row.severity == "CRITICAL" for row in snapshot.incidents)},
        "incident_breakdown": incident_breakdown(snapshot),
        "quarantined_workloads": None, "sources": {"p17": snapshot_meta(snapshot, error), "neutron": {"freshness_state": "UNKNOWN"}},
        "protection_path": [{"name": name, "status": "UNKNOWN", "observed_at": None}
                            for name in ("SQL clients", "DB Firewall", "Galera Cluster")],
        "projection_counts": {"processed_events": len(snapshot.events), "incidents": len(snapshot.incidents),
                              "outbox": len(snapshot.export.tables.outbox)},
        "view_kind": "P17_EVENT_PROJECTION",
    })


@router.get('/dashboard/decision-funnel', response_model=FunnelResponse)
def decision_funnel(request: Request, window: Literal['15m','1h','24h']='15m', end: AwareDatetime | None=None,
                    context: Literal['LIVE','EVALUATION']='LIVE',
                    run_id: Annotated[str | None, Query(max_length=100,pattern=r'^[A-Za-z0-9][A-Za-z0-9_.-]*$')]=None):
    return build_funnel(request,window,end,context,run_id)


@evaluation_run_router.get('/evaluations/runs', response_model=RunsResponse)
def evaluation_runs(request: Request):
    return evaluation_response(request)


@evaluation_run_router.get('/evaluations/runs/{run_id}', response_model=RunResponse)
def evaluation_run(request: Request,run_id: Annotated[str,Path(max_length=100,pattern=r'^[A-Za-z0-9][A-Za-z0-9_.-]*$')]):
    return evaluation_response(request,run_id)


@router.get("/dashboard/event-series")
def dashboard_series(request: Request, window: Annotated[str, Query(max_length=12)] = "15m",
                     bucket: Annotated[str, Query(max_length=12)] = "1m", end: AwareDatetime | None = None):
    if request.app.state.settings.v4_audit_enabled:
        return canonical_audit.aggregate(request, window, end, bucket)
    snapshot, error = read(request)
    start, finish = snapshot_window(snapshot, window, end)
    interval = duration(bucket)
    total = math.ceil((finish - start) / interval)
    if interval > finish - start or total > 1000:
        fail(422, "INVALID_BUCKET")
    points = [{"occurred_at": iso(start + i * interval), "allow": 0, "block": 0} for i in range(total)]
    for row in snapshot.events:
        if in_range(row.event_ms, start, finish):
            index = min(total - 1, max(0, int((row.event_ms / 1000 - start.timestamp()) / interval.total_seconds())))
            points[index]["block" if row.blocked else "allow"] += 1
    return envelope(request, snapshot, error, {"window_from": iso(start), "window_to": iso(finish), "points": points})


@router.get("/system/proxy-services")
def proxy_services(request: Request):
    result = read_services(request.app.state.settings.proxy_services_path)
    return {"data": {"components": result["components"]},
            "meta": {"request_id": request.state.request_id, **result["source"]}, "error": None}


@router.get("/system/health")
def system_health(request: Request):
    snapshot, error = read(request)
    components = [{"component_id": "p17-snapshot-reader", "name": "Proxy P17 SSH reader" if snapshot.remote_status is not None else "P17 snapshot reader", "status": "DEGRADED" if error else "HEALTHY",
                   "observed_at": utc_now(), "last_success": None if error else utc_now(), "last_attempt": utc_now(),
                   "source_ref": "sha256:" + snapshot.fingerprint}]
    components.extend({"component_id": name, "name": name, "status": "UNKNOWN", "observed_at": None,
                       "last_success": None, "last_attempt": None, "source_ref": None}
                      for name in ("P17 worker live", "P16H canonical reader", "P17.5 controller", "Nova / Neutron", "Galera"))
    services = read_services(request.app.state.settings.proxy_services_path)
    return envelope(request, snapshot, error, {"components": components + services["components"],
                                              "proxy_services_source": services["source"]})


@router.get("/system/data-sources")
def data_sources(request: Request):
    snapshot, error = read(request)
    remote = snapshot.remote_status
    items = [{"source_system": "Proxy P17 via SSH" if remote is not None else "P17 snapshot", "source_schema": snapshot.metadata["schema"],
              "source_mode": "REMOTE_READONLY" if remote is not None else "SNAPSHOT", "freshness_state": "STALE" if error else "FRESH",
              "data_as_of": iso(snapshot.export.exported_at), "last_success": remote.get("last_success") if remote is not None else None if error else utc_now(),
              "last_attempt": remote.get("last_attempt") if remote is not None else utc_now(), "last_error_code": error}]
    if request.app.state.settings.proxy_sync_status_path is not None and not (
        request.app.state.settings.v4_audit_enabled and request.app.state.settings.mode == "snapshot"
    ):
        audit, audit_error = read_sync_status(request.app.state.settings.proxy_sync_status_path, "audit")
        items.append({"source_system": "Proxy audit.jsonl via SSH (current file only)", "source_schema": "audit-v1.0",
                      "source_mode": "REMOTE_READONLY", "freshness_state": "STALE" if audit_error else "FRESH",
                      "last_success": audit.get("last_success"), "last_attempt": audit.get("last_attempt"),
                      "data_as_of": audit.get("last_success"), "last_error_code": audit_error})
    if request.app.state.settings.v4_audit_enabled:
        try:
            with canonical_audit.audit_read(request) as (_, audit_meta, _):
                items.append({**audit_meta, "source_system": "P16H canonical audit (independent source)",
                              "coverage_complete": False})
        except HTTPException:
            items.append({"source_system": "P16H canonical audit", "freshness_state": "UNKNOWN",
                          "last_error_code": "CANONICAL_AUDIT_UNAVAILABLE"})
    if request.app.state.settings.proxy_services_path is not None:
        items.append(read_services(request.app.state.settings.proxy_services_path)["source"])
    if request.app.state.settings.galera_snapshot_dir is not None:
        items.append(read_galera(request.app.state.settings.galera_snapshot_dir)["meta"])
    return envelope(request, snapshot, error, {"items": items})


@router.get("/workloads")
def workloads(request: Request,
              limit: Annotated[int, Query(ge=1, le=100)] = 25,
              cursor: Annotated[str | None, Query(max_length=2048)] = None,
              name: Annotated[str | None, Query(max_length=128)] = None,
              project_id: Annotated[str | None, Query(max_length=64)] = None,
              network_state: Literal["UNKNOWN", "NORMAL", "QUARANTINED", "MISMATCH"] | None = None):
    items, meta, fingerprint = workload_read(request)
    if project_id and project_id != request.app.state.settings.openstack_project_id:
        fail(403, "OPENSTACK_PROJECT_OUTSIDE_SCOPE")
    if network_state and network_state != "UNKNOWN":
        fail(503, "NETWORK_CLASSIFICATION_NOT_CONFIGURED")
    if name:
        items = [item for item in items if name.casefold() in (item["name"] or "").casefold()]
    total = len(items)
    scope = hashlib.sha256(json.dumps(["workloads", name, project_id, network_state, limit]).encode()).hexdigest()
    key = lambda item: ((item["name"] or "").casefold(), item["server_id"])
    codec = request.app.state.p17_cursors
    if cursor:
        after = codec.decode(cursor, scope, fingerprint, (str, str))
        items = [item for item in items if key(item) > after]
    selected, more = items[:limit], len(items) > limit
    next_cursor = codec.encode(scope, fingerprint, key(selected[-1])) if more else None
    return {"data": {"items": selected}, "meta": {"request_id": request.state.request_id, **meta,
            "next_cursor": next_cursor, "has_more": more, "total_count": total}, "error": None}


def workload_read(request):
    try:
        return request.app.state.openstack_inventory.read()
    except InventoryError as error:
        fail(503, error.code)


@router.get("/workloads/{server_id}")
def workload_detail(request: Request, server_id: IdPath):
    items, meta, _ = workload_read(request)
    item = next((item for item in items if item["server_id"] == server_id), None)
    if item is None:
        fail(404, "WORKLOAD_NOT_FOUND")
    return {"data": item, "meta": {"request_id": request.state.request_id, **meta}, "error": None}


@router.get("/workloads/{server_id}/ports")
def workload_ports(request: Request, server_id: IdPath):
    result = workload_detail(request, server_id)
    result["data"] = {"items": result["data"]["ports"]}
    return result


class ConsoleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    protocol: Literal["vnc"] = "vnc"
    type: Literal["novnc"] = "novnc"


def console_access(request):
    try:
        local = request.client is not None and ip_address(request.client.host).is_loopback
    except ValueError:
        local = False
    if not local:
        fail(403, "CONSOLE_LOOPBACK_ONLY")
    if request.method == "POST" and (request.headers.get("origin") not in request.app.state.settings.cors_origins
            or request.headers.get("x-portal-console") != "connect"):
        fail(403, "CONSOLE_ORIGIN_REJECTED")


@router.get("/workloads/{server_id}/console")
def console_capabilities(request: Request, server_id: IdPath):
    console_access(request)
    try:
        data = request.app.state.console_service.capabilities()
    except ConsoleError as error:
        fail(error.status, error.code)
    return {"data": data, "meta": {"request_id": request.state.request_id, "read_at": utc_now()}, "error": None}


@router.post("/workloads/{server_id}/console")
def console_create(request: Request, server_id: IdPath, body: ConsoleRequest):
    console_access(request)
    try:
        data = request.app.state.console_service.create(server_id)
    except ConsoleError as error:
        fail(error.status, error.code)
    return {"data": data, "meta": {"request_id": request.state.request_id, "read_at": utc_now()}, "error": None}


@router.get("/system/galera")
def galera_status(request: Request):
    directory = request.app.state.settings.galera_snapshot_dir
    if directory is None:
        fail(503, "GALERA_NOT_CONFIGURED")
    result = read_galera(directory)
    result["meta"]["request_id"] = request.state.request_id
    return result
