from datetime import datetime, timedelta, timezone
import hmac
import json
import math
import re
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.security import APIKeyHeader
from pydantic import AwareDatetime, IPvAnyAddress

from .schemas import (
    AuditEvent, DashboardSummary, Decision, Envelope, EventPage, EventSeries, Severity, iso, utc_now,
)


key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_key(request: Request, key: Annotated[str | None, Depends(key_header)]):
    expected = request.app.state.settings.api_key
    if expected and (not key or not hmac.compare_digest(key.encode(), expected.encode())):
        raise HTTPException(401, {"code": "UNAUTHORIZED", "message": "A valid X-API-Key is required."})


router = APIRouter(prefix="/api", dependencies=[Depends(require_key)])


def response(request: Request, data, source=None):
    meta = {"request_id": request.state.request_id, "timestamp": utc_now()}
    if source is not None:
        meta["audit_source"] = source
        meta["data_state"] = (
            "STALE" if source["state"] in {"UNREACHABLE", "STORE_ERROR"} else
            "DEGRADED" if source["state"] == "DEGRADED" else
            "HISTORICAL" if source["mode"] == "snapshot" else
            "CATCHING_UP" if source["pending_bytes"] else "CURRENT"
        )
    return {"data": data, "meta": meta, "error": None}


def read_source(request: Request, canonical=False):
    source = request.app.state.importer.sync()
    with request.app.state.store.connection() as db:
        total = db.execute("SELECT COUNT(*) FROM " + ("p16h_audit_index_v1" if canonical else "security_events")).fetchone()[0]
    source["cached_events"] = total
    if not total and source["state"] != "REACHABLE":
        raise HTTPException(503, {"code": "AUDIT_SOURCE_UNAVAILABLE",
                                  "message": "Audit source is unavailable or contains no usable records.",
                                  "audit_source": source})
    return source


def event_filters(
    severity: Severity | None = None,
    decision: Decision | None = None,
    client_ip: IPvAnyAddress | None = None,
    db_user: Annotated[str | None, Query(max_length=128)] = None,
    rule: Annotated[str | None, Query(max_length=128)] = None,
    action_result: Literal["FORWARDED", "BLOCKED", "ERROR"] | None = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
    start: AwareDatetime | None = None,
    end: AwareDatetime | None = None,
):
    if start and end and start > end:
        raise HTTPException(400, {"code": "INVALID_TIME_RANGE", "message": "start must not exceed end."})
    clauses, parameters = [], []
    for column, value in (("severity", severity), ("policy_decision", decision),
                          ("client_ip", str(client_ip) if client_ip else None),
                          ("db_user", db_user), ("action_result", action_result)):
        if value is not None:
            clauses.append(f"{column}=?")
            parameters.append(value)
    if rule:
        clauses.append("EXISTS (SELECT 1 FROM json_each(payload, '$.matched_rules') WHERE value=?)")
        parameters.append(rule)
    if q:
        clauses.append("(instr(lower(COALESCE(query_masked,'')),lower(?))>0 OR "
                       "instr(lower(event_id),lower(?))>0)")
        parameters.extend((q, q))
    for operator, date in ((">=", start), ("<=", end)):
        if date:
            clauses.append(f"timestamp {operator} ?")
            parameters.append(iso(date))
    return ("WHERE " + " AND ".join(clauses) if clauses else "", parameters)


@router.get("/events", response_model=Envelope[EventPage], tags=["Events"])
def events(
    request: Request,
    filters: Annotated[tuple, Depends(event_filters)],
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 50,
):
    source = read_source(request)
    where, parameters = filters
    store = request.app.state.store
    with store.connection() as db:
        # A single read transaction keeps counts and page contents consistent during imports.
        db.execute("BEGIN")
        summary = store.counts(db, where, parameters)
        rows = db.execute(
            "SELECT payload FROM security_events " + where
            + " ORDER BY timestamp DESC, event_id DESC LIMIT ? OFFSET ?",
            (*parameters, page_size, (page - 1) * page_size),
        ).fetchall()
    return response(request, {
        "events": [json.loads(row["payload"]) for row in rows], "total": summary["total"],
        "page": page, "page_size": page_size,
        "page_count": max(1, math.ceil(summary["total"] / page_size)), "summary": summary,
    }, source)


@router.get("/events/{event_id}", response_model=Envelope[AuditEvent], tags=["Events"])
def event_detail(request: Request, event_id: UUID):
    source = read_source(request)
    with request.app.state.store.connection() as db:
        row = db.execute("SELECT payload FROM security_events WHERE event_id=?", (str(event_id),)).fetchone()
    if not row:
        raise HTTPException(404, {"code": "EVENT_NOT_FOUND", "message": "Event was not found."})
    return response(request, json.loads(row["payload"]), source)


def duration(value: str) -> timedelta:
    match = re.fullmatch(r"([1-9][0-9]{0,4})(m|h|d)", value)
    if not match:
        raise HTTPException(422, {"code": "INVALID_DURATION", "message": "Use a duration such as 60m, 1h or 7d."})
    number, unit = match.groups()
    return timedelta(seconds=int(number) * {"m": 60, "h": 3600, "d": 86400}[unit])


def time_window(window: str, end: datetime | None):
    period = duration(window)
    if period > timedelta(days=7):
        raise HTTPException(422, {"code": "WINDOW_TOO_LARGE", "message": "Maximum window is 7d."})
    finish = end.astimezone(timezone.utc) if end else datetime.now(timezone.utc)
    return finish - period, finish


@router.get("/dashboard/summary", response_model=Envelope[DashboardSummary], tags=["Dashboard"])
def dashboard_summary(
    request: Request, window: Annotated[str, Query(max_length=12)] = "24h",
    end: AwareDatetime | None = None,
):
    start, finish = time_window(window, end)
    source = read_source(request)
    store = request.app.state.store
    where = "WHERE timestamp>=? AND timestamp<=?"
    parameters = (iso(start), iso(finish))
    with store.connection() as db:
        db.execute("BEGIN")
        counts = store.counts(db, where, parameters)
        extra = db.execute("SELECT COUNT(DISTINCT client_ip), MAX(timestamp) FROM security_events " + where,
                           parameters).fetchone()
    source.update(window_start=iso(start), window_end=iso(finish))
    return response(request, {"events": counts, "unique_client_ips": extra[0], "last_event_at": extra[1]}, source)


@router.get("/dashboard/event-series", response_model=Envelope[EventSeries], tags=["Dashboard"])
def event_series(
    request: Request,
    window: Annotated[str, Query(max_length=12)] = "60m",
    bucket: Annotated[str, Query(max_length=12)] = "5m",
    end: AwareDatetime | None = None,
):
    start, finish = time_window(window, end)
    interval = duration(bucket)
    count = math.ceil((finish - start) / interval)
    if interval > finish - start or count > 1000:
        raise HTTPException(422, {"code": "INVALID_BUCKET", "message": "Bucket must fit the window; maximum 1000 buckets."})
    source = read_source(request)
    points = [{"timestamp": iso(start + i * interval), "allowed": 0, "blocked": 0, "total": 0}
              for i in range(count)]
    with request.app.state.store.connection() as db:
        rows = db.execute("""SELECT CAST((unixepoch(timestamp)-?)/? AS INTEGER) AS bucket_index,
            policy_decision, COUNT(*) AS n FROM security_events
            WHERE timestamp>=? AND timestamp<=? GROUP BY bucket_index, policy_decision""",
            (start.timestamp(), interval.total_seconds(), iso(start), iso(finish))).fetchall()
    for row in rows:
        point = points[min(count - 1, max(0, row["bucket_index"]))]
        point["allowed" if row["policy_decision"] == "ALLOW" else "blocked"] += row["n"]
        point["total"] += row["n"]
    return response(request, {"start": iso(start), "end": iso(finish), "bucket": bucket, "points": points}, source)


@router.get("/system/health", response_model=Envelope[dict], tags=["System"])
def system_health(request: Request):
    source = request.app.state.importer.sync()
    with request.app.state.store.connection() as db:
        total = db.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
        last = db.execute("SELECT MAX(timestamp) FROM security_events").fetchone()[0]
        # Verify a real SQLite write without retaining a health record in the transaction.
        db.execute("SAVEPOINT health_probe")
        db.execute("INSERT OR REPLACE INTO portal_health_probe VALUES (1,?)", (utc_now(),))
        db.execute("ROLLBACK TO health_probe")
        db.execute("RELEASE health_probe")
        first = db.execute("SELECT MIN(timestamp) FROM security_events").fetchone()[0]
        metadata = audit_metadata(db)
    return response(request, {
        "scope": "portal_and_audit_only", "portal": "REACHABLE", "sqlite": "REACHABLE",
        "cached_events": total, "last_event_at": last, "audit_source": source,
        "openstack": "NOT_CONFIGURED", "firewall_listener": "NOT_CONFIGURED", "galera": "NOT_CONFIGURED",
        "first_event_at": first, "metadata": metadata,
        "storage": {"format": "jsonl", "encoding": "utf-8", "source_access": "read_only",
                    "sqlite_probe": "read_write_rollback", "deduplication_key": "event_id"},
        "writer_status": "UNKNOWN",
        "writer_note": "File readability and event timestamps do not independently verify the P16 writer process.",
    }, source)


def audit_metadata(db):
    versions = [dict(row) for row in db.execute("""SELECT
        json_extract(payload,'$.policy_id') AS policy_id,
        json_extract(payload,'$.policy_version') AS policy_version,
        json_extract(payload,'$.risk_id') AS risk_id,
        json_extract(payload,'$.risk_version') AS risk_version,
        json_extract(payload,'$.runtime_mode') AS runtime_mode,
        COUNT(*) AS event_count, MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen
        FROM security_events GROUP BY policy_id,policy_version,risk_id,risk_version,runtime_mode
        ORDER BY last_seen DESC""")]
    return {"scope": "observed_audit_metadata", "versions": versions,
            "note": "Versions and modes were recorded on events; they are not a live configuration probe."}


@router.get("/system/audit-schema", response_model=Envelope[dict], tags=["System"])
def audit_schema(request: Request):
    schema = AuditEvent.model_json_schema()
    return response(request, {
        "audit_id": "db-firewall-audit", "audit_version": "1.0.0", "event_type": "AUDIT_EVENT",
        "field_count": len(AuditEvent.model_fields), "required_fields": schema["required"],
        "fields": schema["properties"], "json_schema": schema,
        "privacy": {"store_raw_sql": False, "allowed_query_field": "query_masked",
                    "forbidden_fields": ["raw_sql", "query_raw", "original_sql"]},
        "scope": "backend_supported_contract",
        "note": "Contract supported by this backend, checked against the provided P16 schema. Not a live Proxy config read.",
    })


@router.get("/rules", response_model=Envelope[dict], tags=["Rules"])
def observed_rules(request: Request):
    source = read_source(request)
    with request.app.state.store.connection() as db:
        # One row per rule/version/score observed in the evidence. Never invent enabled status or a full catalog.
        rows = db.execute("""SELECT json_extract(part.value,'$.rule_id') AS rule_id,
            json_extract(part.value,'$.score') AS score,
            json_extract(part.value,'$.category') AS category,
            json_extract(part.value,'$.reason') AS description,
            json_extract(e.payload,'$.policy_version') AS policy_version,
            json_extract(e.payload,'$.risk_version') AS risk_version,
            COUNT(*) AS event_count, MAX(e.timestamp) AS last_seen
            FROM security_events e, json_each(e.payload,'$.score_breakdown') part
            WHERE json_extract(part.value,'$.rule_id') IS NOT NULL
            GROUP BY rule_id,score,category,description,policy_version,risk_version
            ORDER BY rule_id,policy_version,risk_version,score""").fetchall()
        defaults = db.execute("SELECT COUNT(*) FROM security_events WHERE json_extract(payload,'$.default_deny_applied')=1").fetchone()[0]
    return response(request, {
        "rules": [{**dict(row), "enabled": None, "origin": "observed_audit"} for row in rows],
        "scope": "observed_audit_only", "total_observed_rules": len({row["rule_id"] for row in rows}),
        "default_deny_event_count": defaults, "complete_catalog": False,
        "note": "Only rules present in P16 evidence; enabled status and the full policy catalog are not available from this log.",
    }, source)
