"""Portal v4 views over the validated P16 audit index, never the P17 projection.

A readable log does not prove complete history. Counts describe imported records;
empty, unverified windows/buckets remain unknown rather than fabricated zeroes.
"""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math

from fastapi import HTTPException

from .api import duration, read_source
from .schemas import iso, utc_now
from .canonical_contract import CanonicalEventView


def fail(status, code):
    raise HTTPException(status, {"code": code, "message": "Canonical audit source or requested scope is unavailable."})


@contextmanager
def audit_read(request):
    if not request.app.state.settings.v4_audit_enabled:
        fail(503, "CANONICAL_AUDIT_NOT_CONFIGURED")
    source = read_source(request, canonical=True)
    with request.app.state.store.connection() as db:
        db.execute("BEGIN")
        stats = db.execute("SELECT COUNT(*), MIN(timestamp), MAX(timestamp), MAX(event_id) FROM p16h_audit_index_v1").fetchone()
        canonical_count = db.execute("SELECT COUNT(*) FROM p16h_events_v1").fetchone()[0]
        stored_context = db.execute("SELECT context FROM p16h_store_context_v1 WHERE id=1").fetchone()
        if canonical_count and (not stored_context or stored_context[0] != request.app.state.settings.p16h_import_context):
            fail(503, "P16H_STORE_CONTEXT_MISMATCH")
        historical = request.app.state.settings.mode == "snapshot"
        healthy = source["state"] == "REACHABLE" and not source["pending_bytes"]
        meta = {
            "request_id": request.state.request_id, "read_at": utc_now(), "data_as_of": stats[2],
            "source_system": "p16-canonical-audit", "source_schema": "audit-v1.0",
            "source_mode": "SNAPSHOT" if historical else "REMOTE_READONLY" if source.get("transport") else "LIVE_READONLY",
            "collection_mode": "FILE_EXPORT" if historical else "FILE_TAIL",
            "freshness_state": "FRESH" if healthy else "STALE", "stale_after_seconds": 30,
            "data_state": "HISTORICAL" if historical else "PARTIAL" if healthy else "STALE",
            "last_error_code": source["error_code"] or ("AUDIT_IMPORT_PENDING" if source["pending_bytes"] else None),
            "canonical_history_complete": False,
            "import_status": {key: source[key] for key in ("invalid_records", "duplicate_records", "conflicting_records", "pending_bytes")},
            "available_records": stats[0], "first_event_at": stats[1], "last_event_at": stats[2],
            "next_cursor": None,
        }
        if canonical_count:
            meta.update(source_schema="portal-p16h-import-1+audit-v1.0", coverage_kind="RECENT_SAMPLE",
                        coverage_note="Imported offline profile; retained sample only; producer HEALTH unavailable.",
                        producer_health="UNAVAILABLE", producer_error_code="P16H_HEALTH_NOT_CONNECTED",
                        freshness_state="HISTORICAL" if historical and healthy else "STALE",
                        data_state="HISTORICAL" if historical and healthy else "STALE")
            meta.update(import_context=stored_context[0],
                        population_kind="LEGACY_PLUS_OFFLINE_IMPORT" if stats[0] > canonical_count else "OFFLINE_IMPORT")
        checkpoints = [tuple(row) for row in db.execute(
            "SELECT identity,byte_offset,anchor,invalid_records,conflicting_records FROM audit_checkpoints ORDER BY source")]
        # IDs are immutable and the index is append-only. A changed count invalidates cursors.
        identity = [str(request.app.state.settings.database_path.resolve()), *stats, checkpoints]
        fingerprint = hashlib.sha256(json.dumps(identity).encode()).hexdigest()
        yield db, meta, fingerprint


def envelope(data, meta, **extra):
    return {"data": data, "meta": {**meta, **extra}, "error": None}


def event_view(record, imported_at=None):
    """Explicit allowlist; no synthesized request/stream IDs or incident membership."""
    delivery = record.get("_p16h", {})
    metadata = delivery.get("metadata", {})
    source = delivery.get("source", {})
    projected = record.get("query_text_withheld", False)
    result = {
        "event_id": record["event_id"], "stream_id": delivery.get("stream_id"), "request_id": metadata.get("request_id"),
        "stream_sequence": delivery.get("stream_sequence"),
        "occurred_at": record["timestamp"], "ingested_at": None,
        "request_received_at": metadata.get("request_received_at"),
        "storage_recorded_at": delivery.get("storage_recorded_at"), "imported_at": imported_at,
        "time_basis": {"occurred_at": "record.timestamp", "request_received_at": metadata.get("received_time_basis"),
                       "storage_recorded_at": "delivery.storage_recorded_at" if delivery.get("storage_recorded_at") else None,
                       "imported_at": "PORTAL_CLOCK" if imported_at else None, "ingested_at": None},
        "identity_status": "STREAM_EVENT" if delivery else "LEGACY_EVENT_ONLY",
        "missing_fields_reason": ("SANITIZED_RECENT_PROJECTION: query text, free-text evidence and nested metadata withheld"
                                  if projected else "SOURCE_NOT_PROVIDED; ingested_at has no verified upstream semantic"),
        "source_ip": record["client_ip"], "db_user": record["db_user"],
        "database_name": record["session_database"], "mysql_command": record["mysql_command"],
        "decision": record["policy_decision"], "decision_basis": "P14_POLICY_DECISION",
        "effective_action": record["effective_action"], "runtime_mode": record["runtime_mode"],
        "would_block": record["would_block"],
        "action_result": record["action_result"], "matched_rules": record["matched_rules"],
        "blocking_rules": record["blocking_rules"], "monitor_rules": record["monitor_rules"],
        "policy_id": record["policy_id"], "policy_version": record["policy_version"],
        "reasons": record["reasons"], "raw_score": record["raw_score"],
        "score_breakdown": record["score_breakdown"],
        "risk": {"status": record["risk_status"], "score": record["risk_score"], "severity": record["severity"],
                 "version": record["risk_version"]},
        "masked_query": record["query_masked"] if record["query_mask_status"] == "MASKED" and not projected else None,
        "sql_text_status": "MASKED" if record["query_mask_status"] == "MASKED" and not projected else "WITHHELD",
        "source_metadata": metadata if delivery else None,
        "view_kind": "P16H_CANONICAL_AUDIT", "canonical_complete": not projected,
        "p17_event_class": None, "incident_refs": [], "incident_membership": "UNAVAILABLE",
        "source_provenance": {"source_system": "P16H" if delivery else "p16-canonical-audit",
                              "source_schema": delivery.get("schema_version", "audit-v1.0"),
                              "source_ref": source.get("artifact_id", "audit:event:" + record["event_id"]),
                              "source_host": source.get("source_host"), "source_run_id": source.get("source_run_id"),
                              "collected_at": source.get("collected_at"), "imported_at": imported_at,
                              "payload_sha256": delivery.get("payload_sha256"), "payload_hash_basis": "UPSTREAM_UNVERIFIED" if delivery.get("payload_sha256") else None,
                              "artifact_sha256": source.get("artifact_sha256"),
                              "original_artifact_sha256": source.get("original_artifact_sha256"),
                              "verification": "IMPORTED_UNVERIFIED", "human_review": "UNAVAILABLE",
                              "context": delivery.get("context"), "coverage_kind": "RECENT_SAMPLE" if delivery else "NOT_PROVEN",
                              "delivery_version": delivery.get("delivery_version"), "event_role": delivery.get("event_role"),
                              "journal_stream_id": delivery.get("journal_stream_id"), "journal_sequence": delivery.get("journal_sequence"),
                              "segment_index": delivery.get("segment_index")},
    }
    return CanonicalEventView.model_validate(result).model_dump(mode="json")


def aggregate(request, window, end, bucket=None):
    period = duration(window)
    if period > timedelta(days=30):
        fail(422, "WINDOW_TOO_LARGE")
    interval = duration(bucket) if bucket else None
    if interval and (interval > period or math.ceil(period / interval) > 1000):
        fail(422, "INVALID_BUCKET")
    with audit_read(request) as (db, meta, _):
        historical = meta["source_mode"] == "SNAPSHOT"
        last = datetime.fromisoformat(meta["last_event_at"]) if meta["last_event_at"] else None
        finish = end or (last if historical and last else datetime.now(timezone.utc))
        start = finish - period
        rows = db.execute("SELECT timestamp, policy_decision, json_extract(payload, '$.risk_status') AS risk_status "
                          "FROM p16h_audit_index_v1 WHERE timestamp>=? AND timestamp<=? ORDER BY timestamp",
                          (iso(start), iso(finish))).fetchall()
        coverage = {"state": "UNCONFIRMED", "complete": False,
                    "reason": "EXPORT_COVERAGE_NOT_PROVIDED" if historical else "LOG_HISTORY_COVERAGE_NOT_PROVIDED",
                    "first_event_at": meta["first_event_at"], "last_event_at": meta["last_event_at"],
                    "records_in_window": len(rows), "basis": "IMPORTED_RECORDS_ONLY"}
        data = {"window_from": iso(start), "window_to": iso(finish),
                "window_anchor": "EXPLICIT" if end else "LAST_CANONICAL_EVENT" if historical and last else "CURRENT_TIME",
                "view_kind": "P16H_CANONICAL_AUDIT", "coverage": coverage,
                "event_counts": {"allow": sum(row["policy_decision"] == "ALLOW" for row in rows) if rows else None,
                                 "block": sum(row["policy_decision"] == "BLOCK" for row in rows) if rows else None,
                                 "risk_errors": sum(row["risk_status"] == "ERROR" for row in rows) if rows else None,
                                 "unknown": 0 if rows else None}}
        if interval:
            points = [{"occurred_at": iso(start + i * interval), "allow": None, "block": None,
                       "records": 0, "coverage_complete": False} for i in range(math.ceil(period / interval))]
            for row in rows:
                index = min(len(points) - 1, int((datetime.fromisoformat(row["timestamp"]) - start) / interval))
                point = points[index]
                if not point["records"]:
                    point.update(allow=0, block=0)
                point["records"] += 1
                point["allow" if row["policy_decision"] == "ALLOW" else "block"] += 1
            data["points"] = points
            data["bucket"] = bucket
        return envelope(data, meta)


def events(request, limit, cursor, filters):
    if any(filters.get(key) for key in ("incident_ref", "event_class")):
        fail(503, "CANONICAL_P17_MEMBERSHIP_NOT_PROVIDED")
    clauses, parameters = [], []
    for key, column in (("source_ip", "client_ip"), ("decision", "policy_decision"), ("db_user", "db_user"), ("stream_id", "stream_id")):
        if filters.get(key):
            clauses.append(column + "=?")
            parameters.append(filters[key])
    for key, operator in (("from", ">="), ("to", "<=")):
        if filters.get(key):
            clauses.append("timestamp" + operator + "?")
            parameters.append(filters[key])
    if filters.get("rule"):
        clauses.append("EXISTS (SELECT 1 FROM json_each(payload, '$.matched_rules') WHERE value=?)")
        parameters.append(filters["rule"])
    if filters.get("risk_status"):
        clauses.append("json_extract(payload, '$.risk_status')=?")
        parameters.append(filters["risk_status"])
    for key, operator in (("risk_min", ">="), ("risk_max", "<=")):
        if filters.get(key) is not None:
            clauses.extend(["json_extract(payload, '$.risk_status')='OK'", "json_extract(payload, '$.risk_score')" + operator + "?"])
            parameters.append(filters[key])
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    scope = hashlib.sha256(json.dumps(["canonical-events", filters, limit], sort_keys=True).encode()).hexdigest()
    with audit_read(request) as (db, meta, fingerprint):
        total = db.execute("SELECT COUNT(*) FROM p16h_audit_index_v1" + where, parameters).fetchone()[0]
        if cursor:
            after = request.app.state.p17_cursors.decode(cursor, scope, fingerprint, (str, str, str))
            where += (" AND " if where else " WHERE ") + "(timestamp,event_id,COALESCE(stream_id,''))<(?,?,?)"
            parameters.extend(after)
        rows = db.execute("SELECT timestamp,event_id,stream_id,imported_at,payload FROM p16h_audit_index_v1" + where +
                          " ORDER BY timestamp DESC,event_id DESC,COALESCE(stream_id,'') DESC LIMIT ?", (*parameters, limit + 1)).fetchall()
        more = len(rows) > limit
        selected = rows[:limit]
        next_cursor = request.app.state.p17_cursors.encode(scope, fingerprint, (selected[-1]["timestamp"], selected[-1]["event_id"], selected[-1]["stream_id"] or "")) if more else None
        return envelope({"items": [event_view(json.loads(row["payload"]), row["imported_at"]) for row in selected]}, meta,
                        next_cursor=next_cursor, has_more=more, total_count=total,
                        time_scope="EXPLICIT_FILTER" if filters.get("from") or filters.get("to") else "ALL_IMPORTED_AUDIT")


def detail(request, event_id, stream_id):
    with audit_read(request) as (db, meta, _):
        rows = db.execute("SELECT payload,imported_at FROM p16h_audit_index_v1 WHERE event_id=?" +
                          (" AND stream_id=?" if stream_id else "") + " LIMIT 2",
                          (event_id, stream_id) if stream_id else (event_id,)).fetchall()
        if not rows:
            fail(404, "EVENT_NOT_FOUND")
        if len(rows) > 1:
            fail(409, "CANONICAL_EVENT_ID_AMBIGUOUS")
        return envelope(event_view(json.loads(rows[0]["payload"]), rows[0]["imported_at"]), meta)
