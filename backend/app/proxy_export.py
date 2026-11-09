"""Standalone stdlib-only Proxy reader, sent on SSH stdin; never installed on Proxy."""
import base64
from datetime import datetime, timezone
import json
import os
import sqlite3
import time

P17_PATH = "/var/lib/db-firewall-p17/state.sqlite3"
AUDIT_PATH = "/var/log/db-firewall/audit.jsonl"
MAX_P17_BYTES = 16 * 1024 * 1024
MAX_AUDIT_BYTES = 8 * 1024 * 1024
MAX_ROWS = 100_000

# Select only the known P17 contract. Future tables/columns are not exported.
COLUMNS = {
    "metadata": "key,value",
    "processed_events": "stream_id,event_id,request_id,stream_sequence,payload_sha256,source_id,client_ip,source_key,session_id,db_user,identity_complete,event_ms,received_utc,risk_status,risk_score,blocked,rules_json,groups_json,event_class,live_eligible",
    "incidents": "incident_id,stream_id,source_key,client_ip,signal_rule,first_ms,last_ms,evidence_count,peak_p15,severity,confidence,status,source_verified,isolation_authorized,created_utc,updated_utc",
    "outbox": "alert_id,incident_id,event_id,alert_json,delivered,created_utc",
}


def now():
    return datetime.now(timezone.utc).isoformat()


def read_p17(path=P17_PATH):
    db = sqlite3.connect("file:" + path + "?mode=ro", uri=True, timeout=3)
    try:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA query_only=ON")
        deadline = time.monotonic() + 5
        db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        db.execute("BEGIN")
        tables = {}
        for table, columns in COLUMNS.items():
            rows = db.execute("SELECT " + columns + " FROM " + table + " LIMIT ?", (MAX_ROWS + 1,)).fetchall()
            if len(rows) > MAX_ROWS:
                raise ValueError("P17_TOO_LARGE")
            tables[table] = [dict(row) for row in rows]
        payload = {"export_version": "portal-p17-snapshot-1", "exported_at": now(),
                   "mode": "SNAPSHOT", "tables": tables}
        if len(json.dumps(payload, ensure_ascii=False).encode("utf-8")) > MAX_P17_BYTES:
            raise ValueError("P17_TOO_LARGE")
        return payload
    finally:
        db.rollback()
        db.close()


def read_audit(path=AUDIT_PATH):
    with open(path, "rb") as source:
        before = os.fstat(source.fileno())
        if before.st_size > MAX_AUDIT_BYTES:
            raise ValueError("AUDIT_TOO_LARGE")
        raw = source.read(before.st_size)
        after = os.fstat(source.fileno())
        if len(raw) != before.st_size or after.st_size < before.st_size:
            raise ValueError("AUDIT_CHANGED_DURING_READ")
    boundary = raw.rfind(b"\n") + 1
    return {"base64": base64.b64encode(raw[:boundary]).decode("ascii"),
            "pending_bytes": len(raw) - boundary, "bytes_at_read": before.st_size}


def collect():
    result = {"version": 1, "p17": {}, "audit": {}}
    for name, reader in (("p17", read_p17), ("audit", read_audit)):
        try:
            result[name] = {"ok": True, "payload": reader()}
        except (OSError, sqlite3.Error, ValueError):
            result[name] = {"ok": False, "error_code": name.upper() + "_REMOTE_READ_FAILED"}
    return result


if __name__ == "__main__":
    print(json.dumps(collect(), ensure_ascii=False, separators=(",", ":")))
