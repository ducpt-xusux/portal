"""Read-only P17 export adapter. No SQLite writes, correlation engine or cloud calls."""
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
from functools import cached_property
import json
import re
from pathlib import Path
import threading
from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StrictInt, ValidationError

from .schemas import iso, utc_now
from .sync_status import read_sync_status


MAX_BYTES = 16 * 1024 * 1024
MAX_ROWS = 100_000
INJECTION = {"INJ-001", "INJ-002", "INJ-006"}
SENSITIVE = {"OBJ-003", "OBJ-004"}


class SnapshotError(Exception):
    def __init__(self, code="P17_SOURCE_UNAVAILABLE"):
        self.code = code
        super().__init__("P17 snapshot is unavailable or invalid.")


class Record(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)


class MetaRow(Record):
    key: str = Field(min_length=1, max_length=128)
    value: str = Field(max_length=4096)


class EventRow(Record):
    stream_id: str = Field(min_length=1, max_length=160)
    event_id: str = Field(min_length=1, max_length=160)
    request_id: str = Field(min_length=1, max_length=160)
    stream_sequence: StrictInt = Field(ge=0)
    payload_sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    source_id: str = Field(min_length=1, max_length=256)
    client_ip: str = Field(min_length=1, max_length=45)
    source_key: str = Field(min_length=1, max_length=1024)
    session_id: str | None = Field(default=None, max_length=256)
    db_user: str | None = Field(default=None, max_length=128)
    identity_complete: Literal[0, 1]
    event_ms: StrictInt = Field(ge=0, le=4102444800000)
    received_utc: AwareDatetime
    risk_status: str = Field(min_length=1, max_length=64)
    risk_score: StrictInt | None = Field(ge=0, le=100)
    blocked: Literal[0, 1]
    rules_json: str = Field(max_length=65536)
    groups_json: str = Field(max_length=65536)
    event_class: Literal["LIVE", "STALE", "HISTORICAL", "OUT_OF_ORDER", "FUTURE_SKEW"]
    live_eligible: Literal[0, 1]


class IncidentRow(Record):
    incident_id: str = Field(min_length=1, max_length=160)
    stream_id: str = Field(min_length=1, max_length=160)
    source_key: str = Field(min_length=1, max_length=1024)
    client_ip: str = Field(min_length=1, max_length=45)
    signal_rule: str = Field(pattern=r"^CORR-00[1-5]$")
    first_ms: StrictInt = Field(ge=0, le=4102444800000)
    last_ms: StrictInt = Field(ge=0, le=4102444800000)
    evidence_count: StrictInt = Field(ge=0)
    peak_p15: StrictInt | None = Field(ge=0, le=100)
    severity: str = Field(min_length=1, max_length=64)
    confidence: str = Field(min_length=1, max_length=128)
    status: str = Field(min_length=1, max_length=128)
    source_verified: Literal[0, 1]
    isolation_authorized: Literal[0, 1]
    created_utc: AwareDatetime
    updated_utc: AwareDatetime


class OutboxRow(Record):
    alert_id: str = Field(min_length=1, max_length=160)
    incident_id: str | None = Field(default=None, max_length=160)
    event_id: str = Field(min_length=1, max_length=160)
    alert_json: str = Field(max_length=131072)
    delivered: Literal[0, 1]
    created_utc: AwareDatetime


class Tables(Record):
    metadata: list[MetaRow] = Field(max_length=MAX_ROWS)
    processed_events: list[EventRow] = Field(max_length=MAX_ROWS)
    incidents: list[IncidentRow] = Field(max_length=MAX_ROWS)
    outbox: list[OutboxRow] = Field(max_length=MAX_ROWS)


class Export(Record):
    export_version: Literal["portal-p17-snapshot-1"]
    exported_at: AwareDatetime
    mode: Literal["SNAPSHOT"]
    tables: Tables


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def string_array(text):
    values = json.loads(text)
    if not isinstance(values, list) or any(not isinstance(x, str) or len(x) > 128 for x in values):
        raise ValueError("Expected bounded string array")
    return values


def ms_iso(value):
    return iso(datetime.fromtimestamp(value / 1000, timezone.utc))


@dataclass(frozen=True)
class Snapshot:
    export: Export
    fingerprint: str
    metadata: dict
    rules: dict
    remote_status: dict | None = None

    @property
    def cursor_fingerprint(self):
        if self.remote_status is None:
            return self.fingerprint
        # Collection time changes every poll; identical source rows keep the cursor valid.
        raw = json.dumps(self.export.tables.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(raw).hexdigest()

    @classmethod
    def parse(cls, raw: bytes):
        try:
            export = Export.model_validate(json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique_object))
            tables = export.tables
            metadata = {row.key: row.value for row in tables.metadata}
            if len(metadata) != len(tables.metadata) or metadata.get("schema") != "p17-incident-durable-1":
                raise ValueError("Schema mismatch")
            stream = metadata.get("stream_id")
            checkpoint = int(metadata["last_committed_sequence"])
            if not stream or checkpoint < 0:
                raise ValueError("Missing stream or checkpoint")
            ids, requests, sequences = set(), set(), set()
            rules = {}
            for row in tables.processed_events:
                if row.stream_id != stream or row.event_id in ids or row.request_id in requests or row.stream_sequence in sequences:
                    raise ValueError("Event identity mismatch")
                if row.stream_sequence > checkpoint or (row.identity_complete and not row.db_user):
                    raise ValueError("Event checkpoint or identity mismatch")
                ids.add(row.event_id); requests.add(row.request_id); sequences.add(row.stream_sequence)
                rules[row.event_id] = tuple(string_array(row.rules_json))
                string_array(row.groups_json)
            incident_ids = set()
            for row in tables.incidents:
                if row.stream_id != stream or row.incident_id in incident_ids or row.first_ms > row.last_ms:
                    raise ValueError("Incident identity mismatch")
                incident_ids.add(row.incident_id)
            alert_ids = set()
            for row in tables.outbox:
                if row.alert_id in alert_ids or row.event_id not in ids or (row.incident_id and row.incident_id not in incident_ids):
                    raise ValueError("Outbox identity mismatch")
                alert = json.loads(row.alert_json, object_pairs_hook=unique_object)
                if not isinstance(alert, dict):
                    raise ValueError("Outbox schema mismatch")
                alert_ids.add(row.alert_id)
            return cls(export, hashlib.sha256(raw).hexdigest(), metadata, rules)
        except (ValueError, TypeError, KeyError, UnicodeError, ValidationError, OverflowError) as exc:
            raise SnapshotError("P17_SOURCE_INVALID") from exc

    @property
    def events(self):
        return self.export.tables.processed_events

    @property
    def incidents(self):
        return self.export.tables.incidents

    def get_incident(self, incident_id):
        return next((x for x in self.incidents if x.incident_id == incident_id), None)

    def evidence(self, incident):
        """Reconstruct links only. Never create incidents, counts, scores or decisions."""
        if incident.signal_rule not in {"CORR-002", "CORR-003"}:
            return None
        window = 60000 if incident.signal_rule == "CORR-002" else 120000
        group = INJECTION if incident.signal_rule == "CORR-002" else SENSITIVE
        return sorted((row for row in self.events if
            row.stream_id == incident.stream_id and row.source_key == incident.source_key
            and row.client_ip == incident.client_ip and row.live_eligible == 1
            and row.event_class == "LIVE" and row.blocked == 1
            and incident.last_ms - window < row.event_ms <= incident.last_ms
            and set(self.rules[row.event_id]) & group), key=lambda row: (row.event_ms, row.stream_sequence))

    def incident_view(self, row):
        evidence = self.evidence(row)
        return {
            "incident_id": row.incident_id, "stream_id": row.stream_id, "source_ip": row.client_ip,
            "source_key_hash": row.source_key if re.fullmatch(r"[a-f0-9]{64}", row.source_key) else hashlib.sha256(row.source_key.encode()).hexdigest(),
            "signal_rule": row.signal_rule, "first_seen": ms_iso(row.first_ms), "last_seen": ms_iso(row.last_ms),
            "created_at": iso(row.created_utc), "updated_at": iso(row.updated_utc),
            "evidence_count": row.evidence_count, "p15_peak_score": row.peak_p15,
            "severity": row.severity, "confidence": row.confidence, "incident_status": row.status,
            "source_verified_recorded": bool(row.source_verified),
            "isolation_authorized_recorded": bool(row.isolation_authorized),
            "response_state": "UNKNOWN", "review_state": None,
            "evidence_membership": "RECONSTRUCTED_WINDOW" if evidence is not None else "UNAVAILABLE",
            "mapping": {"verified": False, "source_ip": row.client_ip, "observed_at": None,
                        "reason": "OPENSTACK_MAPPING_NOT_PROVIDED"},
        }

    def event_view(self, row):
        refs = self.event_incidents.get(row.event_id, [])
        return {
            "stream_id": row.stream_id, "event_id": row.event_id, "request_id": row.request_id,
            "stream_sequence": row.stream_sequence, "occurred_at": ms_iso(row.event_ms), "ingested_at": iso(row.received_utc),
            "source_ip": row.client_ip, "db_user": row.db_user if row.identity_complete else None,
            "database_name": None, "mysql_command": None,
            "decision": "BLOCK" if row.blocked else "ALLOW", "decision_basis": "P17_PERSISTED_BLOCKED_FLAG",
            "matched_rules": list(self.rules[row.event_id]), "blocking_rules": None,
            "risk": {"score": row.risk_score if row.risk_status == "OK" else None, "status": row.risk_status, "severity": None},
            "masked_query": None, "policy_version": None, "p17_event_class": row.event_class,
            "incident_refs": refs, "incident_membership": "RECONSTRUCTED_WINDOW" if refs else "UNAVAILABLE",
            "view_kind": "P17_EVENT_PROJECTION", "canonical_complete": False,
            "source_provenance": {"source_system": "p17-proxy-reader" if self.remote_status is not None else "p17-snapshot", "source_schema": self.metadata["schema"],
                                  "source_ref": f"p17:{row.stream_id}:event:{row.event_id}",
                                  "payload_sha256": row.payload_sha256},
        }

    @cached_property
    def event_incidents(self):
        result = {}
        for incident in self.incidents:
            for event in self.evidence(incident) or []:
                result.setdefault(event.event_id, []).append(incident.incident_id)
        return result

    def timeline(self, incident):
        evidence = self.evidence(incident)
        entries = [{"type": "SQL_REQUEST_RECORDED", "occurred_at": ms_iso(row.event_ms), "source_system": "p17-processed-events",
                    "source_ref": f"p17:{row.stream_id}:event:{row.event_id}", "verification": "SNAPSHOT_PROJECTION",
                    "event_id": row.event_id, "request_id": row.request_id} for row in evidence or []]
        entries.append({"type": "P17_INCIDENT_CREATED", "occurred_at": iso(incident.created_utc), "source_system": "p17-incidents",
                        "source_ref": f"p17:{incident.stream_id}:incident:{incident.incident_id}", "verification": "SNAPSHOT_RECORD"})
        if incident.updated_utc != incident.created_utc:
            entries.append({"type": "P17_INCIDENT_UPDATED", "occurred_at": iso(incident.updated_utc), "source_system": "p17-incidents",
                            "source_ref": f"p17:{incident.stream_id}:incident:{incident.incident_id}", "verification": "SNAPSHOT_RECORD"})
        for alert in self.export.tables.outbox:
            if alert.incident_id == incident.incident_id:
                entries.append({"type": "P17_ALERT_RECORDED", "occurred_at": iso(alert.created_utc), "source_system": "p17-outbox",
                                "source_ref": f"p17:alert:{alert.alert_id}", "verification": "SNAPSHOT_RECORD"})
        return {"incident_id": incident.incident_id, "incident_status": incident.status, "response_state": "UNKNOWN",
                "timeline": sorted(entries, key=lambda item: (item["occurred_at"], item["source_ref"])),
                "network_observation": {"state": "UNKNOWN", "verification": "UNAVAILABLE", "observed_at": None},
                "unavailable_sources": ["p17.5-action-evidence", "nova", "neutron"]}


class SnapshotReader:
    def __init__(self, path: Path | None, status_path: Path | None = None):
        self.path = path
        self.status_path = status_path
        self._snapshot = None
        self._lock = threading.RLock()

    def read(self):
        with self._lock:
            try:
                if self.path is None:
                    raise SnapshotError("P17_SOURCE_NOT_CONFIGURED")
                with self.path.open("rb") as file:
                    raw = file.read(MAX_BYTES + 1)
                if len(raw) > MAX_BYTES:
                    raise SnapshotError("P17_SOURCE_TOO_LARGE")
                digest = hashlib.sha256(raw).hexdigest()
                if self._snapshot is None or self._snapshot.fingerprint != digest:
                    self._snapshot = Snapshot.parse(raw)
                if self.status_path is not None:
                    status, error = read_sync_status(self.status_path, "p17", self._snapshot.fingerprint)
                    self._snapshot = replace(self._snapshot, remote_status=status)
                    return self._snapshot, error
                return self._snapshot, None
            except OSError:
                error = "P17_SOURCE_UNAVAILABLE"
            except SnapshotError as exc:
                error = exc.code
            if self._snapshot is not None:
                return self._snapshot, error
            raise SnapshotError(error)


def snapshot_meta(snapshot, error=None, **extra):
    remote = snapshot.remote_status is not None
    return {
        "read_at": utc_now(), "data_as_of": iso(snapshot.export.exported_at),
        "source_system": "p17-proxy-reader" if remote else "p17-snapshot", "source_schema": snapshot.metadata["schema"],
        "source_ref": "sha256:" + snapshot.fingerprint, "snapshot_sha256": snapshot.fingerprint,
        "source_mode": "REMOTE_READONLY" if remote else "SNAPSHOT",
        "data_state": ("STALE" if error else "CURRENT") if remote else "HISTORICAL",
        "access_mode": "LOCAL_REMOTE_READONLY" if remote else "LOCAL_SNAPSHOT_READONLY",
        "transport": snapshot.remote_status, "collection_mode": "SSH_POLL" if remote else "FILE_EXPORT",
        "freshness_state": "STALE" if error else "FRESH", "stale_after_seconds": 30,
        "last_error_code": error, "stream_id": snapshot.metadata["stream_id"],
        "canonical_history_complete": False, "next_cursor": None, **extra,
    }
