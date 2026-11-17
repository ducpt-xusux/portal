"""P17.1 read-only validation and synthetic evidence correlation candidate.

This module has no socket writes, SQL connection, OpenStack access, or service changes.
Thresholds are TEST CANDIDATES, not production authorization rules.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


class EvidenceError(ValueError):
    pass


GROUPS = {
    "injection": frozenset({"INJ-001", "INJ-002", "INJ-006", "INJ-007", "INJ-008"}),
    "sensitive_data": frozenset({"OBJ-003", "OBJ-004"}),
    "reconnaissance": frozenset({"ENUM-001"}),
    "privilege_or_destructive": frozenset({"DCL-001", "DDL-001"}),
    "file_access": frozenset({"FILE-001"}),
    "stacked_statements": frozenset({"PROTO-003"}),
}
COMPAT = frozenset({"PROTO-001", "PROTO-010"})
KNOWN_RULES = frozenset(['PROTO-001', 'PROTO-003', 'PROTO-010', 'OBJ-003', 'OBJ-004', 'OBJ-005', 'VIEW-001', 'DML-010', 'DML-011', 'DML-012', 'CTX-001', 'CTX-006', 'CTX-003', 'DML-001', 'DML-002', 'DDL-001', 'DCL-001', 'INJ-001', 'INJ-002', 'INJ-003', 'INJ-006', 'ENUM-001', 'FILE-001', 'RES-001', 'RES-002', 'RES-004', 'RES-005', 'READ-001', 'READ-004', 'ADMIN-001', 'ADMIN-002', 'ALLOW-HEALTH-001', 'ALLOW-USE-001', 'ALLOW-READER-001', 'ALLOW-WRITER-SELECT-001', 'ALLOW-WRITER-INSERT-001', 'ALLOW-WRITER-UPDATE-001', 'CTX-007', 'INJ-007', 'INJ-008'])
CORR_SEVERITY = {"CORR-001": "WARNING", "CORR-002": "HIGH", "CORR-003": "HIGH", "CORR-004": "CRITICAL", "CORR-005": "WARNING"}
SEV_RANK = {"WARNING": 1, "HIGH": 2, "CRITICAL": 3}


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


def aware_date(x: str) -> datetime:
    if not isinstance(x, str):
        raise EvidenceError("INVALID_TIMESTAMP")
    try:
        dt = datetime.fromisoformat(x.replace("Z", "+00:00"))
    except (ValueError, TypeError) as exc:
        raise EvidenceError("INVALID_TIMESTAMP") from exc
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise EvidenceError("TIMESTAMP_MISSING_TZ")
    return dt.astimezone(timezone.utc)


@dataclass(frozen=True)
class Event:
    source_id: str
    event_id: str
    request_id: str
    time_utc: datetime
    client_ip: str
    db_user: str | None
    identity_complete: bool
    matched_rules: frozenset[str]
    risk_score: int | None
    risk_status: str
    blocked: bool
    action_result: str
    payload_sha256: str

    @property
    def source_key(self):
        return (self.source_id, self.client_ip, self.db_user)

    @property
    def group_signals(self):
        return frozenset(k for k, rules in GROUPS.items() if self.matched_rules & rules)

    @property
    def signature(self):
        return tuple(sorted(self.matched_rules & frozenset.union(*GROUPS.values())))


def normalize(delivery: dict) -> Event:
    """Accept P16H canonical delivery wrapper, never use raw SQL/reasons."""
    if not isinstance(delivery, dict) or delivery.get("delivery_version") != "p16h-local-1":
        raise EvidenceError("DELIVERY_VERSION_MISMATCH")
    if delivery.get("event_role") != "CANONICAL_AUDIT_DELIVERY":
        raise EvidenceError("DELIVERY_ROLE_MISMATCH")
    if not isinstance(delivery.get("stream_id"), str) or not delivery["stream_id"]:
        raise EvidenceError("STREAM_ID_MISSING")
    if type(delivery.get("stream_sequence")) is not int or delivery["stream_sequence"] < 1:
        raise EvidenceError("STREAM_SEQUENCE_INVALID")
    env = delivery.get("envelope")
    if not isinstance(env, dict) or not isinstance(env.get("record"), dict) or not isinstance(env.get("metadata"), dict):
        raise EvidenceError("ENVELOPE_INVALID")
    if env.get("schema_version") != "1.2.0-candidate" or env.get("stream_role") != "SHADOW":
        raise EvidenceError("ENVELOPE_VERSION_MISMATCH")
    r, m = env["record"], env["metadata"]
    if r.get("event_type") != "AUDIT_EVENT":
        raise EvidenceError("RECORD_TYPE_INVALID")
    eid = env.get("event_id")
    if not isinstance(eid, str) or not eid or r.get("event_id") != eid:
        raise EvidenceError("EVENT_ID_MISMATCH")
    if r.get("policy_id") != "db-firewall-main":
        raise EvidenceError("POLICY_VERSION_MISMATCH")
    if r.get("risk_id") != "db-firewall-risk":
        raise EvidenceError("RISK_VERSION_MISMATCH")
    if (r.get("policy_version"), r.get("risk_version")) not in {
        ("1.4.0", "1.0.0"), ("1.4.1-G03-RC5", "1.0.1-G03-RC6")
    }:
        raise EvidenceError("POLICY_RISK_VERSION_PAIR_MISMATCH")
    if r.get("runtime_mode") != "enforce":
        raise EvidenceError("NOT_ENFORCE_MODE")
    if r.get("effective_action") not in ("ALLOW", "BLOCK") or r.get("action_result") not in ("FORWARDED", "BLOCKED", "ERROR"):
        raise EvidenceError("ACTION_INVALID")
    rules = r.get("matched_rules")
    if not isinstance(rules, list) or any(not isinstance(x, str) or not x for x in rules):
        raise EvidenceError("RULE_IDS_INVALID")
    if any(rule not in KNOWN_RULES for rule in rules):
        raise EvidenceError("UNKNOWN_POLICY_RULE_ID")
    if r["effective_action"] == "ALLOW" and r["action_result"] == "BLOCKED":
        raise EvidenceError("ACTION_RESULT_CONFLICT")
    if r["effective_action"] == "BLOCK" and r["action_result"] == "FORWARDED":
        raise EvidenceError("ACTION_RESULT_CONFLICT")
    client_ip = r.get("client_ip")
    try:
        ipaddress.ip_address(client_ip)
    except (ValueError, TypeError) as exc:
        raise EvidenceError("SOURCE_IP_INVALID") from exc
    user = r.get("db_user")
    privacy = m.get("privacy")
    if not isinstance(privacy, dict):
        raise EvidenceError("PRIVACY_METADATA_MISSING")
    clear_user = privacy.get("db_user_status") == "CLEAR_ALLOWED"
    if clear_user:
        if not isinstance(user, str) or not user:
            raise EvidenceError("DB_USER_INVALID")
    else:
        user = None
    source_id = m.get("producer_id")
    if not isinstance(source_id, str) or not source_id:
        raise EvidenceError("PRODUCER_ID_MISSING")
    rid = m.get("request_id")
    if not isinstance(rid, str) or not rid:
        raise EvidenceError("REQUEST_ID_MISSING")
    when = aware_date(m.get("request_received_at"))
    score = r.get("risk_score")
    status = r.get("risk_status")
    if status == "OK":
        if type(score) is not int or not (0 <= score <= 100):
            raise EvidenceError("RISK_SCORE_INVALID")
    elif status == "ERROR":
        if score is not None:
            raise EvidenceError("ERROR_MUST_HAVE_NULL_SCORE")
    else:
        raise EvidenceError("RISK_STATUS_INVALID")
    ph = delivery.get("payload_sha256")
    if not isinstance(ph, str) or len(ph) != 64 or any(c not in '0123456789abcdef' for c in ph):
        raise EvidenceError("PAYLOAD_SHA_INVALID")
    # H2B envelope uses canonical compact JSON; a mismatch indicates altered payload.
    if hashlib.sha256(canonical(env)).hexdigest() != ph:
        raise EvidenceError("PAYLOAD_HASH_MISMATCH")
    return Event(
        source_id=source_id, event_id=eid, request_id=rid, time_utc=when,
        client_ip=client_ip, db_user=user, identity_complete=clear_user,
        matched_rules=frozenset(rules), risk_score=score, risk_status=status,
        blocked=r["effective_action"] == "BLOCK" and r["action_result"] == "BLOCKED",
        action_result=r["action_result"], payload_sha256=ph)


def evaluate_candidate(events: list[Event]) -> dict:
    """Deterministic offline correlation; NO live alert or containment decision."""
    ordered = sorted(events, key=lambda x: (x.time_utc, x.source_id, x.client_ip, x.db_user or "", x.event_id))
    seen: dict[tuple[str, str], str] = {}
    history: dict[tuple[str, str, str | None], list[Event]] = defaultdict(list)
    alerts = []
    for ev in ordered:
        identity = (ev.source_id, ev.event_id)
        old = seen.get(identity)
        if old is not None:
            if old != ev.payload_sha256:
                raise EvidenceError("EVENT_ID_PAYLOAD_CONFLICT")
            continue
        seen[identity] = ev.payload_sha256
        key = ev.source_key
        existing = history[key]
        existing[:] = [x for x in existing if 0 <= (ev.time_utc - x.time_utc).total_seconds() < 120]
        existing.append(ev)

        def window(seconds: int):
            return [x for x in existing if 0 <= (ev.time_utc-x.time_utc).total_seconds() < seconds]

        w60, w120 = window(60), window(120)
        matched: dict[str, list[Event]] = {}
        a = [x for x in w60 if x.blocked and not (x.matched_rules and x.matched_rules <= COMPAT)]
        if len(a) >= 5: matched["CORR-001"] = a
        a = [x for x in w60 if x.blocked and x.matched_rules & GROUPS["injection"]]
        if len(a) >= 3: matched["CORR-002"] = a
        a = [x for x in w120 if x.blocked and x.matched_rules & GROUPS["sensitive_data"]]
        if len(a) >= 3: matched["CORR-003"] = a
        a = [x for x in w120 if x.blocked and x.group_signals]
        if (len(a) >= 3 and len(set().union(*(x.group_signals for x in a))) >= 3
                and len({x.signature for x in a}) >= 2):
            matched["CORR-004"] = a
        a = [x for x in w120 if x.matched_rules & COMPAT]
        if len(a) >= 5: matched["CORR-005"] = a
        if matched:
            evidence = {x.event_id: x for sub in matched.values() for x in sub}
            peak_scores = [x.risk_score for x in evidence.values() if x.risk_score is not None]
            alerts.append({
                "event_type": "P17_CANDIDATE_REPLAY_RESULT",
                "group": {"source_id": key[0], "client_ip": key[1], "db_user": key[2]},
                "trigger_event_id": ev.event_id,
                "rules": sorted(matched),
                "correlation_severity": max((CORR_SEVERITY[x] for x in matched), key=SEV_RANK.get),
                "p15_peak_risk_score": max(peak_scores) if peak_scores else None,
                "evidence_event_count": len(evidence),
                "evidence_event_ids": sorted(evidence)[:20],
                "source_identity_complete": all(x.identity_complete for x in evidence.values()),
                "recommended_action": "REVIEW",
                "action_executed": "NONE",
                "isolation_authorized": False,
            })
    return {"input_events": len(ordered), "distinct_events": len(seen), "candidate_triggers": alerts,
            "p15_critical_request_count": len({(event.source_id, event.event_id) for event in ordered if event.risk_score is not None and event.risk_score >= 60}),
            "historical_replay_only": True, "action_executed": "NONE", "isolation_authorized": False}
