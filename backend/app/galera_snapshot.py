"""Read Galera wsrep observations from local snapshots."""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StrictBool, model_validator

from .proxy_services import observation_metadata, unique_object
from .schemas import iso

NODES = ("galera-1", "galera-2", "galera-3")
FIELDS = (
    "wsrep_cluster_status", "wsrep_cluster_size", "wsrep_local_state_comment",
    "wsrep_ready", "wsrep_connected", "wsrep_cluster_state_uuid",
    "wsrep_local_state_uuid", "wsrep_cluster_conf_id",
)
MAX_BYTES = 65536
TTL = 45


@contextmanager
def batch_lock(directory, *, exclusive=False):
    # The Linux collector and API coordinate on the directory inode.
    if os.name != "posix":
        yield
        return
    import fcntl

    try:
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        if exclusive:
            raise
        yield
        return
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield
    finally:
        os.close(descriptor)


def freshness(stamp, now):
    if stamp is None:
        return "UNKNOWN"
    return "FRESH" if -5 <= (now - stamp).total_seconds() <= TTL else "STALE"


def consistent_primary(nodes, expected_size):
    return len(nodes) == expected_size and all(
        node["wsrep_cluster_status"].upper() == "PRIMARY"
        and node["wsrep_cluster_size"] == expected_size
        and node["wsrep_local_state_comment"].upper() == "SYNCED"
        and node["wsrep_ready"].upper() == node["wsrep_connected"].upper() == "ON"
        and node["wsrep_cluster_state_uuid"]
        and node["wsrep_local_state_uuid"]
        and UUID(node["wsrep_cluster_state_uuid"]).int != 0
        and UUID(node["wsrep_cluster_state_uuid"]) == UUID(node["wsrep_local_state_uuid"])
        for node in nodes
    ) and len({UUID(node["wsrep_cluster_state_uuid"]) for node in nodes}) == 1 and len({
        int(node["wsrep_cluster_conf_id"]) for node in nodes
    }) == 1


class NodeExport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["portal-galera-node-1"] = Field(alias="schema")
    source_host: Literal["galera-1", "galera-2", "galera-3"]
    mode: Literal["SNAPSHOT"]
    scope: Literal["LOCAL_SOCKET_WSREP"]
    attempted_at: AwareDatetime
    observed_at: AwareDatetime | None
    collected_at: AwareDatetime
    read_ok: StrictBool
    batch_id: UUID | None = None
    metrics: dict[str, str]
    error_code: Literal["WSREP_READ_FAILED", "WSREP_FIELDS_MISSING", "WSREP_TIMEOUT",
                        "WSREP_CLIENT_UNAVAILABLE", "WSREP_RESULT_INVALID",
                        "WSREP_SOURCE_UNREACHABLE"] | None

    @model_validator(mode="after")
    def check_observation(self):
        if self.attempted_at > self.collected_at or set(self.metrics) - set(FIELDS):
            raise ValueError("Invalid observation")
        if any(len(value) > 128 for value in self.metrics.values()):
            raise ValueError("Oversized metric")
        if self.read_ok:
            if set(self.metrics) != set(FIELDS) or self.observed_at is None or self.error_code is not None:
                raise ValueError("Incomplete successful observation")
            if not self.attempted_at <= self.observed_at <= self.collected_at:
                raise ValueError("Invalid observation time")
            for key in ("wsrep_cluster_size", "wsrep_cluster_conf_id"):
                value = self.metrics[key]
                if not value.isascii() or not value.isdecimal() or len(value) > 20:
                    raise ValueError("Invalid numeric metric")
            for key in ("wsrep_cluster_state_uuid", "wsrep_local_state_uuid"):
                if self.metrics[key]:
                    UUID(self.metrics[key])
        elif self.observed_at is not None or self.error_code is None:
            raise ValueError("Invalid failed attempt")
        return self


def read_node(directory: Path, name: str, now: datetime):
    exported, digest, error = None, None, None
    try:
        with (directory / (name + ".json")).open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("Oversized source")
        exported = NodeExport.model_validate(json.loads(raw, object_pairs_hook=unique_object))
        if exported.source_host != name or exported.collected_at > now + timedelta(seconds=5):
            raise ValueError("Wrong host or future source")
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    except OSError:
        error = "GALERA_NODE_UNAVAILABLE"
    except (ValueError, UnicodeError, RecursionError):
        error = "GALERA_NODE_INVALID"
    if error:
        exported = None
    observed = exported.observed_at if exported else None
    read_ok = bool(exported and exported.read_ok)
    metrics = exported.metrics if read_ok else {}
    healthy = read_ok and (
        metrics["wsrep_cluster_status"].upper() == "PRIMARY"
        and int(metrics["wsrep_cluster_size"]) == len(NODES)
        and metrics["wsrep_local_state_comment"].upper() == "SYNCED"
        and metrics["wsrep_ready"].upper() == metrics["wsrep_connected"].upper() == "ON"
        and bool(metrics["wsrep_cluster_state_uuid"])
        and bool(metrics["wsrep_local_state_uuid"])
        and UUID(metrics["wsrep_cluster_state_uuid"]).int != 0
        and UUID(metrics["wsrep_cluster_state_uuid"]) == UUID(metrics["wsrep_local_state_uuid"])
    ) if read_ok else False
    error_code = error or (exported.error_code if exported else None)
    observation_freshness = freshness(observed, now)
    collection_freshness = freshness(exported.collected_at if exported else None, now)
    source_availability = "UNKNOWN"
    if exported:
        source_availability = (
            "UNREACHABLE" if error_code == "WSREP_SOURCE_UNREACHABLE" else "REACHED"
        )
    if error_code in {"GALERA_NODE_INVALID", "WSREP_RESULT_INVALID"}:
        observation_status = "INVALID"
    elif "STALE" in (collection_freshness, observation_freshness):
        observation_status = "STALE"
    elif read_ok:
        observation_status = "OK"
    elif source_availability == "UNREACHABLE":
        observation_status = "COLLECTOR_UNREACHABLE"
    elif exported:
        observation_status = "DB_READ_FAILED"
    else:
        observation_status = "UNAVAILABLE"
    return {
        "node_id": name, "name": name, "source_host": name,
        "source_mode": "SNAPSHOT", "scope": "LOCAL_SOCKET_WSREP",
        "status": "UNKNOWN", "current_status": "UNKNOWN",
        "health_at_observation": "HEALTHY" if healthy else "DEGRADED" if read_ok else "UNKNOWN",
        "read_ok": read_ok, "source_read_ok": exported is not None,
        "batch_id": str(exported.batch_id) if exported and exported.batch_id else None,
        "attempted_at": iso(exported.attempted_at) if exported else None,
        "observed_at": iso(observed) if observed else None,
        "collected_at": iso(exported.collected_at) if exported else None,
        "observation_freshness_state": observation_freshness,
        "collection_freshness_state": collection_freshness,
        "observation_status": observation_status,
        "source_availability": source_availability,
        "db_availability": "OBSERVED" if read_ok else "UNKNOWN",
        "source_ref": digest, "last_error_code": error_code,
        **{key: (int(metrics[key]) if key == "wsrep_cluster_size" and key in metrics else metrics.get(key)) for key in FIELDS},
    }


def read_galera(directory: Path, now: datetime | None = None):
    with batch_lock(directory):
        now = now or datetime.now(timezone.utc)
        nodes = [read_node(directory, name, now) for name in NODES]
    valid = [node for node in nodes if node["read_ok"]]
    observations = observation_metadata(nodes)
    start, end = observations["observation_from"], observations["observation_to"]
    complete = len(valid) == len(NODES)
    periodic = any(node["batch_id"] for node in nodes)
    same_batch = periodic and len({node["batch_id"] for node in nodes}) == 1
    collection_states = {node["collection_freshness_state"] for node in nodes}
    fresh_batch = same_batch and collection_states == {"FRESH"}
    agreement = complete and (
        all(node["wsrep_cluster_size"] == len(NODES) for node in valid)
        and all(node["wsrep_cluster_state_uuid"] for node in valid)
        and len({str(UUID(node["wsrep_cluster_state_uuid"])) for node in valid}) == 1
        and len({int(node["wsrep_cluster_conf_id"]) for node in valid}) == 1
    )
    healthy = sum(node["health_at_observation"] == "HEALTHY" for node in nodes)
    current_status = "UNKNOWN"
    reason = "GALERA_BATCH_UNVERIFIED"
    if fresh_batch:
        current = [node for node in valid if node["observation_freshness_state"] == "FRESH"]
        reason = "GALERA_WSREP_INCONCLUSIVE"
        if consistent_primary(current, len(NODES)):
            current_status, reason = "HEALTHY", "GALERA_PRIMARY_COMPLETE"
        elif len(valid) == len(NODES) - 1 and consistent_primary(current, len(NODES) - 1):
            current_status, reason = "DEGRADED", "GALERA_PRIMARY_TWO_NODES"
        for node in current:
            node["current_status"] = node["health_at_observation"]
    elif "STALE" in collection_states:
        reason = "GALERA_BATCH_STALE"
    elif periodic and not same_batch:
        reason = "GALERA_BATCH_INCOMPLETE"
    summary = {
        "expected_nodes": len(NODES), "observed_nodes": len(valid),
        "healthy_node_observations": healthy,
        "consistency": ("MATCHING_AT_OBSERVATIONS" if agreement else "MISMATCH")
        if complete and (same_batch or not periodic) else "UNKNOWN",
        "observation_from": start, "observation_to": end,
        "observation_spread_seconds": (
            datetime.fromisoformat(end.replace("Z", "+00:00")) -
            datetime.fromisoformat(start.replace("Z", "+00:00"))
        ).total_seconds() if start else None,
        "simultaneous_verified": False, "current_status": current_status, "current_reason": reason,
    }
    file_reads = sum(node["source_read_ok"] for node in nodes)
    refs = [node["source_ref"] or "MISSING" for node in nodes]
    meta = {
        "source_system": "Galera wsrep snapshots", "source_schema": "portal-galera-node-1",
        "source_mode": "SNAPSHOT", "scope": "LOCAL_SOCKET_WSREP", "data_state": "HISTORICAL",
        "collection_mode": "PERIODIC" if periodic else "MANUAL",
        "read_at": iso(now),
        "last_attempt": max((node["attempted_at"] for node in nodes if node["attempted_at"]), default=None),
        "last_success": end, "last_successful_sample_at": end,
        "freshness_state": "FRESH" if fresh_batch else "STALE" if "STALE" in collection_states else "UNKNOWN",
        "stale_after_seconds": TTL, "data_as_of": summary["observation_to"],
        "source_ref": "sha256:" + hashlib.sha256(json.dumps(refs).encode()).hexdigest() if file_reads else None,
        "last_error_code": reason if current_status == "UNKNOWN" and periodic else
        "GALERA_NODES_INCOMPLETE" if not complete else None,
        **observations,
    }
    return {"data": {"nodes": nodes, "summary": summary}, "meta": meta, "error": None}
