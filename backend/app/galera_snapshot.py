"""Independent per-node historical wsrep evidence. No database or remote access."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
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
    metrics: dict[str, str]
    error_code: Literal["WSREP_READ_FAILED", "WSREP_FIELDS_MISSING", "WSREP_TIMEOUT",
                        "WSREP_CLIENT_UNAVAILABLE", "WSREP_RESULT_INVALID"] | None

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
    age = (now - observed).total_seconds() if observed else None
    return {
        "node_id": name, "name": name, "source_host": name,
        "source_mode": "SNAPSHOT", "scope": "LOCAL_SOCKET_WSREP",
        "status": "UNKNOWN", "current_status": "UNKNOWN",
        "health_at_observation": "HEALTHY" if healthy else "DEGRADED" if read_ok else "UNKNOWN",
        "read_ok": read_ok, "source_read_ok": exported is not None,
        "attempted_at": iso(exported.attempted_at) if exported else None,
        "observed_at": iso(observed) if observed else None,
        "collected_at": iso(exported.collected_at) if exported else None,
        "observation_freshness_state": "UNKNOWN" if age is None else "FRESH" if -5 <= age <= TTL else "STALE",
        "source_ref": digest, "last_error_code": error or (exported.error_code if exported else None),
        **{key: (int(metrics[key]) if key == "wsrep_cluster_size" and key in metrics else metrics.get(key)) for key in FIELDS},
    }


def read_galera(directory: Path, now: datetime | None = None):
    now = now or datetime.now(timezone.utc)
    nodes = [read_node(directory, name, now) for name in NODES]
    valid = [node for node in nodes if node["read_ok"]]
    observations = observation_metadata(nodes)
    start, end = observations["observation_from"], observations["observation_to"]
    complete = len(valid) == len(NODES)
    # The observations were collected sequentially: agreement is historical evidence,
    # never proof of simultaneous quorum or current three-node health.
    agreement = complete and (
        all(node["wsrep_cluster_size"] == len(NODES) for node in valid)
        and all(node["wsrep_cluster_state_uuid"] for node in valid)
        and len({str(UUID(node["wsrep_cluster_state_uuid"])) for node in valid}) == 1
        and len({int(node["wsrep_cluster_conf_id"]) for node in valid}) == 1
    )
    summary = {
        "expected_nodes": len(NODES), "observed_nodes": len(valid),
        "healthy_node_observations": sum(node["health_at_observation"] == "HEALTHY" for node in nodes),
        "consistency": "MATCHING_AT_OBSERVATIONS" if agreement else "MISMATCH" if complete else "UNKNOWN",
        "observation_from": start, "observation_to": end,
        "observation_spread_seconds": (
            datetime.fromisoformat(end.replace("Z", "+00:00")) -
            datetime.fromisoformat(start.replace("Z", "+00:00"))
        ).total_seconds() if start else None,
        "simultaneous_verified": False, "current_status": "UNKNOWN",
    }
    file_reads = sum(node["source_read_ok"] for node in nodes)
    refs = [node["source_ref"] or "MISSING" for node in nodes]
    meta = {
        "source_system": "Galera wsrep snapshots", "source_schema": "portal-galera-node-1",
        "source_mode": "SNAPSHOT", "scope": "LOCAL_SOCKET_WSREP", "data_state": "HISTORICAL",
        "read_at": iso(now), "last_attempt": iso(now), "last_success": iso(now) if file_reads == len(NODES) else None,
        "freshness_state": "FRESH" if file_reads == len(NODES) else "PARTIAL" if file_reads else "UNKNOWN",
        "stale_after_seconds": TTL, "data_as_of": summary["observation_to"],
        "source_ref": "sha256:" + hashlib.sha256(json.dumps(refs).encode()).hexdigest() if file_reads else None,
        "last_error_code": "GALERA_NODES_INCOMPLETE" if not complete else None,
        **observations,
    }
    return {"data": {"nodes": nodes, "summary": summary}, "meta": meta, "error": None}
