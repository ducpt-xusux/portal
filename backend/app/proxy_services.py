"""Read-only historical systemd observations; never a functional health probe."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StrictBool, ValidationError, model_validator

from .schemas import iso

UNITS = {
    "db-firewall.service": "DB Firewall",
    "db-firewall-audit.service": "P16H audit collector",
    "db-firewall-p17.service": "P17 worker",
}
TTL = 45
MAX_BYTES = 65536


class Properties(BaseModel):
    # Only known systemctl fields can leave this adapter.
    Id: str = Field(max_length=128)
    LoadState: str = Field(max_length=32)
    ActiveState: str = Field(max_length=32)
    SubState: str = Field(max_length=32)
    MainPID: str = Field(pattern=r"^[0-9]{1,10}$")
    Result: str = Field(max_length=64)


class Observation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    unit: str = Field(max_length=128)
    attempted_at: AwareDatetime
    observed_at: AwareDatetime | None
    read_ok: StrictBool
    properties: Properties | dict
    error_code: Literal["SYSTEMCTL_READ_FAILED", "SYSTEMCTL_TIMEOUT", "SYSTEMCTL_UNAVAILABLE"] | None

    @model_validator(mode="after")
    def check_observation(self):
        if self.unit not in UNITS:
            raise ValueError("Unexpected service")
        if self.read_ok:
            self.properties = Properties.model_validate(self.properties)
            if self.properties.Id != self.unit or self.observed_at is None or self.error_code is not None:
                raise ValueError("Inconsistent observation")
            if self.attempted_at > self.observed_at:
                raise ValueError("Invalid observation time")
        elif self.observed_at is not None or self.error_code is None:
            raise ValueError("Invalid failed attempt")
        return self


class Export(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["portal-proxy-services-1"] = Field(alias="schema")
    source_host: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_.:-]+$")
    collected_at: AwareDatetime
    mode: Literal["SNAPSHOT"]
    scope: Literal["SYSTEMD_STATUS_ONLY"]
    services: list[Observation] = Field(max_length=3)

    @model_validator(mode="after")
    def check_export(self):
        if len({row.unit for row in self.services}) != len(self.services):
            raise ValueError("Duplicate service")
        if any((row.observed_at or row.attempted_at) > self.collected_at for row in self.services):
            raise ValueError("Invalid collection time")
        return self


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def observation_metadata(rows):
    observed = [row for row in rows if row["read_ok"]]
    times = sorted(row["observed_at"] for row in observed)  # iso() normalizes to UTC with fixed precision.
    return {
        "coverage_state": "UNKNOWN" if not observed else "COMPLETE" if len(observed) == len(rows) else "PARTIAL",
        "observation_freshness_state": (
            "UNKNOWN" if not observed else
            "STALE" if any(row["observation_freshness_state"] == "STALE" for row in observed) else "FRESH"
        ),
        "observation_from": times[0] if times else None,
        "observation_to": times[-1] if times else None,
    }


def read_services(path: Path | None, now: datetime | None = None):
    now = now or datetime.now(timezone.utc)
    source_error, exported, digest = None, None, None
    if path is None:
        source_error = "PROXY_SERVICES_NOT_CONFIGURED"
    else:
        try:
            with path.open("rb") as stream:
                raw = stream.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise ValueError("Oversized export")
            exported = Export.model_validate(json.loads(raw, object_pairs_hook=unique_object))
            if exported.collected_at > now + timedelta(seconds=5):
                raise ValueError("Future collection time")
            digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        except OSError:
            source_error = "PROXY_SERVICES_UNAVAILABLE"
        except (ValueError, ValidationError, UnicodeError, RecursionError):
            source_error = "PROXY_SERVICES_INVALID"
        if source_error:
            exported = None

    meta = {
        "source_system": "Proxy systemd snapshot", "source_schema": "portal-proxy-services-1",
        "source_mode": "SNAPSHOT", "scope": "SYSTEMD_STATUS_ONLY", "data_state": "HISTORICAL",
        "read_at": iso(now), "last_attempt": iso(now), "last_success": iso(now) if exported else None,
        "freshness_state": "FRESH" if exported else "UNKNOWN", "stale_after_seconds": TTL,
        "data_as_of": iso(exported.collected_at) if exported else None,
        "source_ref": digest, "source_host": exported.source_host if exported else None,
        "last_error_code": source_error,
    }
    by_unit = {row.unit: row for row in exported.services} if exported else {}
    components = []
    for unit, name in UNITS.items():
        row = by_unit.get(unit)
        process_state, pid, props = "UNKNOWN", None, None
        row_error = source_error or ("SERVICE_OBSERVATION_MISSING" if row is None else row.error_code)
        if row and row.read_ok:
            props = row.properties
            pid = int(props.MainPID)
            if props.LoadState == "loaded" and props.ActiveState == "active" and props.SubState == "running" and pid > 0:
                process_state = "RUNNING"
            elif props.ActiveState == "failed":
                process_state = "FAILED"
            elif props.LoadState == "loaded" and props.ActiveState == "inactive":
                process_state = "STOPPED"
        observed = row.observed_at if row else None
        observation_freshness = "UNKNOWN" if observed is None else "FRESH" if -5 <= (now - observed).total_seconds() <= TTL else "STALE"
        components.append({
            "component_id": unit, "unit": unit, "name": name,
            "scope": "SYSTEMD_STATUS_ONLY", "source_mode": "SNAPSHOT",
            "status": "UNKNOWN", "functional_status": "UNKNOWN", "process_state": process_state,
            "observed_at": iso(observed) if observed else None,
            "last_attempt": iso(row.attempted_at) if row else None,
            "last_success": iso(observed) if observed else None,
            "read_ok": row.read_ok if row else False,
            "observation_freshness_state": observation_freshness,
            "pid": pid, "load_state": props.LoadState if props else None,
            "active_state": props.ActiveState if props else None, "sub_state": props.SubState if props else None,
            "result": props.Result if props else None, "source_ref": digest, "last_error_code": row_error,
        })
    meta.update(observation_metadata(components))
    if exported and meta["coverage_state"] != "COMPLETE":
        meta["last_error_code"] = "PROXY_SERVICES_INCOMPLETE"
    return {"components": components, "source": meta}
