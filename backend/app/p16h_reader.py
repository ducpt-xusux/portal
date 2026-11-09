"""Offline read-only domain boundary; no socket codec or LIVE cache connection."""
import asyncio
import json
from pydantic import AwareDatetime
from typing import Literal

from .p16h_normalizer import SafeModel, normalize_line, unique_object
from .schemas import utc_now


class ReaderError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class Health(SafeModel):
    schema_version: Literal["portal-p16h-health-1"]
    context: Literal["TEST", "EVALUATION", "IMPORTED_UNVERIFIED"]
    observed_at: AwareDatetime
    collected_at: AwareDatetime
    producer_status: Literal["RUNNING", "DEGRADED", "UNKNOWN"]
    collector_status: Literal["RUNNING", "DEGRADED", "UNKNOWN"]
    coverage_kind: Literal["RECENT_SAMPLE"]


class OfflineReader:
    def __init__(self, transport, context, timeout=2):
        if context not in {"TEST", "EVALUATION", "IMPORTED_UNVERIFIED"} or not 0 < timeout <= 10:
            raise ValueError("Invalid reader configuration")
        self.transport, self.context, self.timeout = transport, context, timeout
        self.last_good = {}

    async def read(self, operation, limit=32):
        if operation not in {"HEALTH", "RECENT"}:
            raise ReaderError("P16H_OPERATION_DENIED")
        if operation == "RECENT" and (type(limit) is not int or not 1 <= limit <= 100):
            raise ReaderError("P16H_LIMIT_INVALID")
        try:
            # Domain call only. Encoding/framing/socket path remain unimplemented.
            raw = await asyncio.wait_for(self.transport(operation, limit if operation == "RECENT" else None), self.timeout)
            if not isinstance(raw, bytes) or len(raw) > 8 * 1024 * 1024:
                raise ValueError()
            if operation == "HEALTH":
                health = Health.model_validate(json.loads(raw, object_pairs_hook=unique_object))
                if health.context != self.context:
                    raise ValueError()
                value = health.model_dump(mode="json")
            else:
                lines = raw.splitlines()
                if len(lines) > limit:
                    raise ValueError()
                value = [normalize_line(line) for line in lines]
                if any(item.get("context") != self.context for item in value):
                    raise ValueError()
            entry = {"data": value, "last_success_at": utc_now(), "state": "HISTORICAL", "error_code": None}
            self.last_good[operation] = entry
            return {**entry, "read_at": utc_now()}
        except (TimeoutError, OSError, ValueError, TypeError, RecursionError) as exc:
            code = "P16H_READER_TIMEOUT" if isinstance(exc, TimeoutError) else "P16H_RESPONSE_INVALID"
            previous = self.last_good.get(operation)
            return {**(previous or {"data": None, "last_success_at": None}), "read_at": utc_now(),
                    "state": "STALE" if previous else "UNAVAILABLE", "error_code": code}
