"""Read local transport health without mistaking cached files for a reachable Proxy."""
from datetime import datetime, timezone
import json


def read_sync_status(path, feed, digest=None):
    try:
        with path.open("rb") as file:
            raw = file.read(8193)
        if len(raw) > 8192:
            raise ValueError()
        payload = json.loads(raw)
        if payload.get("version") != 1:
            raise ValueError()
        item = payload[feed]
        stamp = datetime.fromisoformat(item["last_success"].replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            raise ValueError()
        age = (datetime.now(timezone.utc) - stamp).total_seconds()
        if item.get("state") != "FRESH":
            error = "REMOTE_SYNC_FAILED"
        elif not -5 <= age <= 30:
            error = "REMOTE_SYNC_STALE"
        elif digest is not None and item.get("sha256") != digest:
            error = "REMOTE_CACHE_CHANGED"
        else:
            error = None
        return {"last_success": item["last_success"], "last_attempt": item.get("last_attempt"),
                "freshness_state": "STALE" if error else "FRESH", "error_code": error,
                "pending_bytes": item.get("pending_bytes", 0)}, error
    except (OSError, ValueError, KeyError, TypeError, AttributeError, OverflowError):
        return {"last_success": None, "freshness_state": "UNKNOWN",
                "error_code": "REMOTE_STATUS_UNAVAILABLE"}, "REMOTE_STATUS_UNAVAILABLE"
