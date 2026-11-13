"""Return only validated release metadata from the deployed build manifest."""
import json
import re

from pydantic import AwareDatetime, TypeAdapter

from .schemas import iso


def load_build_info(path):
    keys = ("build_sha", "build_utc", "backend_release", "frontend_build_sha", "collector_release")
    empty = dict.fromkeys(keys)
    if path is None:
        return empty
    try:
        with path.open("rb") as stream:
            raw = stream.read(4097)
        if len(raw) > 4096:
            return empty
        manifest = json.loads(raw)
        if not isinstance(manifest, dict):
            return empty
        result = {}
        for key in keys:
            value = manifest.get(key)
            if not isinstance(value, str) or len(value) > 80:
                result[key] = None
            elif key == "build_utc":
                result[key] = iso(TypeAdapter(AwareDatetime).validate_python(value))
            else:
                result[key] = value if re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", value) else None
        return result
    except (OSError, ValueError, RecursionError):
        return empty
