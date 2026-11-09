"""Bounded, sanitized local import contract. This is NOT a socket wire codec.

The source document identifies p16h-local-1 but supplies no machine-readable
RECENT sample or nested metadata schema. This explicit offline profile is never a claim
that a production RECENT response has been verified.
"""
import json
from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator

from .schemas import AuditEvent, iso

MAX_BYTES = 1024 * 1024
PROFILE = "portal-p16h-import-1"
Identifier = Annotated[str, Field(strict=True, min_length=1, max_length=160, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")]
Hash = Annotated[str, Field(strict=True, pattern=r"^[a-f0-9]{64}$")]
Sequence = Annotated[StrictInt, Field(ge=0, le=9007199254740991)]


class ImportError(ValueError):
    def __init__(self, code="P16H_IMPORT_INVALID"):
        self.code = code
        super().__init__(code)


class SafeModel(BaseModel):
    model_config = ConfigDict(extra="ignore")

    @field_validator("*", mode="before")
    @classmethod
    def timestamp_strings(cls, value, info):
        if info.field_name in {"timestamp", "request_received_at", "storage_recorded_at", "collected_at"} and value is not None and not isinstance(value, str):
            raise ValueError("Timestamps require ISO8601 strings with offsets")
        return value


class Metadata(SafeModel):
    request_id: Identifier | None = None
    request_sequence: Sequence | None = None
    request_received_at: AwareDatetime | None = None
    received_time_basis: Identifier | None = None
    producer_id: Identifier | None = None
    producer_boot_id: Identifier | None = None
    session_id: Identifier | None = None
    mysql_command_code: Annotated[StrictInt, Field(ge=0, le=255)] | None = None
    policy_config_hash: Hash | None = None
    risk_config_hash: Hash | None = None
    config_hash_basis: Identifier | None = None
    # Nested backend/privacy layouts are not documented. Only these states are
    # supported by the local profile; arbitrary producer objects are withheld.
    backend: Literal["UNAVAILABLE"] | None = None
    privacy: Literal["UNAVAILABLE"] | None = None
    backend_status: Literal["UNAVAILABLE_SCHEMA"] = "UNAVAILABLE_SCHEMA"
    privacy_status: Literal["UNAVAILABLE_SCHEMA"] = "UNAVAILABLE_SCHEMA"

    @model_validator(mode="before")
    @classmethod
    def withhold_uncontracted_nested_metadata(cls, value):
        if isinstance(value, dict):
            return {**value, **{key: None for key in ("backend", "privacy") if value.get(key) != "UNAVAILABLE"}}
        return value

    def record(self):
        result = self.model_dump(mode="json")
        if self.request_received_at:
            result["request_received_at"] = iso(self.request_received_at)
        return result


class CanonicalRecord(AuditEvent):
    """Reuse the field types, with version-independent risk checks below."""

    event_id: Identifier
    risk_status: Literal["OK", "ERROR"] | None = None
    risk_score: Annotated[StrictInt, Field(ge=0, le=100)] | None = None
    query_mask_status: Literal["MASKED", "NOT_APPLICABLE", "ERROR"] | None = None
    query_text_withheld: Literal[True] | None = None

    @field_validator("timestamp", mode="before")
    @classmethod
    def timestamp_string(cls, value):
        if not isinstance(value, str):
            raise ValueError("Timestamp requires an ISO8601 string with offset")
        return value

    @model_validator(mode="after")
    def validate_risk(self):
        # No legacy severity thresholds, score sum/cap assumptions or rescoring.
        if self.query_text_withheld:
            if self.query_masked is not None:
                raise ValueError("Projected query text must be absent")
        if self.query_mask_status != "MASKED":
            self.query_masked = None
        elif (not self.query_masked and not self.query_text_withheld) or self.query_mask_error is not None:
            raise ValueError("Invalid mask state")
        if self.action_result not in {"ALLOW": {"FORWARDED", "ERROR"}, "BLOCK": {"BLOCKED", "ERROR"}}[self.action]:
            raise ValueError("Invalid action result")
        if self.effective_action != self.action:
            raise ValueError("Action disagrees with effective action")
        if self.runtime_mode == "monitor" and self.effective_action == "BLOCK":
            raise ValueError("Monitor cannot enforce block")
        if self.risk_status != "OK":
            for key in ("raw_score", "risk_score", "severity", "score_breakdown", "dominant_rule",
                        "recommended_action", "default_deny_applied", "matched_rule_count", "score_component_count"):
                setattr(self, key, None)
        elif self.risk_score is None:
            raise ValueError("OK risk requires a score")
        return self

    def record(self):
        result = super().record()
        if self.query_text_withheld is None:
            result.pop("query_text_withheld")
        return result


class Source(SafeModel):
    artifact_id: Identifier
    source_host: Identifier | None = None
    source_run_id: Identifier | None = None
    collected_at: AwareDatetime | None = None
    artifact_sha256: Hash | None = None
    original_artifact_sha256: Hash | None = None
    # An input never grants itself VERIFIED or human-reviewed status.


class Envelope(SafeModel):
    record: CanonicalRecord
    metadata: Metadata


class Delivery(SafeModel):
    # Reported by 02P1 source inspection; actual wire framing remains pending.
    delivery_version: Literal["p16h-local-1"]
    envelope: Envelope
    stream_id: Identifier
    stream_sequence: Sequence
    event_role: Identifier | None = None
    journal_sequence: Sequence | None = None
    journal_stream_id: Identifier | None = None
    segment_index: Sequence | None = None
    payload_sha256: Hash | None = None
    storage_recorded_at: AwareDatetime | None = None


class ImportDocument(SafeModel):
    schema_version: Literal["portal-p16h-import-1"]
    context: Literal["TEST", "EVALUATION", "IMPORTED_UNVERIFIED"]
    source: Source
    delivery: Delivery

    @model_validator(mode="after")
    def validate_projection_context(self):
        if self.delivery.envelope.record.query_text_withheld and self.context != "IMPORTED_UNVERIFIED":
            raise ValueError("Projected records require the offline import context")
        return self


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ImportError()
        result[key] = value
    return result


def bounds(value, depth=0):
    if depth > 12:
        raise ImportError("P16H_IMPORT_LIMIT")
    if isinstance(value, dict):
        if len(value) > 100:
            raise ImportError("P16H_IMPORT_LIMIT")
        if any(key.lower() in {"raw_sql", "query_raw", "original_sql", "password", "token", "private_key", "authorization"} for key in value):
            raise ImportError("P16H_IMPORT_PRIVACY")
        for item in value.values():
            bounds(item, depth + 1)
    elif isinstance(value, list):
        if len(value) > 256:
            raise ImportError("P16H_IMPORT_LIMIT")
        for item in value:
            bounds(item, depth + 1)
    elif isinstance(value, str) and len(value) > 16384:
        raise ImportError("P16H_IMPORT_LIMIT")


def normalize_line(raw):
    """Return sanitized persisted document; no import timestamp in dedup content."""
    if len(raw) > MAX_BYTES:
        raise ImportError("P16H_IMPORT_LIMIT")
    try:
        value = json.loads(raw, object_pairs_hook=unique_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(ImportError()))
        bounds(value)
        if not isinstance(value, dict):
            raise ImportError()
        if "schema_version" not in value:
            # Flat legacy only. Never silently discard an unrecognized envelope.
            if any(key in value for key in ("delivery", "envelope", "metadata", "delivery_version", "stream_id", "request_id")):
                raise ImportError("P16H_SCHEMA_UNSUPPORTED")
            result = AuditEvent.model_validate(value).record()
            if result["query_mask_status"] != "MASKED":
                result["query_masked"] = None
            return result
        if value["schema_version"] != PROFILE:
            raise ImportError("P16H_SCHEMA_UNSUPPORTED")
        if value.get("delivery", {}).get("delivery_version") != "p16h-local-1":
            raise ImportError("P16H_DELIVERY_VERSION_UNSUPPORTED")
        parsed = ImportDocument.model_validate(value)
        result = parsed.model_dump(mode="json")
        result["delivery"]["envelope"]["record"] = parsed.delivery.envelope.record.record()
        result["delivery"]["envelope"]["metadata"] = parsed.delivery.envelope.metadata.record()
        if parsed.delivery.storage_recorded_at:
            result["delivery"]["storage_recorded_at"] = iso(parsed.delivery.storage_recorded_at)
        if parsed.source.collected_at:
            result["source"]["collected_at"] = iso(parsed.source.collected_at)
        return result
    except ImportError:
        raise
    except (ValueError, TypeError, AttributeError, RecursionError, OverflowError):
        raise ImportError() from None


def unpack(document):
    if document.get("schema_version") == PROFILE:
        delivery = document["delivery"]
        return delivery["envelope"]["record"], delivery["stream_id"]
    return document, None


def storage_record(document):
    record, stream = unpack(document)
    if stream is None:
        return record
    return {**record, "_p16h": {
        "schema_version": PROFILE, "context": document["context"], "source": document["source"],
        **{key: value for key, value in document["delivery"].items() if key != "envelope"},
        "metadata": document["delivery"]["envelope"]["metadata"],
    }}


def evidence_content(payload):
    """Import artifact identity is not part of upstream event content."""
    value = json.loads(payload)
    if "_p16h" in value:
        value["_p16h"].pop("source", None)
    return value
