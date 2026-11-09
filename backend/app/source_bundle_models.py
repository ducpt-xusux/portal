"""Operator-only receipt contract, independent of runtime source configuration."""
from typing import Literal
from pydantic import AwareDatetime, Field, model_validator
from .evidence_models import Closed, Id, Sha

SourceRef = Literal[
    'P16H_RECENT', 'P16H_HEALTH', 'P16H_WIRE_CONTRACT', 'PROXY_02P1_MANIFEST',
    '60_CASE_JOIN', 'LIVE_POLICY_PREFLIGHT', 'LIVE_EVENT_LINKAGE', 'POLICY_32', 'PROTOCOL_3',
    'P17_SEVEN_CASES', 'P17_INCIDENT_ALERT', 'P17_DURABLE', 'PACKET_RELAY', 'PRIVACY_SAMPLE',
    'PRIVACY_CANARY', 'PRODUCER_FAULT', 'PROTOCOL_PATCH', 'REAL_AUDIT_SCHEMA', 'FRAMING_TELEMETRY',
    'P16H_P17_CHECKPOINT', 'P16H_RECOVERY', 'PROXY_FAILOVER', 'CONTROLLER_02P2_REPORT',
    'GLOBAL_ACTIONS', 'INCIDENT_ACTIONS', 'CONTAINMENT', 'WATCHDOG', 'CYCLE_START',
    'HANDLED_INCIDENTS', 'NEUTRON_SNAPSHOT', 'ACTIVE_POLICY_RC5', 'ACTIVE_RISK_RC6',
    'WORKBOOK', 'CASE_CATALOG', 'CASE_OBSERVED', 'CORRELATION_REPLAY', 'G07_C1_REPORT',
    'HA_SUMMARY', 'TLS_SUMMARY', 'PRIVACY_SUMMARY', 'STAGING_SUMMARY', 'P19_GATE',
    'EVIDENCE_SUMMARY', 'OTHER_WITHHELD',
]


class SourceBundleFile(Closed):
    artifact_id: Id
    source_ref: SourceRef
    relative_path: str = Field(min_length=1, max_length=240, pattern=r'^[A-Za-z0-9][A-Za-z0-9_./-]*$')
    source_host: Id
    source_run_id: Id
    execution_modes: list[Literal['LIVE', 'ISOLATED', 'STAGING', 'HISTORICAL', 'DESIGN_ONLY', 'OFFLINE', 'UNKNOWN']] = Field(min_length=1, max_length=6)
    captured_at: AwareDatetime | None
    data_as_of: AwareDatetime | None
    timestamp_basis: Literal['PRODUCER', 'OPERATOR', 'UNAVAILABLE']
    declared_schema: Id
    validation_profile: Literal['WITHHELD', 'EVIDENCE_SUMMARY_V1', 'P16H_HEALTH_V1', 'P16H_LOCAL_IMPORT_V1']
    operator_sanitization: Literal['SANITIZED', 'WITHHELD']
    sha256: Sha
    size_bytes: int = Field(ge=0, le=8 * 1024 * 1024)
    original_sha256: Sha | None
    transformation: Literal['UNCHANGED', 'REDACTED', 'PROJECTED', 'UNKNOWN']

    @model_validator(mode='after')
    def provenance(self):
        if len(set(self.execution_modes)) != len(self.execution_modes):
            raise ValueError('DUPLICATE_MODE')
        if 'UNKNOWN' in self.execution_modes and len(self.execution_modes) != 1:
            raise ValueError('AMBIGUOUS_MODE')
        if self.timestamp_basis == 'UNAVAILABLE':
            if self.captured_at is not None or self.data_as_of is not None:
                raise ValueError('TIMESTAMP_BASIS_CONFLICT')
        elif self.captured_at is None or self.data_as_of is None:
            raise ValueError('TIMESTAMPS_REQUIRED')
        if self.transformation == 'UNCHANGED' and self.original_sha256 != self.sha256:
            raise ValueError('UNCHANGED_HASH_CONFLICT')
        if self.transformation in ('REDACTED', 'PROJECTED') and self.original_sha256 == self.sha256:
            raise ValueError('TRANSFORMED_HASH_CONFLICT')
        if self.validation_profile != 'WITHHELD' and self.operator_sanitization != 'SANITIZED':
            raise ValueError('PROFILE_REQUIRES_SANITIZATION')
        profiles = {'P16H_HEALTH_V1': 'P16H_HEALTH', 'P16H_LOCAL_IMPORT_V1': 'P16H_RECENT'}
        if self.validation_profile in profiles and self.source_ref != profiles[self.validation_profile]:
            raise ValueError('PROFILE_SOURCE_CONFLICT')
        return self


class SourceBundleManifest(Closed):
    schema_version: Literal['n91-source-bundle-1']
    bundle_id: Id
    context: Literal['TEST', 'EVALUATION', 'IMPORTED_UNVERIFIED']
    created_at: AwareDatetime
    files: list[SourceBundleFile] = Field(min_length=1, max_length=256)

    @model_validator(mode='after')
    def unique(self):
        identities = [f.artifact_id for f in self.files]
        paths = [f.relative_path.casefold() for f in self.files]
        keys = [(f.source_host, f.source_run_id, f.source_ref) for f in self.files if f.source_ref != 'OTHER_WITHHELD']
        if len(set(identities)) != len(identities) or len(set(paths)) != len(paths) or len(set(keys)) != len(keys):
            raise ValueError('DUPLICATE_ID_PATH_OR_SOURCE')
        if self.context == 'IMPORTED_UNVERIFIED' and any(
            value.upper().startswith('TEST-') for f in self.files for value in (f.artifact_id, f.source_host, f.source_run_id)
        ):
            raise ValueError('TEST_FIXTURE_CANNOT_BE_REAL_SOURCE')
        return self


class SourceBundleHealth(Closed):
    schema_version: Literal['portal-p16h-health-1']
    context: Literal['TEST', 'EVALUATION', 'IMPORTED_UNVERIFIED']
    observed_at: AwareDatetime
    collected_at: AwareDatetime
    producer_status: Literal['RUNNING', 'DEGRADED', 'UNKNOWN']
    collector_status: Literal['RUNNING', 'DEGRADED', 'UNKNOWN']
    coverage_kind: Literal['RECENT_SAMPLE']
