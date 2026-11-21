"""Reviewed report observations; preserves the measured scope and source hashes."""
import json
import re
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator
from .source_json import unique_object


class Closed(BaseModel):
    model_config = ConfigDict(extra='forbid', allow_inf_nan=False)


class Fact(Closed):
    key: str = Field(min_length=1, max_length=100, pattern=r'^[A-Z0-9_]+$')
    value: str | int | float | bool

    @field_validator('key')
    @classmethod
    def no_secrets(cls, value):
        if re.search(r'PASSWORD|PASSWD|SECRET|TOKEN|PRIVATE_KEY|RAW_SQL|AUTHORIZATION', value):
            raise ValueError('Credential/raw SQL evidence is forbidden')
        return value

    @field_validator('value')
    @classmethod
    def bounded(cls, value):
        if isinstance(value, str) and len(value) > 2048:
            raise ValueError('Evidence text too large')
        return value


class Artifact(Closed):
    evidence_id: str = Field(min_length=1, max_length=160)
    title: str = Field(min_length=1, max_length=300)
    scope: str = Field(min_length=1, max_length=300)
    observed_at: AwareDatetime
    source_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    facts: list[Fact] = Field(max_length=200)


class ReportEvidence(Closed):
    schema_version: str = Field(pattern=r'^portal-report-evidence-1$')
    artifacts: list[Artifact] = Field(max_length=20)


def read_report_evidence(path):
    if path is None or path.is_symlink():
        raise ValueError('Report evidence source not configured')
    with path.open('rb') as source:
        raw = source.read(65537)
    if len(raw) > 65536:
        raise ValueError('Report evidence too large')
    return ReportEvidence.model_validate(json.loads(raw, object_pairs_hook=unique_object)).model_dump(mode='json')
