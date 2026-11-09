from dataclasses import dataclass
from enum import Enum
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator
from .privacy import plain_text


class Role(str, Enum):
    VIEWER = 'Viewer'
    ANALYST = 'Analyst'
    OPERATOR = 'Operator'
    APPROVER = 'Approver'
    EXECUTOR = 'Executor'
    AUDITOR = 'Auditor'


class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)


class Login(StrictModel):
    username: str = Field(min_length=3, max_length=64, pattern=r'^[a-z][a-z0-9_.-]*$')
    password: SecretStr = Field(min_length=1, max_length=128)


class NoteInput(StrictModel):
    note: str = Field(min_length=1, max_length=1000)

    @field_validator('note')
    @classmethod
    def safe_note(cls, value):
        return plain_text(value)


class TriageInput(StrictModel):
    version: int = Field(ge=0)
    review_state: Literal['UNREAD', 'REVIEWED']
    acknowledged: bool
    assignee_id: str | None = Field(default=None, max_length=64)
    priority: Literal['UNSET', 'LOW', 'MEDIUM', 'HIGH', 'URGENT'] = 'UNSET'


class AlertReviewInput(StrictModel):
    version: int = Field(ge=0)
    review_state: Literal['UNREAD', 'REVIEWED']
    acknowledged: bool


class UserCreate(StrictModel):
    username: str = Field(min_length=3, max_length=64, pattern=r'^[a-z][a-z0-9_.-]*$')
    password: SecretStr = Field(min_length=12, max_length=128)
    roles: list[str] = Field(min_length=1, max_length=6)
    # Admin is a separate server permission; API cannot grant it.


class UserUpdate(StrictModel):
    version: int = Field(ge=1)
    roles: list[str] = Field(min_length=1, max_length=6)
    active: bool


@dataclass(frozen=True)
class Principal:
    user_id: str
    username: str
    roles: tuple[str, ...]
    portal_admin: bool
    expires_at: int
    csrf_token: str
    session_hash: str


@dataclass(frozen=True)
class SourceRef:
    kind: Literal['incident', 'alert']
    object_id: str
    stream_id: str
    execution_mode: Literal['LIVE', 'HISTORICAL', 'ISOLATED', 'STAGING', 'TEST']


READ_ROLES = frozenset(r.value for r in Role)
WRITE_ROLES = frozenset({'Analyst', 'Operator'})
EVIDENCE_ROLES = READ_ROLES - {'Viewer'}
