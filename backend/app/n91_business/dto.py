"""Local typed response schemas; frozen AuthSession/Note/AdminAudit shapes retained."""
from typing import Generic, Literal, TypeVar
from pydantic import BaseModel, ConfigDict, AwareDatetime, Field


class DTO(BaseModel):
    model_config = ConfigDict(extra='forbid')


class Meta(DTO):
    request_id: str
    read_at: AwareDatetime
    source_system: Literal['PORTAL_BUSINESS']
    source_schema: Literal['n91-business-v1']
    freshness_state: Literal['FRESH', 'UNAVAILABLE']
    sources: list[dict]
    coverage_note: str
    next_cursor: str | None = None


T = TypeVar('T')
class Success(DTO, Generic[T]):
    data: T
    meta: Meta
    error: None = None


class AuthSession(DTO):
    username: str
    roles: list[str]
    expires_at: AwareDatetime
    csrf_token: str | None = None


class Note(DTO):
    note_id: str
    incident_id: str
    note: str
    actor_id: str
    created_at: AwareDatetime


class Overlay(DTO):
    kind: Literal['incident', 'alert']
    object_id: str
    stream_id: str
    execution_mode: Literal['LIVE', 'HISTORICAL', 'ISOLATED', 'STAGING', 'TEST']
    review_state: Literal['UNREAD', 'REVIEWED']
    acknowledged: bool
    assignee_id: str | None
    priority: Literal['UNSET', 'LOW', 'MEDIUM', 'HIGH', 'URGENT']
    version: int = Field(ge=0)
    updated_at: AwareDatetime | None
    actor_id: str | None
    owner: Literal['PORTAL_ANNOTATION']
    source_status_changed: Literal[False]


class User(DTO):
    user_id: str
    username: str
    roles: list[str]
    active: bool
    version: int


class UserPage(DTO):
    items: list[User]


class Assignee(DTO):
    user_id: str
    username: str


class AssigneePage(DTO):
    items: list[Assignee]


class NotePage(DTO):
    items: list[Note]
    owner: Literal['PORTAL_ANNOTATION']


class AdminAudit(DTO):
    audit_id: str
    actor_id: str
    action: str
    target_ref: str | None
    outcome: str
    timestamp: AwareDatetime
    request_id: str
    source_ref: str | None


class ExtendedAudit(AdminAudit):
    sequence: int
    before: dict | None
    after: dict | None


class AuditPage(DTO):
    items: list[AdminAudit]
    has_more: bool
    next_cursor: str | None = None
    total_count: int | None = None


class ExtendedAuditPage(DTO):
    items: list[ExtendedAudit]


class Capabilities(DTO):
    user_id: str
    portal_admin: bool
    can_triage: bool
    can_read_notes: bool
    network_actions_enabled: Literal[False]
    context: Literal['TEST', 'PORTAL']
