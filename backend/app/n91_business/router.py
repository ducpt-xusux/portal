from typing import Annotated
import json
from uuid import uuid4
from fastapi import APIRouter, Path, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from fastapi.routing import APIRoute
from pydantic import ValidationError
from .gate import envelope
from .models import Login, NoteInput, TriageInput, AlertReviewInput, UserCreate, UserUpdate
from .privacy import notes_csv
from .service import BusinessError, iso
from .dto import (Success, AuthSession, Note, NotePage, Overlay, User, UserPage,
                  AssigneePage, Capabilities, AuditPage, ExtendedAuditPage)

ID = Annotated[str, Path(min_length=1, max_length=160, pattern=r'^[A-Za-z0-9][A-Za-z0-9_.:-]*$')]
Stream = Annotated[str | None, Query(min_length=1, max_length=160, pattern=r'^[A-Za-z0-9][A-Za-z0-9_.:-]*$')]
Limit = Annotated[int, Query(ge=1, le=100)]
After = Annotated[int, Query(ge=0, le=100_000)]
Cursor = Annotated[str | None, Query(min_length=1, max_length=2048)]


def session_view(actor):
    return {'username': actor.username, 'roles': list(actor.roles), 'expires_at': iso(actor.expires_at), 'csrf_token': actor.csrf_token}


def create_business_router(service):
    class SafeRoute(APIRoute):
        def get_route_handler(self):
            handler = super().get_route_handler()
            async def safe(request):
                try:
                    if getattr(request.state, 'business_gate_service', None) is not service:
                        raise BusinessError(503, 'SESSION_GATE_REQUIRED')
                    if not getattr(request.state, 'business_principal', None) and request.url.path != '/api/v1/auth/login':
                        raise BusinessError(401, 'SESSION_REQUIRED')
                    response = await handler(request)
                    if self.response_model and isinstance(response, JSONResponse) and 200 <= response.status_code < 300:
                        self.response_model.model_validate(json.loads(response.body))
                    return response
                except BusinessError as exc:
                    return JSONResponse(envelope(request, service, code=exc.code), status_code=exc.status,
                                        headers={'Retry-After': '300'} if exc.status == 429 else None)
                except RequestValidationError:
                    # Never echo password, note, input payload or internal paths.
                    return JSONResponse(envelope(request, service, code='VALIDATION_ERROR'), status_code=422)
                except ValidationError:
                    return JSONResponse(envelope(request, service, code='BUSINESS_RESPONSE_INVALID'), status_code=503)
            return safe

    router = APIRouter(prefix='/api/v1', tags=['Portal business'], route_class=SafeRoute)
    def actor(request):
        return request.state.business_principal
    def rid(request):
        return getattr(request.state, 'request_id', str(uuid4()))
    def result(request, data, **headers):
        return JSONResponse(envelope(request, service, data), headers={'Cache-Control': 'no-store', **headers})

    def paged(request, scope, cursor, limit, read, *, sequence=False, extra=None):
        user = actor(request)
        position = service.cursor(user, [scope,limit], token=cursor) if cursor else 0
        rows = read(limit+1, position)
        has_more = len(rows)>limit
        selected = rows[:limit]
        next_position = selected[-1]['sequence'] if sequence and selected else position+len(selected)
        payload = envelope(request, service, {'items':selected, **(extra or {})})
        payload['meta']['next_cursor'] = service.cursor(user,[scope,limit],offset=next_position) if has_more else None
        return JSONResponse(payload, headers={'Cache-Control':'no-store'})

    @router.post('/auth/login', response_model=Success[AuthSession])
    def login(request: Request, payload: Login):
        # Route must be used behind SessionGate; direct mounting fails closed.
        if getattr(request.state, 'business_gate_service', None) is not service:
            raise BusinessError(503, 'SESSION_GATE_REQUIRED')
        token, user = service.login(payload.username, payload.password.get_secret_value(),
                                    request.client.host if request.client else 'unknown', rid(request))
        response = result(request, session_view(user))
        response.set_cookie(service.config.cookie_name, token, max_age=service.config.session_seconds,
                            httponly=True, secure=service.config.secure_cookie, samesite='strict', path='/')
        return response

    @router.get('/auth/me', response_model=Success[AuthSession])
    def me(request: Request):
        return result(request, session_view(actor(request)))

    @router.post('/auth/logout', response_model=Success[AuthSession])
    def logout(request: Request):
        user = actor(request)
        service.logout(user, rid(request))
        # Frozen AuthSession requires username/roles/expires_at even after logout.
        response = result(request, {'username': user.username, 'roles': [], 'expires_at': iso(service.clock()), 'csrf_token': None})
        response.delete_cookie(service.config.cookie_name, path='/', secure=service.config.secure_cookie,
                               httponly=True, samesite='strict')
        return response

    @router.post('/incidents/{id}/notes', response_model=Success[Note])
    def add_note(request: Request, id: ID, payload: NoteInput):
        ref = service.resolve('incident', id)
        return result(request, service.add_note(actor(request), ref, payload.note,
                      request.headers.get('idempotency-key'), rid(request)))

    @router.get('/portal/incidents/{id}/notes', response_model=Success[NotePage])
    def notes(request: Request, id: ID, stream_id: Stream = None, limit: Limit = 25, cursor: Cursor = None):
        ref = service.resolve('incident', id, stream_id)
        return paged(request,['notes',service._key(ref)],cursor,limit,
            lambda count,offset:service.notes(actor(request),ref,count,offset),extra={'owner':'PORTAL_ANNOTATION'})

    @router.get('/portal/incidents/{id}/notes.csv', response_class=Response,
                responses={200:{'content':{'text/csv':{'schema':{'type':'string'}}}}})
    def export_notes(request: Request, id: ID, stream_id: Stream = None, limit: Limit = 25, after: After = 0):
        ref = service.resolve('incident', id, stream_id)
        rows = service.notes(actor(request), ref, limit, after)
        return Response(notes_csv(rows), media_type='text/csv', headers={'Cache-Control': 'no-store',
                        'Content-Disposition': 'attachment; filename="portal-notes.csv"'})

    @router.get('/portal/{kind}/{id}/overlay', response_model=Success[Overlay])
    def overlay(request: Request, kind: Annotated[str, Path(pattern=r'^(incidents|alerts)$')], id: ID, stream_id: Stream = None):
        return result(request, service.overlay(actor(request), service.resolve('incident' if kind == 'incidents' else 'alert', id, stream_id)))

    @router.patch('/portal/incidents/{id}/triage', response_model=Success[Overlay])
    def triage(request: Request, id: ID, payload: TriageInput, stream_id: Stream = None):
        return result(request, service.triage(actor(request), service.resolve('incident', id, stream_id),
                      payload.model_dump(), request.headers.get('idempotency-key'), rid(request)))

    @router.patch('/portal/alerts/{id}/review', response_model=Success[Overlay])
    def review(request: Request, id: ID, payload: AlertReviewInput, stream_id: Stream = None):
        return result(request, service.triage(actor(request), service.resolve('alert', id, stream_id),
                      payload.model_dump(), request.headers.get('idempotency-key'), rid(request)))

    @router.get('/portal/assignees', response_model=Success[AssigneePage])
    def assignees(request: Request, limit: Limit = 25, cursor: Cursor = None):
        return paged(request,'assignees',cursor,limit,
            lambda count,offset:service.users(actor(request),count,offset,assignees=True))

    @router.get('/portal/session/capabilities', response_model=Success[Capabilities])
    def capabilities(request: Request):
        from .models import WRITE_ROLES, EVIDENCE_ROLES
        user = actor(request)
        return result(request, {'user_id': user.user_id, 'portal_admin': user.portal_admin,
            'can_triage': bool(set(user.roles).intersection(WRITE_ROLES)),
            'can_read_notes': bool(set(user.roles).intersection(EVIDENCE_ROLES)),
            'network_actions_enabled': False, 'context': service.config.context})

    @router.get('/portal/admin/users', response_model=Success[UserPage])
    def users(request: Request, limit: Limit = 25, cursor: Cursor = None):
        return paged(request,'users',cursor,limit,lambda count,offset:service.users(actor(request),count,offset))

    @router.post('/portal/admin/users', response_model=Success[User])
    def create_user(request: Request, payload: UserCreate):
        fields = payload.model_dump()
        fields['password'] = payload.password.get_secret_value()
        return result(request, service.create_user(actor(request), fields, request.headers.get('idempotency-key'), rid(request)))

    @router.patch('/portal/admin/users/{id}', response_model=Success[User])
    def update_user(request: Request, id: ID, payload: UserUpdate):
        return result(request, service.update_user(actor(request), id, payload.model_dump(),
                      request.headers.get('idempotency-key'), rid(request)))

    @router.get('/portal/admin/audit', response_model=Success[ExtendedAuditPage])
    def audit_extended(request: Request, limit: Limit = 25, cursor: Cursor = None):
        return paged(request,'audit',cursor,limit,lambda count,offset:service.audit(actor(request),count,offset,extended=True),sequence=True)

    @router.get('/audit/admin-actions', response_model=Success[AuditPage])
    def audit_frozen(request: Request, limit: Limit = 25, cursor: Cursor = None):
        # Sequence is only needed internally for cursor generation, stripped from frozen DTO.
        user=actor(request)
        position=service.cursor(user,['audit-frozen',limit],token=cursor) if cursor else 0
        rows=service.audit(user,limit+1,position,extended=True)
        selected=rows[:limit]
        has_more=len(rows)>limit
        next_cursor=service.cursor(user,['audit-frozen',limit],offset=selected[-1]['sequence']) if has_more else None
        payload=envelope(request,service,{'items':[{k:v for k,v in row.items() if k not in {'sequence','before','after'}} for row in selected],
                                         'has_more':has_more,'next_cursor':next_cursor,'total_count':None})
        payload['meta']['next_cursor']=next_cursor
        return JSONResponse(payload)

    return router
