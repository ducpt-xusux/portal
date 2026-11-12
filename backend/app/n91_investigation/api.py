"""Injectable API with an application-owned access gate and no local fallback."""
from inspect import isawaitable
import re
from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from starlette.concurrency import run_in_threadpool

from ..api import require_key
from .aggregate import InvestigationAggregate
from .aggregate_models import (InvestigationErrorMeta, InvestigationErrorResponse,
    InvestigationResponse, InvestigationSessionErrorResponse)
from .models import ActionsPage, ActionView, DecisionTrace, PolicyCatalog, PolicyRuleDetail, Response, SgLifecycleView, SourceStamp, TimelineView
from .response_history import ResponseHistory, read_history
from .service import InvestigationService, action_dict, dump, freshness
from .sources import SourceError

IdPath = Annotated[str, Path(min_length=1, max_length=160, pattern=r'^[A-Za-z0-9][A-Za-z0-9_.:-]*$')]
IdQuery = Annotated[str | None, Query(min_length=1, max_length=160, pattern=r'^[A-Za-z0-9][A-Za-z0-9_.:-]*$')]


def request_id(request):
    return getattr(request.state, 'request_id', str(uuid4()))


def reply(request, service, data=None, source=None, *, status=200, code=None):
    rid = request_id(request)
    source = source or SourceStamp(source_system='INVESTIGATION', source_ref='unavailable',
        source_schema='investigation-1', execution_mode=service.mode, freshness_state='UNAVAILABLE')
    observed = source.observed_at
    payload = {'data': data, 'meta': {
        'request_id': rid, 'read_at': service.clock().isoformat(),
        'data_as_of': observed.isoformat() if observed else None,
        'source_system': source.source_system, 'source_schema': source.source_schema,
        'freshness_state': source.freshness_state, 'next_cursor': data.get('next_cursor') if isinstance(data, dict) else None,
        'sources': [dump(freshness(source, service.clock()))],
        'coverage_note': f'execution_mode={source.execution_mode}; verification={source.verification}; human_review=UNAVAILABLE; no mutation; no full-history claim.'},
        'error': {'code': code, 'message': 'Investigation source or capability unavailable.', 'request_id': rid} if code else None}
    return JSONResponse(status_code=status, content=payload, headers={
        'Cache-Control': 'no-store', 'X-Request-ID': rid,
        'X-Investigation-Mode': source.execution_mode})


def create_investigation_router(service=None, *, access_gate=None, include_replacements=False):
    """access_gate(request, 'Viewer'|'Analyst') is a trusted server dependency.

    It may raise HTTPException/SourceError (401/403). Only literal True grants
    access. No role header, API-key-only or loopback access can substitute for it.
    Keep the application's require_key dependency in addition to session auth.
    Default excludes four existing handlers: A must replace/delegate them first.
    """
    service = service or InvestigationService()
    aggregate = InvestigationAggregate(clock=service.clock, service=service)

    class SafeRoute(APIRoute):
        def failure(self, request, status, code):
            if self.response_model is InvestigationResponse:
                rid = request_id(request)
                payload = InvestigationErrorResponse(meta=InvestigationErrorMeta(
                    request_id=rid, read_at=service.clock()), error={
                    'code': code, 'message': 'Investigation source or capability unavailable.', 'request_id': rid})
                return JSONResponse(status_code=status, content=payload.model_dump(mode='json'),
                    headers={'Cache-Control': 'no-store', 'X-Request-ID': rid})
            return reply(request, service, status=status, code=code)

        def get_route_handler(self):
            original = super().get_route_handler()

            async def handler(request):
                try:
                    result = await original(request)
                    if self.response_model and isinstance(result, JSONResponse) and result.status_code == 200:
                        self.response_model.model_validate_json(result.body)
                    return result
                except SourceError as exc:
                    return self.failure(request, exc.status, exc.code)
                except RequestValidationError:
                    return self.failure(request, 422, 'INVESTIGATION_INVALID_REQUEST')
                except HTTPException as exc:
                    code = exc.detail.get('code') if isinstance(exc.detail, dict) else None
                    if not isinstance(code, str) or not re.fullmatch(r'[A-Z0-9_]{1,80}', code):
                        code = 'INVESTIGATION_ACCESS_DENIED' if exc.status_code in {401, 403} else 'INVESTIGATION_REQUEST_FAILED'
                    return self.failure(request, exc.status_code, code)
                except Exception:
                    # Never echo filesystem exceptions, raw values or stack traces.
                    return self.failure(request, 503, 'INVESTIGATION_SOURCE_INVALID')
            return handler

    router = APIRouter(prefix='/api/v1', tags=['Investigation'], route_class=SafeRoute,
                       dependencies=[Depends(require_key)])

    async def authorize(request, required, allowed_query=()):
        if access_gate is None:
            raise SourceError('INVESTIGATION_ACCESS_NOT_CONFIGURED', 403)
        allowed = access_gate(request, required)
        if isawaitable(allowed):
            allowed = await allowed
        if allowed is not True:
            raise SourceError('INVESTIGATION_FORBIDDEN', 403)
        if set(request.query_params) - set(allowed_query) or any(len(request.query_params.getlist(k)) != 1 for k in request.query_params):
            raise SourceError('INVESTIGATION_QUERY_UNSUPPORTED', 422)

    async def policies(request: Request):
        await authorize(request, 'Viewer')
        catalog, source = await run_in_threadpool(service.policy_catalog)
        return reply(request, service, dump(catalog), source)

    @router.get('/system/policies/{rule_id}', response_model=Response[PolicyRuleDetail],
                openapi_extra={'x-role-required': 'Viewer', 'x-readonly': True})
    async def rule_detail(request: Request, rule_id: IdPath):
        await authorize(request, 'Viewer')
        data, source = await run_in_threadpool(service.rule_detail, rule_id)
        return reply(request, service, dump(data), source)

    @router.get('/events/{event_id}/decision-trace', response_model=Response[DecisionTrace],
                openapi_extra={'x-role-required': 'Viewer', 'x-readonly': True})
    async def event_trace(request: Request, event_id: IdPath, stream_id: IdQuery = None):
        await authorize(request, 'Viewer', ('stream_id',))
        data, source = await run_in_threadpool(service.event_trace, request, event_id, stream_id)
        return reply(request, service, dump(data), source)

    @router.get('/incidents/{incident_id}/decision-trace', response_model=Response[DecisionTrace],
                openapi_extra={'x-role-required': 'Analyst', 'x-readonly': True})
    async def incident_trace(request: Request, incident_id: IdPath):
        await authorize(request, 'Analyst')
        data, source = await run_in_threadpool(service.incident_trace, request, incident_id)
        return reply(request, service, dump(data), source)

    @router.get('/portal/incidents/{incident_id}/investigation', response_model=InvestigationResponse,
                responses={**{status: {'model': InvestigationErrorResponse} for status in (404, 409, 422, 503)},
                    **{status: {'model': InvestigationErrorResponse | InvestigationSessionErrorResponse}
                       for status in (401, 403)}},
                openapi_extra={'x-local-schema-version': 'portal-investigation-1',
                               'x-role-required': 'Analyst', 'x-readonly': True})
    async def incident_investigation(request: Request, incident_id: IdPath,
            stream_id: Annotated[str, Query(min_length=1, max_length=160,
                pattern=r'^[A-Za-z0-9][A-Za-z0-9_.:-]*$')],
            events_limit: Annotated[int, Query(ge=1, le=100)] = 25,
            events_cursor: Annotated[str | None, Query(max_length=2048)] = None):
        await authorize(request, 'Analyst', ('stream_id', 'events_limit', 'events_cursor'))
        result = await run_in_threadpool(aggregate.read, request, incident_id, stream_id,
                                        events_limit, events_cursor)
        return JSONResponse(result.model_dump(mode='json'), headers={
            'Cache-Control': 'no-store', 'X-Request-ID': request_id(request),
            'X-Investigation-Mode': result.meta.execution_mode})

    @router.get('/portal/investigation/response-history', response_model=Response[ResponseHistory],
                openapi_extra={'x-local-schema-version': 'portal-response-history-1',
                               'x-role-required': 'Analyst', 'x-readonly': True})
    async def controller_response_history(request: Request, current: bool = False):
        await authorize(request, 'Analyst', ('current',))
        history, source = await run_in_threadpool(read_history, request, service, include_current=current)
        return reply(request, service, dump(history), source)

    async def timeline(request: Request, incident_id: IdPath):
        await authorize(request, 'Viewer')
        data, source = await run_in_threadpool(service.timeline, request, incident_id)
        return reply(request, service, dump(data), source)

    async def actions(request: Request, incident_id: IdQuery = None,
                      server_id: IdQuery = None,
                      limit: Annotated[int, Query(ge=1, le=100)] = 25,
                      cursor: Annotated[str | None, Query(max_length=2048)] = None):
        await authorize(request, 'Viewer', ('incident_id', 'server_id', 'limit', 'cursor'))
        data, source = await run_in_threadpool(service.actions, request, incident_id, limit, cursor, server_id)
        return reply(request, service, data, source)

    async def action(request: Request, action_id: IdPath):
        await authorize(request, 'Viewer')
        data, source = await run_in_threadpool(service.action, request, action_id)
        return reply(request, service, action_dict(data), source)

    # Explicit additive namespace: frozen ActionView cannot carry cycle/current,
    # null SG phases, context ARM or metric semantics. ADR and JSON schema shipped.
    @router.get('/investigation/actions/{action_id}/sg-lifecycle', response_model=Response[SgLifecycleView],
                openapi_extra={'x-local-schema-version': 'investigation-sg-lifecycle-1', 'x-readonly': True, 'x-role-required': 'Analyst'})
    async def lifecycle(request: Request, action_id: IdPath):
        await authorize(request, 'Analyst')
        data, source = await run_in_threadpool(service.sg_lifecycle, request, action_id)
        return reply(request, service, data, source)

    # Enable only after removing/delegating the existing exact shared handlers.
    if include_replacements:
        for path, endpoint, model in (
            ('/system/policies', policies, PolicyCatalog),
            ('/incidents/{incident_id}/timeline', timeline, TimelineView),
            ('/actions', actions, ActionsPage),
            ('/actions/{action_id}', action, ActionView),
        ):
            router.add_api_route(path, endpoint, methods=['GET'], response_model=Response[model],
                openapi_extra={'x-readonly': True, 'x-role-required': 'Viewer'})
    return router


def business_session_access_gate(request, required):
    """Adapter for D's outer SessionGate. Missing gate/principal always denies.

    Activation must still protect every legacy/API/console surface atomically.
    This function does not activate a session or authenticate browser headers.
    """
    actor = getattr(request.state, 'business_principal', None)
    business = getattr(request.state, 'business_gate_service', None)
    if actor is None or business is None:
        raise SourceError('SESSION_REQUIRED', 401)
    roles = set(getattr(actor, 'roles', ()))
    permitted = {'Analyst', 'Operator', 'Approver', 'Executor', 'Auditor'}
    if required == 'Viewer':
        permitted.add('Viewer')
    if not roles.intersection(permitted):
        raise SourceError('INVESTIGATION_ROLE_REQUIRED', 403)
    return True


def route_operations(app, prefix=''):
    """Handle flattened routers and FastAPI 0.148 deferred include objects."""
    for route in app.routes:
        included = getattr(route, 'original_router', None)
        if included is not None:
            context = getattr(route, 'include_context', None)
            yield from route_operations(included, prefix + getattr(context, 'prefix', ''))
        elif hasattr(route, 'path'):
            for method in getattr(route, 'methods', set()):
                yield method, prefix + route.path


def assert_no_duplicate_routes(app):
    seen = set()
    for method, raw_path in route_operations(app):
        # {id} and {incident_id} are the same HTTP route.
        path = re.sub(r'\{[^}]+\}', '{}', raw_path)
        identity = method, path
        if identity in seen:
            raise ValueError('Duplicate HTTP method/path; replace existing handler before mounting')
        seen.add(identity)
