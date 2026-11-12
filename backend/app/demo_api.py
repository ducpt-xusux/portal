"""Read-only Evidence and Demo Coverage routes."""
from collections.abc import Callable
from ipaddress import ip_address
from typing import Annotated
from uuid import uuid4
from fastapi import APIRouter, Depends, Path, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from .api import require_key
from .defense_bundle import DefenseBundleError
from .defense_coverage import defense_coverage
from .evidence_models import EvidenceResponse, DemoResponse
from .evidence_registry import EvidenceError, EvidenceConfig, EvidenceRegistry, now
from .demo_coverage import metadata, evidence_view, coverage


def create_evidence_router(config: EvidenceConfig, role_resolver: Callable | None = None,
                           *, defense_registry_path=None, defense_archive_dir=None):
    """role_resolver(request) is a trusted server session adapter, never a browser header.

    Without it, only explicitly enabled loopback local owner access is accepted,
    including with a valid API key. This is intentionally stricter than remote key access.
    """
    registry = EvidenceRegistry(config)
    router = APIRouter(prefix='/api/v1', tags=['Evidence / demo'], dependencies=[Depends(require_key)])

    def error(request, status, code):
        request_id = getattr(request.state, 'request_id', str(uuid4()))
        return JSONResponse(status_code=status, content={'data': None,
            'meta': {'request_id': request_id, 'read_at': now(), 'source_system': 'OFFLINE_EVIDENCE_REGISTRY',
                     'freshness_state': 'UNAVAILABLE', 'sources': [], 'coverage_note': 'No usable result.'},
            'error': {'code': code, 'message': 'Evidence capability or source unavailable.', 'request_id': request_id}},
            headers={'X-Request-ID': request_id, 'Cache-Control': 'no-store'})

    def access(request, required):
        try:
            local = request.client is not None and ip_address(request.client.host).is_loopback
        except ValueError:
            local = False
        if role_resolver:
            try:
                roles = set(role_resolver(request) or [])
            except Exception:
                return error(request, 403, 'EVIDENCE_ROLE_UNAVAILABLE')
            permitted = {'Analyst', 'Operator', 'Approver', 'Executor', 'Auditor'}
            if required == 'Viewer':
                permitted.add('Viewer')
            if not roles.intersection(permitted):
                return error(request, 403, 'EVIDENCE_ROLE_REQUIRED')
        elif not config.local_readonly or not local:
            return error(request, 403, 'EVIDENCE_LOCAL_OWNER_ONLY')

    def serve(request, required, evidence_id=None):
        denied = access(request, required)
        if denied is not None:
            return denied
        if request.query_params:
            return error(request, 422, 'EVIDENCE_QUERY_UNSUPPORTED')
        try:
            index, registry_sha = registry.read()
            meta = metadata(index, registry_sha, getattr(request.state, 'request_id', str(uuid4())))
            if evidence_id is None:
                payload = DemoResponse(data=coverage(index), meta=meta)
            else:
                artifact = next((a for a in index.artifacts if a.evidence_id == evidence_id), None)
                if artifact is None:
                    return error(request, 404, 'EVIDENCE_NOT_FOUND')
                payload = EvidenceResponse(data=evidence_view(index, artifact, registry_sha), meta=meta)
            return JSONResponse(content=payload.model_dump(mode='json'), headers={
                'Cache-Control': 'no-store', 'X-Request-ID': meta.request_id,
                'X-Portal-Schema': 'portal-demo-coverage-2' if evidence_id is None else 'EvidenceArtifact-v4.1',
                'X-Portal-Access': 'SESSION_ADAPTER' if role_resolver else 'LOCAL_OWNER_READONLY'})
        except EvidenceError as exc:
            return error(request, 503, exc.code)

    @router.get('/evidence/{evidence_id}', response_model=EvidenceResponse,
                openapi_extra={'x-role-required': 'Analyst', 'x-readonly': True})
    def evidence(request: Request, evidence_id: Annotated[str, Path(min_length=1, max_length=100, pattern=r'^[A-Za-z0-9][A-Za-z0-9_.:-]*$')]):
        return serve(request, 'Analyst', evidence_id)

    @router.get('/system/demo-coverage', response_model=DemoResponse,
                openapi_extra={'x-role-required': 'Viewer', 'x-readonly': True, 'x-local-schema-version': 'portal-demo-coverage-2'})
    def demo(request: Request):
        return serve(request, 'Viewer')

    @router.get('/system/demo-coverage/defense-run',
                openapi_extra={'x-role-required': 'Viewer', 'x-readonly': True,
                               'x-local-schema-version': 'portal-defense-coverage-1'})
    def defense_run(request: Request):
        denied = access(request, 'Viewer')
        if denied is not None:
            return denied
        if request.query_params:
            return error(request, 422, 'EVIDENCE_QUERY_UNSUPPORTED')
        if defense_registry_path is None or defense_archive_dir is None:
            return error(request, 503, 'DEFENSE_COVERAGE_NOT_CONFIGURED')
        try:
            data = defense_coverage(defense_registry_path, defense_archive_dir)
        except DefenseBundleError as exc:
            return error(request, 503, exc.code)
        request_id = getattr(request.state, 'request_id', str(uuid4()))
        meta = {'request_id': request_id, 'read_at': now(), 'source_system': 'DEFENSE_ARCHIVES',
                'freshness_state': 'HISTORICAL'}
        return JSONResponse(jsonable_encoder({'data': data, 'meta': meta, 'error': None}),
                            headers={'Cache-Control': 'no-store', 'X-Request-ID': request_id})

    return router
