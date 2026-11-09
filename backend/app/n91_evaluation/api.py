"""Router factory. Mount once; never redeclare existing evaluation run routes."""
from collections.abc import Callable
from typing import Annotated, Literal
from uuid import uuid4
from fastapi import APIRouter, Depends, Path, Request
from fastapi.responses import JSONResponse
from ..api import require_key
from .service import EvaluationSystemService, now
from .sources import SourceError
from .views import (Response, Page, EvaluationCaseView, CorrelationScenarioView, BackupArtifact,
    RestoreRunView, ResilienceRunView, TlsRouteHealth, P19LabGate)
from .panels import EvaluationPanel, SystemPanel

IdPath = Annotated[str, Path(min_length=1,max_length=100,pattern=r'^[A-Za-z0-9][A-Za-z0-9_.:-]*$')]
READ_ROLES={'Viewer','Analyst','Operator','Approver','Executor','Auditor'}


def create_evaluation_system_router(service: EvaluationSystemService | None = None,
                                    role_resolver: Callable | None = None):
    """Trusted resolver must enforce active session identity. No local/header fallback.

    The host must atomically apply its session gate across legacy APIs and all
    routers when session mode is enabled. Existing API-key requirement is kept.
    """
    service = service if service is not None else EvaluationSystemService()
    router=APIRouter(prefix='/api/v1',tags=['N91 Evaluation / System'],dependencies=[Depends(require_key)])

    def result(request,data=None,sha=None,code=None,status=200):
        request_id=getattr(request.state,'request_id',str(uuid4()))
        src=service.provenance(sha) if sha else None
        payload=dict(data=data,meta=dict(request_id=request_id,read_at=now(),
            source_system='N91_EVALUATION_SYSTEM',source_schema='n91-evaluation-system-1',
            freshness_state='UNAVAILABLE' if code else 'HISTORICAL',sources=[src] if src else [],
            coverage_note='Frozen imported scope only; expected catalog does not establish an observation.'),
            error=dict(code=code,message='Evaluation/System capability or source unavailable.',request_id=request_id) if code else None)
        return JSONResponse(payload,status_code=status,headers={'Cache-Control':'no-store','X-Request-ID':request_id})

    def serve(request,operation):
        if role_resolver is None:
            return result(request,code='EVALUATION_SYSTEM_SESSION_REQUIRED',status=401)
        try:
            roles=set(role_resolver(request) or [])
        except Exception:
            return result(request,code='EVALUATION_SYSTEM_SESSION_UNAVAILABLE',status=403)
        if not roles.intersection(READ_ROLES):
            return result(request,code='EVALUATION_SYSTEM_ROLE_REQUIRED',status=403)
        if request.query_params:
            return result(request,code='EVALUATION_SYSTEM_QUERY_UNSUPPORTED',status=422)
        try:
            data,sha=operation()
            return result(request,data,sha)
        except SourceError as exc:
            return result(request,code=exc.code,status=exc.status)

    def page(rows):
        return dict(items=rows,has_more=False,next_cursor=None)

    def selected(rows,key,value):
        item=next((r for r in rows if r[key]==value),None)
        if item is None:
            raise SourceError('EVALUATION_SYSTEM_ITEM_NOT_FOUND',404)
        return item

    @router.get('/evaluations/runs/{run_id}/cases',response_model=Response[Page[EvaluationCaseView]],openapi_extra={'x-role-required':'Viewer','x-readonly':True})
    def cases(request:Request,run_id:IdPath):
        def read():
            rows,sha=service.cases(request,run_id)
            return page(rows),sha
        return serve(request,read)

    @router.get('/evaluations/runs/{run_id}/cases/{case_id}',response_model=Response[EvaluationCaseView],openapi_extra={'x-role-required':'Viewer','x-readonly':True})
    def case(request:Request,run_id:IdPath,case_id:IdPath):
        def read():
            rows,sha=service.cases(request,run_id)
            return selected(rows,'case_id',case_id),sha
        return serve(request,read)

    @router.get('/evaluations/runs/{run_id}/correlations',response_model=Response[Page[CorrelationScenarioView]],openapi_extra={'x-role-required':'Viewer','x-readonly':True})
    def correlations(request:Request,run_id:IdPath):
        def read():
            rows,sha=service.correlations(request,run_id)
            return page(rows),sha
        return serve(request,read)

    @router.get('/evaluations/runs/{run_id}/correlations/{scenario_id}',response_model=Response[CorrelationScenarioView],openapi_extra={'x-role-required':'Viewer','x-readonly':True})
    def correlation(request:Request,run_id:IdPath,scenario_id:IdPath):
        def read():
            rows,sha=service.correlations(request,run_id)
            return selected(rows,'scenario_id',scenario_id),sha
        return serve(request,read)

    def system_page(kind):
        def read():
            rows,sha=service.frozen_system(kind)
            return page(rows),sha
        return read

    @router.get('/system/backups',response_model=Response[Page[BackupArtifact]],openapi_extra={'x-role-required':'Viewer','x-readonly':True})
    def backups(request:Request):
        return serve(request,system_page('backups'))

    @router.get('/system/restore-runs',response_model=Response[Page[RestoreRunView]],openapi_extra={'x-role-required':'Viewer','x-readonly':True})
    def recoveries(request:Request):
        return serve(request,system_page('recoveries'))

    @router.get('/system/restore-runs/{restore_run_id}',response_model=Response[RestoreRunView],openapi_extra={'x-role-required':'Viewer','x-readonly':True})
    def recovery(request:Request,restore_run_id:IdPath):
        def read():
            rows,sha=service.frozen_system('recoveries')
            return selected(rows,'restore_run_id',restore_run_id),sha
        return serve(request,read)

    @router.get('/system/resilience-runs',response_model=Response[Page[ResilienceRunView]],openapi_extra={'x-role-required':'Viewer','x-readonly':True})
    def resilience(request:Request):
        return serve(request,system_page('resilience'))

    @router.get('/system/resilience-runs/{run_id}',response_model=Response[ResilienceRunView],openapi_extra={'x-role-required':'Viewer','x-readonly':True})
    def resilience_detail(request:Request,run_id:IdPath):
        def read():
            rows,sha=service.frozen_system('resilience')
            return selected(rows,'run_id',run_id),sha
        return serve(request,read)

    @router.get('/system/tls',response_model=Response[Page[TlsRouteHealth]],openapi_extra={'x-role-required':'Viewer','x-readonly':True})
    def tls(request:Request):
        return serve(request,system_page('tls'))

    @router.get('/system/p19-gate',response_model=Response[P19LabGate],openapi_extra={'x-role-required':'Viewer','x-readonly':True})
    def p19(request:Request):
        def read():
            rows,sha=service.frozen_system('p19')
            return rows[0],sha
        return serve(request,read)

    # Separate additive namespace for mode/context/request multiplicity and decimal metrics.
    @router.get('/n91/evaluation-system/catalog',openapi_extra={'x-role-required':'Viewer','x-readonly':True})
    def catalog(request:Request):
        return serve(request,lambda:(service.catalog,service.catalog['source_document_sha256']))

    @router.get('/n91/evaluation-system/runs/{run_id}',response_model=Response[EvaluationPanel],openapi_extra={'x-role-required':'Viewer','x-readonly':True})
    def evaluation_panel(request:Request,run_id:IdPath):
        return serve(request,lambda:service.evaluation_panel(request,run_id))

    @router.get('/n91/evaluation-system/panels/{kind}',response_model=Response[SystemPanel],openapi_extra={'x-role-required':'Viewer','x-readonly':True})
    def panel(request:Request,kind:Literal['backups','recoveries','resilience','tls','privacy','staging','p19']):
        return serve(request,lambda:service.system_panel(kind))

    return router
