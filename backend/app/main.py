import asyncio
from contextlib import asynccontextmanager, suppress
import logging
import sqlite3
from ipaddress import ip_address
from uuid import uuid4

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

from .api import require_key, router, response
from .config import Settings
from .ingest import Importer
from .schemas import utc_now
from .store import Store
from .p17_snapshot import SnapshotReader
from .p17_api import CursorCodec, evaluation_run_router, observation_auth_router, quarantine_router, require_read_access, router as p17_router, source_status_router
from .openstack_inventory import InventoryError, InventoryReader
from .remote_console import ConsoleService
from .workload_quarantine import WorkloadQuarantine
from .build_info import load_build_info
from .demo_api import create_evidence_router
from .evidence_registry import EvidenceConfig, EvidenceRegistry
from .integration_sources import business_evidence_loader, business_snapshot_resolver, evaluation_sources, investigation_sources
from .n91_business import BusinessConfig, BusinessService, SessionGate, create_business_router, trusted_roles
from .n91_business.gate import INCIDENT_WRITE_POLICIES
from .n91_evaluation.api import create_evaluation_system_router
from .n91_investigation.api import assert_no_duplicate_routes, business_session_access_gate, create_investigation_router


SESSION_POLICIES = (
    ('GET', '/api/v1/system/build', 'read'),
    ('GET', '/api/v1/system/demo-coverage/defense-run', 'read'),
    ('GET', '/api/v1/portal/incidents/{incident_id}/investigation', 'evidence'),
    ('GET', '/api/v1/portal/investigation/response-history', 'evidence'),
    ('GET', '/api/v1/investigation/actions/{action_id}/sg-lifecycle', 'evidence'),
    ('GET', '/api/v1/n91/evaluation-system/catalog', 'read'),
    ('GET', '/api/v1/n91/evaluation-system/runs/{run_id}', 'read'),
    ('GET', '/api/v1/n91/evaluation-system/panels/{kind}', 'read'),
    ('POST', '/api/v1/workloads/{server_id}/quarantine', 'execute'),
)


def validate_business_database(config, settings, evidence):
    if config.database_path is None:
        return
    path = config.database_path.resolve()
    sources = (
        settings.audit_path, settings.database_path, settings.p17_snapshot_path,
        evidence.index_path, settings.evaluation_index_path, settings.proxy_sync_status_path,
        settings.openstack_credential_path, settings.openstack_console_credential_path,
        settings.openstack_quarantine_credential_path,
        settings.investigation_policy_path, settings.investigation_controller_path,
        settings.investigation_controller_archive_path, settings.investigation_controller_binding_path,
        settings.evaluation_observations_path, settings.system_observations_path,
        settings.defense_source_registry_path,
    )
    for source in sources:
        if source is None:
            continue
        if path == source.resolve() or (path.is_file() and source.is_file() and path.samefile(source)):
            raise ValueError('Business DB must be separate from Portal caches and source files')


def create_app(settings: Settings | None = None, *, evidence_config: EvidenceConfig | None = None,
               evidence_role_resolver=None, session_auth_enabled: bool | None = None,
               business_config: BusinessConfig | None = None, business_source_resolver=None,
               investigation_service=None, evaluation_system_service=None):
    settings = settings or Settings.from_env()
    session_enabled = settings.session_auth_enabled if session_auth_enabled is None else session_auth_enabled
    evidence = evidence_config if evidence_config is not None else EvidenceConfig(
        settings.evidence_index_path, settings.evidence_local_readonly)
    snapshot_reader = SnapshotReader(settings.p17_snapshot_path, settings.proxy_sync_status_path)
    business = None
    if session_enabled:
        config = business_config or BusinessConfig(
            database_path=settings.business_database_path,
            secure_cookie=not settings.session_local_http,
            allow_insecure_loopback=settings.session_local_http,
            trusted_origins=settings.cors_origins if settings.business_database_path else (),
        )
        validate_business_database(config, settings, evidence)
        if config.context == 'TEST' and settings.mode != 'snapshot':
            raise ValueError('TEST sessions require an isolated snapshot instance')
        resolver = business_source_resolver or business_snapshot_resolver(snapshot_reader, config.context)
        business = BusinessService(config, source_resolver=resolver, evidence_loader=business_evidence_loader(
            snapshot_reader, config.context, settings.p16h_import_context) if settings.p17_snapshot_path else None)
    store = Store(settings.database_path)
    importer = Importer(settings, store)
    inventory = InventoryReader(settings, history_store=store)

    async def poll():
        while True:
            await asyncio.sleep(settings.poll_seconds)
            try:
                await asyncio.to_thread(importer.sync)
            except sqlite3.Error:
                logging.getLogger(__name__).error("Audit SQLite synchronization failed")

    async def poll_inventory():
        while True:
            started = inventory.monotonic()
            try:
                await asyncio.to_thread(inventory.sample)
            except InventoryError:
                # Inventory metadata already reports read errors and stale data.
                pass
            await asyncio.sleep(max(0.1, inventory.refresh_seconds - (inventory.monotonic() - started)))

    @asynccontextmanager
    async def lifespan(app):
        store.initialize()
        await asyncio.to_thread(importer.sync)
        tasks = [asyncio.create_task(poll())]
        if settings.openstack_enabled and settings.openstack_quarantine_sg_id:
            tasks.append(asyncio.create_task(poll_inventory()))
        try:
            yield
        finally:
            for task in tasks:
                task.cancel()
            for task in tasks:
                with suppress(asyncio.CancelledError):
                    await task

    app = FastAPI(
        title="DB Security Portal API", version="0.2.0", lifespan=lifespan,
        description="Read-only P16 audit APIs. Events are imported from the configured JSONL source. "
                    "Snapshot mode serves historical records; live mode follows the Proxy log. "
                    "Portal v4 can read an explicitly configured historical P17 JSON export. "
                    "P17 remains incident authority. VM quarantine requires a dedicated credential and an Executor session.",
    )
    app.state.settings, app.state.store, app.state.importer = settings, store, importer
    app.state.p17_reader = snapshot_reader
    app.state.p17_cursors = CursorCodec()
    app.state.openstack_inventory = inventory
    app.state.console_service = ConsoleService(settings)
    app.state.workload_quarantine = WorkloadQuarantine(settings)
    app.state.quarantine_audit = business
    app.state.build_info = load_build_info(settings.build_manifest_path)
    app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_origins),
                       allow_methods=["GET"], allow_headers=["X-API-Key", "Content-Type"])

    @app.middleware("http")
    async def request_id(request: Request, call_next):
        request.state.request_id = getattr(request.state, 'request_id', str(uuid4()))
        result = await call_next(request)
        result.headers["X-Request-ID"] = request.state.request_id
        result.headers["Cache-Control"] = "no-store"
        return result

    def error(request, status, detail):
        meta = {"request_id": getattr(request.state, "request_id", str(uuid4())), "timestamp": utc_now()}
        if request.url.path.startswith('/api/v1/'):
            meta.update(read_at=utc_now(), freshness_state="UNKNOWN")
        payload = {"data": None, "meta": meta, "error": detail}
        return JSONResponse(status_code=status, content=payload,
                            headers={"X-Request-ID": payload["meta"]["request_id"], "Cache-Control": "no-store"})

    @app.exception_handler(HTTPException)
    async def http_error(request, exc):
        detail = exc.detail if isinstance(exc.detail, dict) else {"code": "HTTP_ERROR", "message": str(exc.detail)}
        return error(request, exc.status_code, detail)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        return error(request, 422, {"code": "VALIDATION_ERROR", "message": "Invalid request parameters.",
                                    "fields": [".".join(map(str, item["loc"])) for item in exc.errors()]})

    @app.exception_handler(sqlite3.Error)
    async def database_error(request, exc):
        return error(request, 503, {"code": "AUDIT_STORE_UNAVAILABLE", "message": "The audit store is unavailable."})

    @app.exception_handler(Exception)
    async def unexpected_error(request, exc):
        logging.getLogger(__name__).error("Unhandled API error request_id=%s", request.state.request_id)
        return error(request, 500, {"code": "INTERNAL_ERROR", "message": "The request could not be completed."})

    @app.get("/health", tags=["Health"])
    @app.get("/healthz", tags=["Health"])
    def health(request: Request):
        """Process liveness only; /api/system/health reports source availability."""
        return response(request, {"status": "OK", "scope": "process_only"})

    @app.get('/api/v1/portal/access-mode', include_in_schema=False)
    def access_mode(request: Request):
        return response(request, {
            'mode': 'SESSION' if session_enabled else 'OBSERVATION',
            'console_proxy_allowed': not session_enabled and settings.openstack_console_enabled,
            'workload_quarantine_available': bool(
                business is not None and business.config.context == 'PORTAL'
                and business.config.database_path and app.state.workload_quarantine.configured()
            ),
        })

    @app.get("/api/v1/system/build", dependencies=[Depends(require_key), Depends(require_read_access)])
    def build_status(request: Request):
        return response(request, request.app.state.build_info)

    def observation_investigation_access(request, required):
        require_read_access(request)
        try:
            local = request.client is not None and ip_address(request.client.host).is_loopback
        except ValueError:
            local = False
        return local and (required == 'Viewer' or evidence.local_readonly)

    app.include_router(router)
    app.include_router(p17_router)
    app.include_router(evaluation_run_router)
    app.include_router(source_status_router)
    if business:
        app.include_router(create_business_router(business), dependencies=[Depends(require_key)])
        app.include_router(quarantine_router)
    else:
        app.include_router(observation_auth_router)
        def observation_write_denied(request: Request):
            return error(request, 403, {'code': 'OBSERVATION_READ_ONLY',
                                        'message': 'This operation requires Portal session access.'})
        for method, path, _ in (*INCIDENT_WRITE_POLICIES,
                                ('POST', '/api/v1/workloads/{server_id}/quarantine', 'execute')):
            app.add_api_route(path, observation_write_denied, methods=[method], include_in_schema=False)
    app.include_router(create_evidence_router(
        evidence, trusted_roles if business else evidence_role_resolver,
        defense_registry_path=settings.defense_source_registry_path,
        defense_archive_dir=settings.defense_archive_dir,
    ))
    app.include_router(create_investigation_router(
        investigation_service or investigation_sources(settings),
        access_gate=business_session_access_gate if business else observation_investigation_access,
        include_replacements=True,
    ))
    app.include_router(create_evaluation_system_router(
        evaluation_system_service or evaluation_sources(settings, EvidenceRegistry(evidence)),
        trusted_roles if business else None,
    ))
    assert_no_duplicate_routes(app)
    if business:
        app.add_middleware(SessionGate, service=business, extra_policies=SESSION_POLICIES)
    return app


app = create_app()
