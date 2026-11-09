"""Independent source counters. This is not a conversion cohort or a detector."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import sqlite3
from typing import Literal
from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, AwareDatetime, StrictInt, model_validator
from . import canonical_audit
from .api import duration
from .alerts import read_alerts, alert_key, AlertError
from .p17_snapshot import SnapshotError, snapshot_meta, unique_object
from .schemas import iso, utc_now


class DTO(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Source(DTO):
    source_system: str = Field(max_length=160)
    source_ref: str | None = None
    source_schema: str | None = None
    data_as_of: AwareDatetime | None = None
    observed_at: AwareDatetime | None = None
    read_at: AwareDatetime
    freshness_state: Literal['FRESH','STALE','PARTIAL','UNKNOWN','UNAVAILABLE','HISTORICAL']
    age_seconds: int | None = None
    error_code: str | None = None
    coverage_kind: Literal['COMPLETE_QUERY_WINDOW','RECENT_SAMPLE','P17_PROJECTION','CACHE_ONLY','NOT_PROVEN']


class Meta(DTO):
    request_id: str
    read_at: AwareDatetime
    source_system: str
    freshness_state: Literal['FRESH','STALE','PARTIAL','UNKNOWN','UNAVAILABLE','HISTORICAL']
    sources: list[Source]
    coverage_note: str


class Metric(DTO):
    key: str
    count: StrictInt | None = Field(ge=0)
    unit: Literal['AUDIT_EVENTS','REQUESTS','ALERTS','INCIDENTS','ACTIONS']


class Stage(DTO):
    stage: Literal['REQUEST','PARSE','POLICY','ALERT','INCIDENT','ACTION']
    metrics: list[Metric]
    status: Literal['PARTIAL','UNAVAILABLE','STALE','HISTORICAL']
    reason_code: str
    window_from: AwareDatetime
    window_to: AwareDatetime
    time_basis: str
    source: Source


class Funnel(DTO):
    context: Literal['LIVE','EVALUATION']
    run_id: str | None
    window_from: AwareDatetime
    window_to: AwareDatetime
    scope: Literal['INDEPENDENT_SOURCE_COUNTERS'] = 'INDEPENDENT_SOURCE_COUNTERS'
    cohort_linked: Literal[False] = False
    stages: list[Stage]


class FunnelResponse(DTO):
    data: Funnel
    meta: Meta
    error: None = None


class Counts(DTO):
    passed: StrictInt = Field(alias='pass', ge=0)
    fail: StrictInt = Field(ge=0)
    incomplete: StrictInt = Field(ge=0)
    not_executed: StrictInt = Field(ge=0)
    unknown: StrictInt = Field(ge=0)
    na: StrictInt = Field(ge=0)


class EvaluationRun(DTO):
    run_id: str = Field(min_length=1,max_length=100,pattern=r'^[A-Za-z0-9][A-Za-z0-9_.-]*$')
    dataset: Literal['P14_P17_60','P17_CORR_13','COMBINED','OTHER']
    run_kind: Literal['LIVE','OFFLINE','HISTORICAL','MIXED']
    started_at: AwareDatetime | None = None
    completed_at: AwareDatetime | None = None
    status: Literal['COMPLETE','PARTIAL','NOT_EXECUTED','UNKNOWN']
    policy_version: str | None = Field(default=None,max_length=128)
    source_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    case_count: StrictInt = Field(ge=0,le=100000)
    counts: Counts
    review_state: Literal['CANDIDATE','OWNER_REVIEWED','INDEPENDENT_REVIEWED','UNREVIEWED']
    limitations: list[str] = Field(max_length=30)
    provenance: Source

    @model_validator(mode='after')
    def consistent(self):
        if sum(self.counts.model_dump().values()) != self.case_count:
            raise ValueError('Count mismatch')
        if self.status == 'NOT_EXECUTED' and self.counts.not_executed != self.case_count:
            raise ValueError('Unexecuted fixture is not an observation')
        if self.provenance.source_ref != 'sha256:' + self.source_sha256:
            raise ValueError('Missing source hash reference')
        if self.started_at and self.completed_at and self.completed_at < self.started_at:
            raise ValueError('Time mismatch')
        if any(len(note)>1000 for note in self.limitations):
            raise ValueError('Oversized note')
        return self


class RunsPage(DTO):
    items: list[EvaluationRun]
    has_more: Literal[False] = False
    next_cursor: None = None


class RunsResponse(DTO):
    data: RunsPage
    meta: Meta
    error: None = None


class RunResponse(DTO):
    data: EvaluationRun
    meta: Meta
    error: None = None


def fail(code, status=503):
    raise HTTPException(status, {'code':code,'message':'Requested dashboard source is unavailable or invalid.'})


def source(meta=None, system='unavailable', coverage='NOT_PROVEN', error=None):
    meta = meta or {}
    state = 'UNAVAILABLE' if error else 'STALE' if meta.get('freshness_state')=='STALE' else 'HISTORICAL' if meta.get('source_mode') == 'SNAPSHOT' else meta.get('freshness_state','UNKNOWN')
    return Source(source_system=system, source_ref=meta.get('source_ref'), source_schema=meta.get('source_schema'),
        data_as_of=meta.get('data_as_of'), read_at=utc_now(), freshness_state=state,
        coverage_kind='CACHE_ONLY' if state=='STALE' else coverage, error_code=error or meta.get('last_error_code'))


def read_runs(request):
    path = request.app.state.settings.evaluation_index_path
    if path is None:
        fail('EVALUATION_SOURCE_NOT_CONFIGURED')
    try:
        with path.open('rb') as stream:
            raw = stream.read(2*1024*1024+1)
        if len(raw)>2*1024*1024:
            raise ValueError()
        document = json.loads(raw.decode('utf-8-sig'), object_pairs_hook=unique_object)
        if set(document) != {'schema','runs'} or document['schema'] != 'portal-evaluation-index-1' or not isinstance(document['runs'],list) or len(document['runs'])>100:
            raise ValueError()
        runs = [EvaluationRun.model_validate(value) for value in document['runs']]
        if len({run.run_id for run in runs})!=len(runs):
            raise ValueError()
        # A frozen run remains historical even if its planned execution mode was LIVE.
        for run in runs:
            run.provenance.freshness_state='HISTORICAL'
            run.provenance.read_at=datetime.now(timezone.utc)
        src = source({'source_ref':'sha256:'+hashlib.sha256(raw).hexdigest(),'source_schema':'portal-evaluation-index-1','source_mode':'SNAPSHOT'},'evaluation-index')
        return runs, src
    except OSError:
        fail('EVALUATION_SOURCE_UNAVAILABLE')
    except (ValueError,TypeError,KeyError,RecursionError):
        fail('EVALUATION_SOURCE_INVALID')


def evaluation_response(request, run_id=None):
    runs, src = read_runs(request)
    data = RunsPage(items=sorted(runs,key=lambda r:r.run_id))
    if run_id is not None:
        data = next((run for run in runs if run.run_id==run_id),None)
        if data is None:
            fail('EVALUATION_RUN_NOT_FOUND',404)
    return {'data':data,'meta':Meta(request_id=request.state.request_id,read_at=utc_now(),source_system='evaluation-index',
        freshness_state='HISTORICAL',sources=[src],coverage_note='Frozen run summaries only; not live SQL counters.'),'error':None}


def build_funnel(request, window, end, context, run_id):
    period=duration(window)
    if period>timedelta(days=1):
        fail('WINDOW_TOO_LARGE',422)
    finish=end or datetime.now(timezone.utc)
    start=finish-period
    if context=='LIVE' and run_id:
        fail('RUN_ID_REQUIRES_EVALUATION',422)
    definitions=[('REQUEST',[('requests','REQUESTS'),('audit_events','AUDIT_EVENTS')]),
                 ('PARSE',[('valid','REQUESTS'),('invalid','REQUESTS')]),
                 ('POLICY',[('allow','AUDIT_EVENTS'),('block','AUDIT_EVENTS')]),
                 ('ALERT',[('alerts','ALERTS')]),('INCIDENT',[('incidents','INCIDENTS')]),('ACTION',[('actions','ACTIONS')])]
    unavailable=source(system='not-configured',error='SOURCE_NOT_CONFIGURED')
    rows=[Stage(stage=name,metrics=[Metric(key=k,count=None,unit=u) for k,u in metrics],status='UNAVAILABLE',
                reason_code='SOURCE_NOT_CONFIGURED',window_from=start,window_to=finish,time_basis='UNAVAILABLE',source=unavailable.model_copy()) for name,metrics in definitions]
    def set_stage(index, values, src, reason, basis):
        row=rows[index]
        row.source=src
        row.status='STALE' if src.freshness_state=='STALE' else 'HISTORICAL' if src.freshness_state=='HISTORICAL' else 'PARTIAL'
        row.reason_code=reason
        row.time_basis=basis
        for metric in row.metrics:
            metric.count=values.get(metric.key)
    if context=='EVALUATION':
        if end is not None:
            fail('EVALUATION_WINDOW_IS_RUN_DEFINED',422)
        result=evaluation_response(request,run_id) if run_id else None
        if not run_id:
            fail('EVALUATION_RUN_REQUIRED',422)
        run=result['data']
        src=run.provenance
        finish=run.completed_at or src.data_as_of or run.started_at
        if finish is None:
            fail('EVALUATION_RUN_TIME_NOT_PROVIDED')
        start=run.started_at or finish-period
        if start>=finish:
            start=finish-period
        for row in rows:
            row.source=src
            row.reason_code='EVALUATION_FUNNEL_NOT_CAPTURED'
            row.window_from=start
            row.window_to=finish
            row.time_basis='EVALUATION_RUN_OBSERVATION'
        # PASS case counts are never SQL request/incident/action counts.
    else:
        try:
            with canonical_audit.audit_read(request) as (db,meta,_):
                audit=db.execute('SELECT policy_decision FROM p16h_audit_index_v1 WHERE timestamp>=? AND timestamp<=?',(iso(start),iso(finish))).fetchall()
                src=source(meta,'P16H canonical audit')
                set_stage(0,{'audit_events':len(audit) if audit else None},src,'REQUEST_ID_NOT_PROVIDED','occurred_at')
                set_stage(2,{'allow':sum(r['policy_decision']=='ALLOW' for r in audit) if audit else None,
                             'block':sum(r['policy_decision']=='BLOCK' for r in audit) if audit else None},src,'IMPORTED_RECORDS_ONLY','occurred_at')
        except (HTTPException,sqlite3.Error) as exc:
            code=exc.detail['code'] if isinstance(exc,HTTPException) else 'CANONICAL_AUDIT_STORE_UNAVAILABLE'
            for index in [0,2]:
                rows[index].source=source(system='P16H canonical audit',error=code)
                rows[index].reason_code=code
        rows[1].reason_code='PARSER_FEATURES_NOT_PROVIDED'
        rows[1].source=source(system='P14 parser',error='PARSER_FEATURES_NOT_PROVIDED')
        rows[5].reason_code='P17_5_NOT_CONFIGURED'
        rows[5].source=source(system='P17.5 action evidence',error='P17_5_NOT_CONFIGURED')
        try:
            snapshot,error=request.app.state.p17_reader.read()
            src=source(snapshot_meta(snapshot,error),'P17.2 incidents','P17_PROJECTION')
            count=sum(start<=row.created_utc<=finish for row in snapshot.incidents)
            set_stage(4,{'incidents':count if count else None},src,'P17_CREATED_RECORDS_ONLY','created_utc')
            try:
                alerts=read_alerts(snapshot,error)
                count=sum(start<=datetime.fromisoformat(alert_key(row)[0].replace('Z','+00:00'))<=finish for row in alerts)
                set_stage(3,{'alerts':count if count else None},src.model_copy(update={'source_system':'P17 outbox'}),'OUTBOX_RECORDS_ONLY','created_utc')
            except AlertError:
                rows[3].source=source(system='P17 outbox',error='P17_ALERT_SOURCE_INVALID')
                rows[3].reason_code='P17_ALERT_SOURCE_INVALID'
        except SnapshotError as exc:
            for index in [3,4]:
                rows[index].source=source(system='P17',error=exc.code)
                rows[index].reason_code=exc.code
    return {'data':Funnel(context=context,run_id=run_id,window_from=start,window_to=finish,stages=rows),
            'meta':Meta(request_id=request.state.request_id,read_at=utc_now(),source_system='dashboard-decision-funnel',
                        freshness_state='HISTORICAL' if context=='EVALUATION' else 'PARTIAL',sources=[row.source for row in rows],
                        coverage_note='Independent counters; no cohort linkage or conversion percentages. Missing/empty unproven windows are null.'),'error':None}
