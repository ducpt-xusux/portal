"""Read-only P17 VNext APIs, separate from legacy P17 incident authority.

Receives bounded atomic file exports from Proxy's already-committed VNext SQLite.
Never writes to P17/Neutron/Controller, never constructs an Incident itself.
"""
from __future__ import annotations
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from fastapi import APIRouter, HTTPException, Query, Request

SCHEMA='n91-portal-p17-vnext-1'
MAX_FILE=8*1024*1024
FRESH_SECONDS=90
SAFE_ID=re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$')
FORBIDDEN=re.compile(r'(^|_)(raw_sql|raw_query|sql_text|password|passwd|private_key|secret|authorization|openrc|raw_envelope|raw_payload)($|_)',re.I)
router=APIRouter(prefix='/api/v1/p17-vnext',tags=['P17 VNext read-only'])


def _reject(code, status=503):
    raise HTTPException(status, {'code': code, 'message':'P17 VNext read-only source is unavailable or invalid.'})


def _pairs(items):
    result={}
    for key,value in items:
        if key in result:raise ValueError('DUPLICATE_KEY')
        result[key]=value
    return result


def _bounds(obj, depth=0):
    if depth>14:raise ValueError('DEPTH_EXCEEDED')
    if isinstance(obj,dict):
        if len(obj)>110:raise ValueError('OBJECT_TOO_LARGE')
        for key,value in obj.items():
            if FORBIDDEN.search(key):raise ValueError('SECRET_FIELD_FORBIDDEN')
            _bounds(value,depth+1)
    elif isinstance(obj,list):
        if len(obj)>400:raise ValueError('LIST_TOO_LARGE')
        for value in obj:_bounds(value,depth+1)
    elif isinstance(obj,str) and len(obj)>20000:
        raise ValueError('STRING_TOO_LARGE')


def load_snapshot(path):
    if not path: _reject('VNEXT_SOURCE_NOT_CONFIGURED')
    p=Path(path)
    try:
        if not p.is_absolute() or p.is_symlink() or not p.is_file() or p.stat().st_size>MAX_FILE:
            _reject('VNEXT_SOURCE_NOT_READABLE')
        with p.open('rb') as f:
            raw=f.read(MAX_FILE+1)
        if len(raw)>MAX_FILE:raise ValueError('SNAPSHOT_TOO_LARGE')
        value=json.loads(raw.decode('utf-8'),object_pairs_hook=_pairs)
        _bounds(value)
        if not isinstance(value,dict) or value.get('schema_version')!=SCHEMA:
            raise ValueError('VERSION_MISMATCH')
        for key in ('cases','events'):
            if not isinstance(value.get(key),list):raise ValueError('INVALID_COLLECTION')
        if (value.get('profile') != 'n91-vnext-source-evidence-v1' or
            value.get('source_mode') != 'COMMITTED_SQLITE_READONLY_EXPORT' or
            value.get('detector_manifest',{}).get('profile') != value.get('profile') or
            len(value.get('detector_manifest',{}).get('detectors',[])) != 22):
            raise ValueError('VNEXT_PROFILE_OR_MANIFEST_INVALID')
        if len(value['cases'])>50 or len(value['events'])>100:
            raise ValueError('UNBOUNDED_COLLECTION')
        if not isinstance(value.get('checkpoint'),int) or value['checkpoint']<0:
            raise ValueError('BAD_CHECKPOINT')
        if value.get('security_boundary')!='REVIEW_ONLY_NO_OPENSTACK_ACTION':
            raise ValueError('SECURITY_BOUNDARY_INVALID')
        for key in ('source_system', 'stream_id', 'coverage'):
            if not isinstance(value.get(key), str) or not value[key]:
                raise ValueError('SOURCE_METADATA_INVALID')
        for key in ('legacy_incident_count', 'event_total', 'case_total'):
            if type(value.get(key)) is not int or value[key] < 0:
                raise ValueError('SOURCE_TOTAL_INVALID')
        if value['case_total'] < len(value['cases']) or value['event_total'] < len(value['events']):
            raise ValueError('SOURCE_TOTAL_INVALID')
        timestamp=datetime.fromisoformat(value['generated_at'].replace('Z','+00:00'))
        if timestamp.tzinfo is None:raise ValueError('NAIVE_TIMESTAMP')
        case_ids = set()
        for case in value['cases']:
            if (not isinstance(case,dict) or not isinstance(case.get('case_id'),str) or
                not SAFE_ID.fullmatch(case['case_id']) or
                case.get('isolation_authorized') is not False or case.get('response')!='NO_ACTION' or
                not isinstance(case.get('evidence'),list) or not isinstance(case.get('signals'),list)):
                raise ValueError('CASE_SCHEMA_INVALID')
            if case['case_id'] in case_ids or len(case['evidence']) > 100:
                raise ValueError('CASE_IDENTITY_INVALID')
            case_ids.add(case['case_id'])
            for member in case['evidence']:
                if (not isinstance(member, dict) or not isinstance(member.get('trace'), dict) or
                    not SAFE_ID.fullmatch(str(member.get('event_id', ''))) or
                    member['trace'].get('event_id') != member['event_id'] or
                    member['trace'].get('p17', {}).get('action_authorized') is not False):
                    raise ValueError('MEMBER_SCHEMA_INVALID')
        event_ids = set()
        for event in value['events']:
            if (not isinstance(event,dict) or not isinstance(event.get('trace'),dict) or
                not SAFE_ID.fullmatch(str(event.get('event_id',''))) or
                event['trace'].get('event_id')!=event['event_id'] or
                event['trace'].get('p17',{}).get('action_authorized') is not False):
                raise ValueError('EVENT_SCHEMA_INVALID')
            if event['event_id'] in event_ids:
                raise ValueError('EVENT_IDENTITY_INVALID')
            event_ids.add(event['event_id'])
        return value
    except (OSError,ValueError,TypeError,KeyError,UnicodeError,OverflowError,AttributeError):
        _reject('VNEXT_SOURCE_INVALID')


def meta(request,raw):
    stamp=datetime.fromisoformat(raw['generated_at'].replace('Z','+00:00'))
    age=(datetime.now(timezone.utc)-stamp).total_seconds()
    if age< -5:state='CLOCK_SKEW'
    else:state='FRESH' if age<=FRESH_SECONDS else 'STALE'
    return {
        'request_id':getattr(request.state,'request_id',None),
        'source_system':raw['source_system'],
        'source_schema':SCHEMA,'source_mode':'READONLY_EXPORT',
        'data_as_of':raw['generated_at'],'read_at':datetime.now(timezone.utc).isoformat(),
        'last_success':raw['generated_at'], 'last_attempt':raw.get('collection_started_at'),
        'collection_mode':'COMMITTED_SQLITE_EXPORT', 'access_mode':'LOCAL_REMOTE_READONLY',
        'freshness_state':state,'age_seconds':round(age,2),
        'coverage_state':'PARTIAL','coverage_complete':False,
        'coverage_note':raw['coverage'],'stream_id':raw['stream_id'],
        'last_committed_sequence':raw['checkpoint'],
        'review_only':True,'source_action_authority':False,
        'p17_legacy_incident_authority_unchanged':True,
    }


def envelope(request,raw,data):
    return {'data':data,'meta':meta(request,raw),'error':None}


def snapshot(request):
    return load_snapshot(request.app.state.settings.p17_vnext_snapshot_path)


def case_summary(c):
    return {k:c.get(k) for k in ('case_id','episode_id','stream_id','source_ip','severity',
        'peak_p15','evidence_count','signals','status','isolation_authorized',
        'response','created_at','updated_at','evidence_export_complete')}


@router.get('/status')
def status(request:Request):
    data=snapshot(request)
    return envelope(request,data,{
        'profile':data['profile'],'checkpoint':data['checkpoint'],
        'legacy_incident_count':data['legacy_incident_count'],
        'vnext_event_total':data['event_total'],
        'vnext_case_total':data['case_total'],
        'exported_events':len(data['events']),'exported_cases':len(data['cases']),
        'response_policy':'NO_ACTION',
    })


@router.get('/cases')
def cases(request:Request,limit:int=Query(50,ge=1,le=50),source_ip:str|None=None,detector:str|None=None):
    raw=snapshot(request)
    result=[case_summary(c) for c in raw['cases']
            if (not source_ip or c.get('source_ip')==source_ip)
            and (not detector or detector in c.get('signals',[]))]
    return envelope(request,raw,{'cases':result[:limit],'shown':len(result[:limit]),'source_total':raw['case_total']})


@router.get('/cases/{case_id}')
def case_detail(request:Request,case_id:str):
    if not SAFE_ID.fullmatch(case_id):_reject('VNEXT_ID_INVALID',422)
    raw=snapshot(request)
    found=next((c for c in raw['cases'] if c.get('case_id')==case_id),None)
    if found is None:_reject('VNEXT_CASE_NOT_IN_BOUNDED_EXPORT',404)
    return envelope(request,raw,{**found,'detector_manifest':raw.get('detector_manifest')})


@router.get('/events')
def events(request:Request,limit:int=Query(100,ge=1,le=100),source_ip:str|None=None):
    raw=snapshot(request)
    rows=raw['events']
    if source_ip:rows=[r for r in rows if r.get('trace',{}).get('source_ip')==source_ip]
    rows=rows[:limit]
    return envelope(request,raw,{'events':[{k:r.get(k) for k in ('event_id','stream_id','request_id',
        'stream_sequence','event_class','blocked','risk_status','risk_score','qualification')} |
        {'source_ip':r['trace'].get('source_ip'),
         'event_time':r['trace'].get('event_time'),
         'matched_rules':r['trace'].get('p14',{}).get('matched_rules',[]),
         'detectors':r['trace'].get('p17',{}).get('matched_signals',[]),
         'case_id':r['trace'].get('p17',{}).get('case_id')}
        for r in rows], 'source_total':raw['event_total']})


@router.get('/events/{event_id}')
def event_detail(request:Request,event_id:str):
    if not SAFE_ID.fullmatch(event_id):_reject('VNEXT_ID_INVALID',422)
    raw=snapshot(request)
    found=next((e for e in raw['events'] if e.get('event_id')==event_id),None)
    if found is None:_reject('VNEXT_EVENT_NOT_IN_BOUNDED_EXPORT',404)
    return envelope(request,raw,{**found,'detector_manifest':raw.get('detector_manifest')})
