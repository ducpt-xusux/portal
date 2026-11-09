"""Frozen views plus additive context/precision panels. No independent run registry."""
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
from fastapi import HTTPException
from ..dashboard_funnel import EvaluationRun, read_runs
from ..evidence_registry import EvidenceConfig, EvidenceError, EvidenceRegistry
from .sources import SourceError, evaluation_source, system_source
from .views import FROZEN_MODELS
from .panels import EvaluationPanel, SystemPanel


def now():
    return datetime.now(timezone.utc).isoformat().replace('+00:00','Z')


class EvaluationSystemService:
    def __init__(self, *, evaluations=None, system=None, evidence=None, run_reader=read_runs):
        self.evaluations = evaluations if evaluations is not None else evaluation_source()
        self.system = system if system is not None else system_source()
        self.evidence = evidence if evidence is not None else EvidenceRegistry(EvidenceConfig())
        self.run_reader = run_reader
        self.catalog = json.loads((Path(__file__).parent/'design_catalog.json').read_text(encoding='utf-8'))

    def provenance(self, sha, scope=None):
        return dict(source_system=scope.source_system if scope else 'N91_EVALUATION_SYSTEM',
            source_ref='sha256:'+sha, source_schema='n91-evaluation-system-1',
            data_as_of=scope.data_as_of.isoformat() if scope else None,
            observed_at=scope.observed_at.isoformat() if scope else None, read_at=now(),
            freshness_state='HISTORICAL', age_seconds=None, error_code=None, coverage_kind='CACHE_ONLY')

    def links(self, rows):
        if not rows:
            return
        try:
            index, _ = self.evidence.read()
        except EvidenceError as exc:
            raise SourceError(exc.code) from None
        runs = {r.run_id:r for r in index.runs}
        artifacts = {a.evidence_id:a for a in index.artifacts}
        for row in rows:
            scope = row.scope
            run = runs.get(scope.run_id)
            if run is None or run.context != scope.context:
                raise SourceError('EVALUATION_SYSTEM_EVIDENCE_RUN_MISMATCH')
            for ref in row.evidence_refs:
                artifact = artifacts.get(ref)
                if artifact is None or artifact.run_id != scope.run_id:
                    raise SourceError('EVALUATION_SYSTEM_EVIDENCE_LINK_MISMATCH')
                if artifact.sanitization_state != 'SANITIZED' or artifact.summary is None:
                    raise SourceError('EVALUATION_SYSTEM_EVIDENCE_WITHHELD')
                if artifact.summary.execution_mode != scope.execution_mode:
                    raise SourceError('EVALUATION_SYSTEM_EVIDENCE_MODE_MISMATCH')
                # RUN artifacts attest the run. Other entities require an explicit ID join.
                allowed = set(getattr(row,'event_refs',[])+getattr(row,'incident_refs',[]))
                allowed.update(filter(None,[getattr(row,'restore_run_id',None)]))
                entity = artifact.entity
                if (entity.entity_type == 'RUN' and entity.entity_id != scope.run_id) or (entity.entity_type != 'RUN' and entity.entity_id not in allowed):
                    raise SourceError('EVALUATION_SYSTEM_EVIDENCE_ENTITY_MISMATCH')
            linked=[artifacts[ref] for ref in row.evidence_refs]
            if getattr(row,'verdict',None)=='PASS' and hasattr(row,'case_id'):
                if not any(a.entity.entity_type=='EVENT' and a.summary.outcome==row.observed_action for a in linked):
                    raise SourceError('EVALUATION_CASE_PASS_EVIDENCE_MISMATCH')
            if getattr(row,'verdict',None)=='PASS' and hasattr(row,'scenario_id'):
                if not any(a.entity.entity_type in {'EVENT','INCIDENT'} for a in linked):
                    raise SourceError('EVALUATION_CORRELATION_PASS_EVIDENCE_MISMATCH')
            if getattr(row,'verification_state',None)=='PASS':
                if not any(a.entity.entity_type=='RESTORE' and a.summary.outcome in {'VERIFIED','RESTORED'} for a in linked):
                    raise SourceError('EVALUATION_RESTORE_PASS_EVIDENCE_MISMATCH')

    def evaluation(self, request, run_id):
        # Use the existing registry and DTO rather than redeclaring /runs.
        try:
            runs, _ = self.run_reader(request)
        except HTTPException as exc:
            raise SourceError(exc.detail.get('code','EVALUATION_RUN_SOURCE_UNAVAILABLE'),exc.status_code) from None
        run = next((EvaluationRun.model_validate(r) for r in runs if r.run_id == run_id), None)
        if run is None:
            raise SourceError('EVALUATION_RUN_NOT_FOUND',404)
        document, sha = self.evaluations.read()
        if document.run_hashes.get(run_id) != run.source_sha256:
            raise SourceError('EVALUATION_RUN_HASH_MISMATCH')
        cases = [row for row in document.cases if row.scope.run_id == run_id]
        correlations = [row for row in document.correlations if row.scope.run_id == run_id]
        rows = cases + correlations
        if (run.dataset=='P17_CORR_13' and cases) or (run.dataset=='P14_P17_60' and correlations):
            raise SourceError('EVALUATION_DATASET_OBSERVATION_MISMATCH')
        if len(rows)>run.case_count or (run.status=='NOT_EXECUTED' and any(r.verdict!='NOT_EXECUTED' for r in rows)):
            raise SourceError('EVALUATION_SUMMARY_OBSERVATION_MISMATCH')
        counts = Counter(r.verdict for r in rows)
        summary_counts = run.counts.model_dump(by_alias=True)
        if any(count > summary_counts[key.lower()] for key,count in counts.items()):
            raise SourceError('EVALUATION_SUMMARY_COUNTS_MISMATCH')
        for row in rows:
            if ((run.started_at and row.scope.observed_at < run.started_at) or
                (run.completed_at and row.scope.observed_at > run.completed_at)):
                raise SourceError('EVALUATION_OBSERVATION_TIME_MISMATCH')
        self.links(rows)
        case_design = {r['case_id']:r for r in self.catalog['cases']}
        corr_design = {r['scenario_id']:r for r in self.catalog['correlations']}
        for row in cases:
            if row.partition != case_design[row.case_id]['partition']:
                raise SourceError('EVALUATION_PARTITION_MISMATCH')
        for row in correlations:
            if row.scenario_id not in corr_design:
                raise SourceError('EVALUATION_SCENARIO_NOT_IN_CATALOG')
            if row.verdict == 'PASS' and row.observed_incident != corr_design[row.scenario_id]['expected_incident']:
                raise SourceError('EVALUATION_CORRELATION_FALSE_PASS')
        return run, cases, correlations, sha

    def cases(self, request, run_id):
        run, rows, _, sha = self.evaluation(request, run_id)
        if run.dataset=='P17_CORR_13':
            raise SourceError('EVALUATION_DATASET_CASES_NOT_APPLICABLE',422)
        observed = {r.case_id:r for r in rows}
        result=[]
        for expected in self.catalog['cases']:
            row = observed.get(expected['case_id'])
            result.append(dict(case_id=expected['case_id'], run_id=run_id, fixture_id=expected['case_id'],
                partition=expected['partition'], scenario=expected['scenario'], execution_mode=expected['partition'],
                input_excerpt=None, input_visibility='WITHHELD', expected_action=expected['expected_old'],
                expected_rule_ids=expected['expected_rule_ids'], observed_action=row.observed_action if row else None,
                observed_rule_ids=row.observed_rule_ids if row else [], verdict=row.verdict if row else 'NOT_EXECUTED' if run.status=='NOT_EXECUTED' else 'UNKNOWN',
                label_status=row.label_status if row else 'UNREVIEWED', event_refs=row.event_refs if row else [],
                incident_refs=row.incident_refs if row else [], evidence_refs=row.evidence_refs if row else [],
                review_notes=['EXPECTED_OLD_DESIGN_REFERENCE','CATALOG_NOT_RUN_UNCHANGED'] + ([] if row else ['NO_RUN_OBSERVATION']),
                provenance=self.provenance(sha,row.scope if row else None)))
        return [FROZEN_MODELS['cases'].model_validate(r).model_dump(mode='json') for r in result], sha

    def correlations(self, request, run_id):
        run, _, rows, sha = self.evaluation(request, run_id)
        if run.dataset=='P14_P17_60':
            raise SourceError('EVALUATION_DATASET_CORRELATIONS_NOT_APPLICABLE',422)
        observed = {r.scenario_id:r for r in rows}
        result=[]
        for expected in self.catalog['correlations']:
            row=observed.get(expected['scenario_id'])
            result.append(dict(scenario_id=expected['scenario_id'],run_id=run_id,signal_rule=expected['signal_rule'],
                input_event_count=row.input_event_count if row else expected['input_event_count'],expected_incident=expected['expected_incident'],
                observed_incident=row.observed_incident if row else None,expected_reason='DESIGN_REFERENCE',observed_reason=None,
                verdict=row.verdict if row else 'NOT_EXECUTED' if run.status=='NOT_EXECUTED' else 'UNKNOWN',execution_mode='HISTORICAL',
                related_event_refs=row.event_refs if row else [],incident_refs=row.incident_refs if row else [],
                source_label='OBSERVED' if row and row.observed_incident is not None else 'CANDIDATE_REFERENCE',
                provenance=self.provenance(sha,row.scope if row else None)))
        return [FROZEN_MODELS['correlations'].model_validate(r).model_dump(mode='json') for r in result],sha

    def evaluation_panel(self, request, run_id):
        run,cases,correlations,sha=self.evaluation(request,run_id)
        expected=Counter(r['partition'] for r in self.catalog['cases'])
        observed=Counter(r.partition for r in cases if r.observed_action is not None)
        payload=dict(schema_version='n91-evaluation-panel-1',run=run.model_dump(mode='json',by_alias=True),
            expected_partitions=dict(expected),observed_partitions={k:observed[k] for k in expected},
            expected_correlations=13,observed_correlations=sum(r.observed_incident is not None for r in correlations),
            catalog_basis='DESIGN_ONLY',catalog_flag='NOT_RUN',
            cases=[r.model_dump(mode='json') for r in cases],correlations=[r.model_dump(mode='json') for r in correlations])
        return EvaluationPanel.model_validate_json(json.dumps(payload)).model_dump(mode='json',by_alias=True),sha

    def system_rows(self, kind):
        document,sha=self.system.read()
        rows=getattr(document,kind)
        if kind=='p19':
            rows=[rows] if rows else []
        if not rows:
            raise SourceError('EVALUATION_SYSTEM_SECTION_UNAVAILABLE')
        self.links(rows)
        return rows,sha

    def recovery_detail(self,row):
        timing = row.clock_basis == 'SAME_CLOCK' and row.fault_utc is not None and row.recovery_query_verified_utc is not None
        rto=(row.recovery_query_verified_utc-row.fault_utc).total_seconds() if timing else None
        return dict(**row.model_dump(mode='json'),lab_rto_seconds=rto,
            lab_rto_reason=None if timing else 'TIMING_NOT_COMPARABLE_OR_MISSING',
            metric_semantics='LAB_BACKUP_GAP_AND_FAULT_TO_VERIFIED_QUERY_NOT_PRODUCTION',unit='seconds',
            lost_marker_count=len(row.lost_marker_ids) if row.marker_capture_complete else None,
            current_verification='CURRENT_NOT_VERIFIED' if row.observation_kind=='CURRENT_READBACK' and row.verification_state in {'UNKNOWN','NOT_VERIFIED'} else 'SCOPED_OBSERVATION',
            production_measurement='NOT_MEASURED')

    def system_panel(self,kind):
        rows,sha=self.system_rows(kind)
        data=[self.recovery_detail(r) if kind=='recoveries' else r.model_dump(mode='json') for r in rows]
        payload=dict(schema_version='n91-system-panel-1',kind=kind,items=data,
            scope_note='Imported frozen observations; source mode and context remain per item.')
        return SystemPanel.model_validate_json(json.dumps(payload)).model_dump(mode='json'),sha

    def frozen_system(self,kind):
        rows,sha=self.system_rows(kind)
        result=[]
        for r in rows:
            p=self.provenance(sha,r.scope)
            if kind=='backups':
                item={**r.model_dump(mode='json',exclude={'scope'}),'storage_location_status':'WITHHELD','provenance':p}
            elif kind=='recoveries':
                item=dict(restore_run_id=r.restore_run_id,backup_id=r.backup_id,target_server_id=None,target_name=r.target_name,
                    started_at=r.fault_utc.isoformat() if r.fault_utc else None,
                    completed_at=r.recovery_query_verified_utc.isoformat() if r.recovery_query_verified_utc else None,
                    mariadb_status=r.mariadb_status,cluster_membership=r.cluster_membership,schema_verified=r.schema_verified,
                    row_count_verified=r.row_count_verified,content_checksum_verified=r.content_checksum_verified,
                    rpo_seconds=None,rto_seconds=None,verification_state=r.verification_state,run_kind='HISTORICAL',
                    evidence_refs=r.evidence_refs,limitations=['LAB_NOT_PRODUCTION','PRECISE_METRICS_IN_ADDITIVE_RECOVERY_PANEL'],provenance=p)
            elif kind=='resilience':
                item=dict(run_id=r.resilience_id,gate=r.gate,scenario=r.scenario,run_kind='HISTORICAL',
                    started_at=None,finished_at=r.scope.observed_at.isoformat(),expected_outcome=r.expected_outcome,
                    observed_outcome=r.observed_outcome,verdict=r.verdict,affected_workload_ids=r.affected_workload_ids,
                    evidence_refs=r.evidence_refs,limitations=['FROZEN_SCOPE_ONLY'],provenance=p)
            elif kind=='tls':
                item={**r.model_dump(mode='json',exclude={'scope','handshake_retry_limitation'}),
                    'observed_at':r.scope.observed_at.isoformat(),'provenance':p}
            elif kind=='p19':
                item=r.model_dump(mode='json',exclude={'scope','evidence_refs','authority'})
                item.update(evidence_ref=r.evidence_refs[0] if r.evidence_refs else None,updated_at=r.scope.observed_at.isoformat())
            else:
                raise SourceError('EVALUATION_SYSTEM_SECTION_UNAVAILABLE')
            result.append(item)
        return [FROZEN_MODELS[kind].model_validate(r).model_dump(mode='json') for r in result],sha
