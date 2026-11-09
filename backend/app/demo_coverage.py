"""Scene definitions are design requirements, never imported observations."""
import json
from datetime import datetime, timezone
from pathlib import Path
from .evidence_models import DemoPage, DemoItem, EvidenceArtifact, Source, Meta
from .evidence_registry import now

CATALOG = json.loads(Path(__file__).with_name('demo_expected_catalog.json').read_text(encoding='utf-8'))


def legacy_mode(modes):
    mapping = {'LIVE': 'LIVE', 'OFFLINE': 'OFFLINE', 'ISOLATED': 'OFFLINE', 'HISTORICAL': 'HISTORICAL'}
    # STAGING and DESIGN_ONLY have no truthful frozen-contract representation.
    if any(mode not in mapping for mode in modes):
        return None
    values = {mapping[m] for m in modes}
    return next(iter(values)) if len(values) == 1 else 'MIXED'


def source(index, registry_sha, artifact=None):
    return {'source_system': artifact.source_system if artifact else 'OFFLINE_EVIDENCE_REGISTRY',
            'source_ref': 'sha256:' + (artifact.sha256 if artifact else registry_sha),
            'source_schema': 'portal-evidence-index-1',
            'data_as_of': next(r.data_as_of for r in index.runs if r.run_id == artifact.run_id) if artifact else None,
            'observed_at': artifact.captured_at if artifact else None, 'read_at': datetime.now(timezone.utc),
            'freshness_state': 'HISTORICAL', 'coverage_kind': 'NOT_PROVEN'}


def metadata(index, registry_sha, request_id):
    return Meta.model_validate_json(json.dumps({
        'request_id': request_id, 'read_at': now(), 'freshness_state': 'HISTORICAL',
        'sources': [Source.model_validate(source(index, registry_sha)).model_dump(mode='json')],
        'coverage_note': 'Offline import; not producer health, testcase verification, human signoff or production RBAC.'}))


def evidence_view(index, artifact, registry_sha):
    notes = [f'run_id={artifact.run_id}', f'context={next(r.context for r in index.runs if r.run_id == artifact.run_id)}',
             f'source_host={artifact.source_host}', f'scene_ids={",".join(artifact.scene_ids)}',
             f'imported_at={artifact.imported_at.isoformat()}', 'integrity=BYTE_HASH_MATCH_AT_IMPORT',
             'hash_basis=SUPPLIED_MANIFEST; not testcase PASS or human signoff',
             'source_bytes_not_served; current_source_hash_not_rechecked']
    if artifact.original_sha256:
        notes.append('original_sha256_unverified=' + artifact.original_sha256)
    return EvidenceArtifact(evidence_id=artifact.evidence_id, evidence_kind=artifact.evidence_kind,
        related_entity_type=artifact.entity.entity_type, related_entity_id=artifact.entity.entity_id,
        sha256=artifact.sha256, size_bytes=artifact.size_bytes, captured_at=artifact.captured_at,
        source_system=artifact.source_system, sanitization_state=artifact.sanitization_state,
        notes=notes, provenance=Source.model_validate(source(index, registry_sha, artifact)))


def coverage(index):
    artifacts = {a.evidence_id: a for a in index.artifacts}
    observations = {(o.run_id, o.scenario_id): o for o in index.observations}
    items = []
    for run in index.runs:
        for scene in CATALOG:
            observation = observations.get((run.run_id, scene['scenario_id']))
            reasons, valid, missing = [], [], []
            modes, observed, verdict, evaluated = ['DESIGN_ONLY'], None, 'NOT_EXECUTED', None
            if observation:
                modes, observed, verdict, evaluated = observation.execution_modes, observation.outcome, observation.verdict, observation.evaluated_at
                if not observation.evidence_refs:
                    reasons.append('NO_EVIDENCE_REFS')
                if verdict == 'PASS' and observed in ('NOT_CAPTURED', 'NOT_VERIFIED'):
                    reasons.append('SOURCE_OUTCOME_UNVERIFIED')
                supported_modes = set()
                for ref in observation.evidence_refs:
                    artifact = artifacts.get(ref)
                    if artifact is None:
                        missing.append(ref); reasons.append('EVIDENCE_REF_MISSING')
                    elif artifact.run_id != run.run_id:
                        missing.append(ref); reasons.append('EVIDENCE_REF_CROSS_RUN')
                    elif scene['scenario_id'] not in artifact.scene_ids:
                        missing.append(ref); reasons.append('EVIDENCE_SCENE_MISMATCH')
                    else:
                        valid.append(ref)
                        if artifact.sanitization_state != 'SANITIZED':
                            reasons.append('EVIDENCE_WITHHELD')
                        elif artifact.summary.outcome != observation.outcome or artifact.summary.execution_mode not in modes:
                            reasons.append('OBSERVATION_SUMMARY_MISMATCH')
                        else:
                            supported_modes.add(artifact.summary.execution_mode)
                if set(modes) - supported_modes:
                    reasons.append('MODE_EVIDENCE_INCOMPLETE')
                if reasons:
                    verdict = 'INCOMPLETE'
                reasons.append('SOURCE_REPORTED_VERDICT_NOT_INDEPENDENT_SIGNOFF')
            else:
                reasons.append('OBSERVATION_NOT_IMPORTED')
            items.append(DemoItem(**scene, mode=legacy_mode(modes), execution_modes=modes,
                observed_outcome=observed, verdict=verdict, evidence_refs=valid,
                missing_evidence_refs=missing, last_evaluated_at=evaluated, run_id=run.run_id,
                context=run.context, basis='IMPORTED_OBSERVATION' if observation else 'DESIGN_EXPECTED',
                reason_codes=sorted(set(reasons))))
    return DemoPage(runs=index.runs, items=items, observed_scene_count=len(observations))
