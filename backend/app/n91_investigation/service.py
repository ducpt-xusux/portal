"""Investigation projections. No SQL parser, risk calculator or response executor."""
import base64
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import secrets

from ..canonical_contract import CanonicalEventView
from ..p17_snapshot import IncidentRow
from .models import (
    ActionView, ControllerBundle, CurrentObservation, DecisionStage, DecisionTrace,
    DurationMetric, Mapping, PolicyCatalog, PolicyRuleDetail, RuleHit, SgLifecycleView, SourceFreshness,
    SourceStamp, StageEvidence, STAGES, TimelineItem, TimelineView, TraceFact,
)
from .sources import SourceError, bounded, validate


def utc():
    return datetime.now(timezone.utc)


def dump(value):
    return value.model_dump(mode='json')


def check_mode(actual, configured):
    # Test and evaluation stores must never feed LIVE. TEST is also isolated from
    # HISTORICAL and other modes; mode changes require a different service instance.
    if actual in {'TEST', 'EVALUATION'} or configured in {'TEST', 'EVALUATION'}:
        if actual != configured:
            raise SourceError('INVESTIGATION_MODE_MISMATCH')


def freshness(source, now):
    return SourceFreshness(source_system=source.source_system,
        source_ref=source.source_ref, source_schema=source.source_schema,
        observed_at=source.observed_at, data_as_of=source.observed_at, read_at=now,
        freshness_state=source.freshness_state, coverage_kind='NOT_PROVEN')


def missing_stage(stage):
    return DecisionStage(stage_id=stage, stage=stage, status='UNAVAILABLE', outcome=None,
        reason_codes=['SOURCE_NOT_PROVIDED'], source_system=stage,
        verification='UNAVAILABLE')


def fact(name, value, ref, at=None):
    summary = None if value is None else (str(value) if not isinstance(value, (dict, list)) else json.dumps(value, ensure_ascii=False))
    if summary is not None and len(summary) > 2000:
        summary = summary[:1970] + ' [TRUNCATED_SUMMARY]'
    return TraceFact(name=name, value_summary=summary,
        status='UNAVAILABLE' if value is None else 'PRESENT', source_ref=ref,
        observed_at=at, verification='UNAVAILABLE' if value is None else 'SOURCE_REPORTED')


def sourced_stage(name, source, outcome, facts, at=None, codes=None):
    # Historical/imported evidence does not become a current evaluated decision.
    return DecisionStage(stage_id=name, stage=name,
        status='EVALUATED' if source.execution_mode == 'LIVE' and source.freshness_state == 'FRESH' else 'HISTORICAL',
        outcome=outcome, facts=facts, reason_codes=codes or [],
        source_system=source.source_system, source_ref=source.source_ref,
        evaluated_at=at, verification='SOURCE_REPORTED')


def durations(cycle):
    pairs = (
        ('detection_response', 'DETECTED', 'QUARANTINE_APPLIED'),
        ('trigger_to_quarantine', 'TRIGGER_ACCEPTED', 'QUARANTINE_APPLIED'),
        ('quarantine_duration', 'QUARANTINE_APPLIED', 'RESTORE_SUCCESS'),
        ('ingestion_latency', 'REQUEST_RECEIVED', 'AUDIT_STORED'),
    )
    result = []
    for metric, start_kind, end_kind in pairs:
        starts = [m for m in cycle.clock_marks if m.kind == start_kind]
        ends = [m for m in cycle.clock_marks if m.kind == end_kind]
        reason, seconds, clock, basis, refs = None, None, None, None, []
        if not starts or not ends:
            reason = 'MISSING_CLOCK_MARK'
        elif len(starts) != 1 or len(ends) != 1:
            reason = 'AMBIGUOUS_CLOCK_MARK'
        else:
            start, end = starts[0], ends[0]
            refs = [start.source_ref, end.source_ref]
            if (start.incident_id, start.cycle_id) != (end.incident_id, end.cycle_id):
                reason = 'INCIDENT_CYCLE_MISMATCH'
            elif start.clock_id != end.clock_id or start.time_basis != end.time_basis:
                reason = 'CLOCK_TIME_BASIS_MISMATCH'
            elif end.timestamp < start.timestamp:
                reason = 'NEGATIVE_DURATION'
            else:
                seconds = (end.timestamp - start.timestamp).total_seconds()
                clock, basis = start.clock_id, start.time_basis
        result.append(DurationMetric(metric=metric, seconds=seconds, start_kind=start_kind,
            end_kind=end_kind, incident_id=cycle.incident_id, cycle_id=cycle.cycle_id,
            clock_id=clock, time_basis=basis, source_refs=refs, unavailable_reason=reason))
    return result


@dataclass
class InvestigationService:
    mode: str = 'LIVE'
    policy_reader: object | None = None
    controller_reader: object | None = None
    event_loader: object | None = None
    incident_loader: object | None = None
    stage_loader: object | None = None
    neutron_loader: object | None = None
    clock: object = utc
    _cursor_key: bytes = field(default_factory=lambda: secrets.token_bytes(32), repr=False)

    def __post_init__(self):
        if self.mode not in {'LIVE', 'TEST', 'EVALUATION', 'ISOLATED', 'STAGING', 'HISTORICAL', 'DESIGN_ONLY'}:
            raise ValueError('Unsupported investigation mode')

    def policy(self):
        if self.policy_reader is None:
            raise SourceError('POLICY_ACTIVE_SOURCE_UNAVAILABLE')
        snapshot, sha = self.policy_reader.read()
        check_mode(snapshot.source.execution_mode, self.mode)
        return snapshot, sha

    def policy_catalog(self):
        snapshot, sha = self.policy()
        catalog = PolicyCatalog(policy_version=snapshot.policy_version, sha256=sha,
            captured_at=snapshot.source.observed_at,
            risk_algorithm_version=snapshot.risk_algorithm_version,
            rules=[RuleHit(rule_id=r.rule_id, category=r.category,
                effect='UNKNOWN' if not r.enabled else 'MONITOR' if r.mode == 'monitor' else r.action,
                explanation=r.description, policy_version=snapshot.policy_version,
                source_ref=snapshot.source.source_ref) for r in snapshot.rules])
        return catalog, snapshot.source

    def rule_detail(self, rule_id):
        snapshot, sha = self.policy()
        rule = next((r for r in snapshot.rules if r.rule_id == rule_id), None)
        if rule is None:
            raise SourceError('POLICY_RULE_NOT_FOUND', 404)
        return PolicyRuleDetail(**dump(rule), policy_version=snapshot.policy_version,
            policy_sha256=sha, source_ref=snapshot.source.source_ref,
            captured_at=snapshot.source.observed_at), snapshot.source

    def event(self, request, event_id, stream_id):
        if self.event_loader is None:
            raise SourceError('CANONICAL_EVENT_SOURCE_UNAVAILABLE')
        raw = self.event_loader(request, event_id, stream_id)
        event = validate(CanonicalEventView, raw)
        if event.event_id != event_id or (stream_id is not None and event.stream_id != stream_id):
            raise SourceError('CANONICAL_IDENTITY_MISMATCH')
        if not event.stream_id:
            raise SourceError('CANONICAL_STREAM_REQUIRED', 409)
        mode = event.source_provenance.context
        check_mode(mode or 'HISTORICAL', self.mode)
        # Current canonical contract supports offline imports, never asserts LIVE.
        source = SourceStamp(source_system='P16H', source_ref=event.source_provenance.source_ref,
            source_schema=event.source_provenance.source_schema,
            execution_mode=mode if mode in {'TEST', 'EVALUATION'} else 'HISTORICAL',
            observed_at=event.occurred_at, freshness_state='HISTORICAL')
        return event, source

    def incident(self, request, incident_id):
        if self.incident_loader is None:
            raise SourceError('P17_INCIDENT_SOURCE_UNAVAILABLE')
        raw = self.incident_loader(request, incident_id)
        if not isinstance(raw, dict) or set(raw) - set(IncidentRow.model_fields):
            raise SourceError('P17_INCIDENT_SCHEMA_UNSUPPORTED')
        row = validate(IncidentRow, raw)
        if row.incident_id != incident_id:
            raise SourceError('P17_INCIDENT_IDENTITY_MISMATCH')
        return row

    def stages(self, request, *, event=None, incident_id=None):
        if self.stage_loader is None:
            return {}
        raw = self.stage_loader(request, event, incident_id)
        if not isinstance(raw, list) or len(raw) > 7:
            raise SourceError('TRACE_STAGE_SCHEMA_UNSUPPORTED')
        result = {}
        for item in raw:
            evidence = validate(StageEvidence, item)
            check_mode(evidence.source.execution_mode, self.mode)
            if event is not None:
                if (evidence.stream_id, evidence.event_id) != (event.stream_id, event.event_id):
                    raise SourceError('TRACE_STAGE_IDENTITY_MISMATCH')
            elif evidence.incident_id != incident_id:
                raise SourceError('TRACE_STAGE_IDENTITY_MISMATCH')
            stage = evidence.stage
            if stage.source_ref != evidence.source.source_ref:
                raise SourceError('TRACE_STAGE_SOURCE_MISMATCH')
            if stage.stage in result:
                raise SourceError('TRACE_STAGE_DUPLICATE')
            # Adapter input cannot grant VERIFIED_SOURCE simply by declaring it.
            data = dump(stage)
            data['verification'] = 'UNAVAILABLE' if stage.status == 'UNAVAILABLE' else 'SOURCE_REPORTED'
            if evidence.source.execution_mode != 'LIVE' and stage.status == 'EVALUATED':
                data['status'] = 'HISTORICAL'
            for f in data['facts']:
                if f['verification'] == 'VERIFIED_SOURCE':
                    f['verification'] = 'SOURCE_REPORTED'
            for reason in data['reasons']:
                if reason['verification'] == 'VERIFIED_SOURCE':
                    reason['verification'] = 'UNAVAILABLE'
            result[stage.stage] = DecisionStage.model_validate(data)
        return result

    def event_trace(self, request, event_id, stream_id):
        event, source = self.event(request, event_id, stream_id)
        ref, at = source.source_ref, event.occurred_at
        stages = {name: missing_stage(name) for name in STAGES}
        stages['P14_POLICY'] = sourced_stage('P14_POLICY', source, event.decision, [
            fact('decision_basis', event.decision_basis, ref, at),
            fact('effective_action', event.effective_action, ref, at),
            fact('runtime_mode', event.runtime_mode, ref, at),
            fact('matched_rules', event.matched_rules, ref, at),
            fact('blocking_rules', event.blocking_rules, ref, at),
            fact('monitor_rules', event.monitor_rules, ref, at),
            fact('policy_version', event.policy_version, ref, at)], at,
            ['CONTEXT_DENY'] if 'CTX-006' in event.blocking_rules else [])
        risk_ok = event.risk.status == 'OK'
        if event.risk.status is not None:
            stages['P15_RISK'] = sourced_stage('P15_RISK', source, event.risk.status, [
                fact('risk_status', event.risk.status, ref, at),
                fact('risk_score', event.risk.score if risk_ok else None, ref, at),
                fact('severity', event.risk.severity if risk_ok else None, ref, at),
                fact('score_breakdown', [dump(x) for x in event.score_breakdown] if risk_ok and event.score_breakdown is not None else None, ref, at)], at)
        stages['P16H_AUDIT'] = sourced_stage('P16H_AUDIT', source, 'RECORDED', [
            fact('stream_id', event.stream_id, ref, at), fact('event_id', event.event_id, ref, at),
            fact('request_id', event.request_id, ref, at), fact('coverage_kind', event.source_provenance.coverage_kind, ref, at)], at)
        emitted = self.stages(request, event=event)
        # Canonical facts own these stages; extensions cannot contradict decision/risk.
        for name, stage in emitted.items():
            if name in {'SQL_PARSE', 'P17_DETECTION', 'P17_DECISION', 'P17_5_RESPONSE'}:
                stages[name] = stage
        key = hashlib.sha256(f'{event.stream_id}\0{event.event_id}'.encode()).hexdigest()[:24]
        trace = DecisionTrace(trace_id='trace:' + key, event_id=event.event_id,
            trace_kind='OFFLINE_CASE', stages=[stages[name] for name in STAGES],
            overall_outcome=event.decision, link_quality='PARTIAL', evidence_refs=[ref],
            limitations=['Canonical imported sample; no inferred P17 membership. Missing stage does not mean NOT_TRIGGERED.',
                         'CTX-006 denotes context denial; it alone does not establish SQL injection.'],
            provenance=freshness(source, self.clock()))
        return trace, source

    def bundle(self):
        if self.controller_reader is None:
            raise SourceError('CONTROLLER_EVIDENCE_UNAVAILABLE')
        bundle = self.controller_reader.read()
        if not isinstance(bundle, ControllerBundle):
            bundle = validate(ControllerBundle, bundle)
        check_mode(bundle.source.execution_mode, self.mode)
        return bundle

    def current(self, request, cycle):
        if self.neutron_loader is None:
            return None, 'NEUTRON_CURRENT_UNAVAILABLE'
        try:
            raw = self.neutron_loader(request, cycle)
            observation = validate(CurrentObservation, raw)
            # TEST current observation is allowed only in a TEST service.
            check_mode(observation.source.execution_mode, self.mode)
            if observation.source.execution_mode not in ({'TEST'} if self.mode == 'TEST' else {'EVALUATION'} if self.mode == 'EVALUATION' else {'LIVE'}):
                return None, 'NEUTRON_CURRENT_NOT_LIVE'
            if observation.source.freshness_state != 'FRESH' or observation.observed_at > self.clock() or observation.expires_at <= self.clock() or observation.expires_at <= observation.observed_at or observation.expires_at - observation.observed_at > timedelta(seconds=300):
                return None, 'NEUTRON_CURRENT_STALE'
            if (observation.project_id, observation.port_id, observation.server_id) != (
                cycle.project_id, cycle.containment.port_id, cycle.containment.vm_id):
                return None, 'NEUTRON_IDENTITY_MISMATCH'
            if cycle.containment.source_ip is not None:
                addresses = (observation.fixed_ips or []) + (observation.floating_ips or [])
                if not addresses:
                    return None, 'NEUTRON_SOURCE_IP_UNAVAILABLE'
                if cycle.containment.source_ip not in addresses:
                    return None, 'NEUTRON_SOURCE_IP_MISMATCH'
            return observation, None
        except SourceError as exc:
            return None, exc.code
        except Exception:
            return None, 'NEUTRON_CURRENT_UNAVAILABLE'

    def cycle_view(self, request, cycle):
        observation, reason = self.current(request, cycle)
        phases = {s.phase: s for s in cycle.snapshots}
        warnings = ['Controller action state is historical/source-reported; P17 flags are unchanged.']
        mapping = Mapping(verified=False, project_id=cycle.project_id, port_id=cycle.containment.port_id,
            server_id=cycle.containment.vm_id, verification_state='UNAVAILABLE', source_system='OPENSTACK_SNAPSHOT',
            reason='HISTORICAL_TARGET_FROM_CONTROLLER')
        response = 'UNKNOWN'
        if observation:
            mapping = Mapping(verified=True, project_id=observation.project_id, port_id=observation.port_id,
                server_id=observation.server_id, observed_at=observation.observed_at,
                expires_at=observation.expires_at, verification_state='VERIFIED', source_system='NEUTRON_LIVE')
            groups = set(observation.security_group_ids)
            if cycle.containment.quarantine_sg and groups == {cycle.containment.quarantine_sg}:
                response = 'QUARANTINED'
            elif cycle.containment.original_sgs is not None and groups == set(cycle.containment.original_sgs):
                response = 'RESTORED' if cycle.containment.status == 'RESTORED' else 'UNKNOWN'
            else:
                response = 'DRIFT'
            if cycle.containment.status == 'RESTORED' and response != 'RESTORED':
                warnings.append('RESPONSE_STATE_MISMATCH')
        else:
            warnings.append(reason)
        action = ActionView(action_id=cycle.action_id, incident_id=cycle.incident_id,
            action_state=cycle.containment.status, target=mapping,
            before_sgs=phases['BEFORE'].security_group_ids if 'BEFORE' in phases else None,
            during_sgs=phases['DURING'].security_group_ids if 'DURING' in phases else None,
            after_sgs=phases['AFTER'].security_group_ids if 'AFTER' in phases else None,
            network_verified=bool(observation), started_at=cycle.containment.quarantined_at_utc,
            finished_at=cycle.containment.restored_at_utc,
            evidence_refs=list(dict.fromkeys([cycle.source.source_ref, *[s.source_ref for s in cycle.snapshots]])),
            warnings=warnings)
        return action, observation, response, warnings

    def action(self, request, action_id):
        bundle = self.bundle()
        cycle = next((c for c in bundle.cycles if c.action_id == action_id), None)
        if cycle is None:
            raise SourceError('ACTION_NOT_FOUND', 404)
        action, _, _, _ = self.cycle_view(request, cycle)
        return action, cycle.source

    def actions(self, request, incident_id=None, limit=25, cursor=None, server_id=None):
        bundle = self.bundle()
        cycles = sorted((c for c in bundle.cycles if (incident_id is None or c.incident_id == incident_id)
            and (server_id is None or c.containment.vm_id == server_id)), key=lambda c: c.action_id)
        fingerprint = hashlib.sha256(json.dumps(dump(bundle), sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        scope = [self.mode, incident_id, server_id, limit, fingerprint]
        after = None
        if cursor:
            try:
                if len(cursor) > 2048:
                    raise ValueError()
                raw = base64.b64decode(cursor.encode(), altchars=b'-_', validate=True)
                signature, body = raw[:32], raw[32:]
                if not hmac.compare_digest(signature, hmac.digest(self._cursor_key, body, 'sha256')):
                    raise ValueError()
                value = json.loads(body)
                if not isinstance(value, list) or len(value) != 2 or value[0] != scope or not isinstance(value[1], str):
                    raise ValueError()
                after = value[1]
            except (ValueError, TypeError, UnicodeError):
                raise SourceError('INVESTIGATION_CURSOR_INVALID', 422) from None
        remaining = [c for c in cycles if after is None or c.action_id > after]
        selected = remaining[:limit]
        has_more = len(remaining) > limit
        next_cursor = None
        if has_more:
            body = json.dumps([scope, selected[-1].action_id], separators=(',', ':')).encode()
            next_cursor = base64.urlsafe_b64encode(hmac.digest(self._cursor_key, body, 'sha256') + body).decode()
        return {'items': [action_dict(self.cycle_view(request, c)[0]) for c in selected],
                'has_more': has_more, 'next_cursor': next_cursor, 'total_count': len(cycles)}, bundle.source

    def timeline(self, request, incident_id):
        incident = self.incident(request, incident_id)
        result, stamp, _ = self._timeline(request, incident)
        return result, stamp

    def _timeline(self, request, incident):
        incident_id = incident.incident_id
        stamp = SourceStamp(source_system='P17', source_ref=incident_id,
            source_schema='p17-incident-durable-1',
            execution_mode=self.mode if self.mode in {'TEST', 'EVALUATION'} else 'HISTORICAL',
            observed_at=incident.updated_utc, freshness_state='PARTIAL')
        limitations, mapping, observed = [], None, None
        try:
            bundle = self.bundle()
            stamp = bundle.source
            cycles = [c for c in bundle.cycles if c.incident_id == incident_id]
        except SourceError as exc:
            if exc.status not in {503, 504}:
                raise
            cycles = []
            limitations.append(exc.code)
        items = [TimelineItem(item_id='p17:' + hashlib.sha256(f'{incident_id}:{kind}'.encode()).hexdigest()[:24],
            type=kind, occurred_at=at, source_system='P17', source_ref=incident_id,
            description=f'{kind}; persisted P17 row, not response authorization', verification='SOURCE_REPORTED')
            for kind, at in [('P17_INCIDENT_CREATED', incident.created_utc), ('P17_INCIDENT_UPDATED', incident.updated_utc)]]
        # Never choose a current cycle by timestamp. Multiple cycles require the
        # explicit cycle endpoint; the incident timeline stays current UNKNOWN.
        response = 'UNKNOWN'
        for cycle in cycles:
            action, observation, current_state, warnings = self.cycle_view(request, cycle)
            if len(cycles) == 1:
                response = current_state
                mapping = action.target if observation else None
                observed = observation
            for index, row in enumerate(cycle.actions):
                if row.incident_id != incident_id:
                    continue
                key = hashlib.sha256(f'{cycle.action_id}:{index}'.encode()).hexdigest()[:24]
                items.append(TimelineItem(item_id='action:' + key, type=row.kind,
                    occurred_at=row.timestamp, source_system=cycle.source.source_system,
                    source_ref=cycle.source.source_ref, description=f'{row.kind}; cycle={cycle.cycle_id}; source-reported evidence',
                    verification='SOURCE_REPORTED'))
            limitations.extend(warnings)
        if len(cycles) > 1:
            limitations.append('MULTIPLE_CYCLES_SELECT_EXPLICIT_ACTION; no automatic current-cycle attribution.')
        if not cycles:
            limitations.append('NO_DIRECT_INCIDENT_ACTIONS')
        limitations.append('Global ARM rows without matching incident_id are excluded. No IP/time joins. Durations require explicit clock marks.')
        result = TimelineView(incident_id=incident.incident_id, incident_status=incident.status,
            response_state=response, network_observation=mapping,
            items=sorted(items, key=lambda i: (i.occurred_at is None, i.occurred_at or self.clock(), i.item_id)),
            limitations=list(dict.fromkeys(limitations)))
        return result, stamp, observed

    def sg_lifecycle(self, request, action_id):
        bundle = self.bundle()
        cycle = next((c for c in bundle.cycles if c.action_id == action_id), None)
        if cycle is None:
            raise SourceError('ACTION_NOT_FOUND', 404)
        action, observation, response, warnings = self.cycle_view(request, cycle)
        phases = {s.phase: s for s in cycle.snapshots}
        context_rows = [r for r in cycle.actions if r.incident_id is None and r.kind in {'GLOBAL_ARMED', 'ARMED'}]
        payload = {'schema_version': 'investigation-sg-lifecycle-1', 'action': action_dict(action),
            'incident_id': cycle.incident_id, 'cycle_id': cycle.cycle_id,
            'source': dump(cycle.source),
            'history': {p: dump(phases[p]) if p in phases else None for p in ('BEFORE', 'DURING', 'AFTER')},
            'current': dump(observation) if observation else None, 'current_state': response,
            'metrics': [dump(m) for m in durations(cycle)],
            'clock_marks': [dump(mark) for mark in cycle.clock_marks],
            'arm_context': [{'kind': r.kind, 'timestamp': r.timestamp.isoformat() if r.timestamp else None,
                'link_quality': 'CONTEXT_ONLY', 'source_ref': cycle.source.source_ref} for r in context_rows],
            'limitations': warnings}
        # Validate the additive DTO without converting absent frozen SG arrays to null.
        SgLifecycleView.model_validate(payload)
        return payload, cycle.source

    def incident_trace(self, request, incident_id):
        incident = self.incident(request, incident_id)
        source = SourceStamp(source_system='P17', source_ref=incident_id,
            source_schema='p17-incident-durable-1', execution_mode=self.mode if self.mode in {'TEST', 'EVALUATION'} else 'HISTORICAL',
            observed_at=incident.updated_utc, freshness_state='HISTORICAL')
        stages = {name: missing_stage(name) for name in STAGES}
        stages['P17_DETECTION'] = sourced_stage('P17_DETECTION', source, incident.signal_rule, [
            fact('incident_status', incident.status, incident_id),
            fact('evidence_count', incident.evidence_count, incident_id),
            fact('incident_severity', incident.severity, incident_id),
            fact('confidence', incident.confidence, incident_id)], incident.updated_utc)
        # These persisted flags are facts, not a fabricated P17.3 evaluation.
        stages['P17_DECISION'] = DecisionStage(stage_id='P17_DECISION', stage='P17_DECISION',
            status='UNAVAILABLE', outcome=None, reason_codes=['P17_3_DECISION_NOT_PROVIDED'],
            source_system='P17', source_ref=incident_id, verification='UNAVAILABLE', facts=[
                fact('source_verified', incident.source_verified, incident_id),
                fact('isolation_authorized', incident.isolation_authorized, incident_id),
                fact('incident_status', incident.status, incident_id)])
        for name, stage in self.stages(request, incident_id=incident_id).items():
            if name in {'P17_DECISION', 'P17_DETECTION', 'P17_5_RESPONSE'}:
                if name == 'P17_DECISION':
                    # Preserve persisted flag facts alongside an independent dry-run.
                    stage = stage.model_copy(update={'facts': [*stages[name].facts, *stage.facts]})
                stages[name] = stage
        try:
            lifecycle, response_source, observation = self._timeline(request, incident)
            direct_items = [item for item in lifecycle.items if item.source_system != 'P17']
            if direct_items:
                facts = [fact('controller_action_count_in_bundle', len(direct_items), response_source.source_ref)]
                if observation:
                    facts.append(fact('current_response_state', lifecycle.response_state,
                        observation.source.source_ref, observation.observed_at))
                stages['P17_5_RESPONSE'] = sourced_stage('P17_5_RESPONSE', response_source,
                    'CONTROLLER_ACTION_RECORDED', facts,
                    codes=['CURRENT_NEUTRON_REQUIRED'] if lifecycle.network_observation is None else [])
        except SourceError as exc:
            if exc.status not in {503, 504}:
                raise
        key = hashlib.sha256(incident_id.encode()).hexdigest()[:24]
        trace = DecisionTrace(trace_id='trace:' + key, incident_id=incident_id, trace_kind='INCIDENT',
            stages=[stages[name] for name in STAGES], overall_outcome=incident.status,
            link_quality='PARTIAL', evidence_refs=[incident_id],
            limitations=['P17 persisted flags do not authorize Controller actions. No inferred event membership or AST.'],
            provenance=freshness(source, self.clock()))
        return trace, source


def action_dict(action):
    # Frozen arrays cannot be null. Omit absent SG phases (different from an
    # explicitly observed empty list); preserve nullable timestamps/target.
    return action.model_dump(mode='json', exclude={name for name in ('before_sgs', 'during_sgs', 'after_sgs') if getattr(action, name) is None})
