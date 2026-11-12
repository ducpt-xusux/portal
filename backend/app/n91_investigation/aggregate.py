"""One-snapshot read projection. No producer calls, detector or network actions."""
from datetime import datetime, timezone
import hashlib
import json
import sqlite3

from fastapi import HTTPException
from pydantic import ValidationError

from .. import canonical_audit
from ..alerts import AlertError, read_alerts
from ..defense_bundle import DefenseBundleError, DefenseRegistry, summarize_registry
from ..n91_business.models import SourceRef
from ..n91_business.service import BusinessError
from ..p17_api import CursorCodec
from ..p17_snapshot import SnapshotError, ms_iso
from .aggregate_models import (
    AlertsSection, AnalystCase, CanonicalProjection, DependentSection, EventMember,
    EventReference, EventRisk, Identity, InvestigationData, InvestigationMeta,
    InvestigationResponse, MembersPage, P17Projection, RecordedIncident, RegistrySummary, ScopedAlert,
    SourceAvailability,
)
from .sources import SourceError
from .response_history import read_history


MAX_CANONICAL_BYTES = 8 * 1024 * 1024
MAX_ALERTS = 100

# 07D Proxy evidence HISTORICAL_CORR002 records these identifiers, but omits
# the complete predicate and the provenance linking detector bytes to an incident.
DETECTOR_EXCERPT_VERSION = 'p17-incident-g03-dual-v3-20261104'
DETECTOR_EXCERPT_SHA256 = '86eccd8bac12d6c863a393c3ee09f5a6a956d5d6cf70d8f68dd4677b437fac8c'


def detector_profile_reason(metadata):
    version = metadata.get('detector_version')
    sha256 = metadata.get('detector_sha256', '').lower()
    if (version and version != DETECTOR_EXCERPT_VERSION) or (sha256 and sha256 != DETECTOR_EXCERPT_SHA256):
        return 'DETECTOR_PROFILE_MISMATCH'
    if not version or not sha256:
        return 'DETECTOR_PROFILE_UNAVAILABLE'
    return 'DETECTOR_PROFILE_INCOMPLETE'


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def error_code(error, fallback):
    code = getattr(error, 'code', None)
    if isinstance(error, HTTPException) and isinstance(error.detail, dict):
        code = error.detail.get('code')
    return code if isinstance(code, str) and code.replace('_', '').isalnum() and len(code) <= 80 else fallback


def absent(name, now, code):
    return SourceAvailability(source_system=name, availability='UNAVAILABLE',
                              freshness_state='UNAVAILABLE', read_at=now, error_code=code)


def canonical_projection(view):
    """No query text, free-form reasons, user, source paths or nested metadata."""
    provenance = view['source_provenance']
    return CanonicalProjection(**{key: view[key] for key in (
        'stream_id', 'event_id', 'request_id', 'occurred_at', 'decision', 'effective_action',
        'action_result', 'policy_id', 'policy_version', 'runtime_mode', 'matched_rules',
        'blocking_rules', 'monitor_rules')}, risk=EventRisk(**{
            key: view['risk'][key] for key in ('status', 'score', 'severity')}),
        source_ref='p16h-ref:' + digest(provenance['source_ref']),
        payload_sha256=provenance['payload_sha256'],
        payload_hash_basis=provenance['payload_hash_basis'])


class InvestigationAggregate:
    def __init__(self, clock=None, service=None):
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.service = service
        self.cursors = CursorCodec()

    def canonical(self, request, stream_id, candidates, page_ids, now, context):
        """One scoped SQL query, one transaction, bounded payload/fingerprint scan.

        Fingerprint all matching candidate rows, even across pages, to detect an
        in-place cache change as well as ordinary append-only source revisions.
        Only current-page rows are normalized or kept in memory.
        """
        selected, count, size = {}, 0, 0
        try:
            with canonical_audit.audit_read(request) as (db, meta, fingerprint):
                stored_context = meta.get('import_context')
                if (stored_context == 'TEST') != (context == 'TEST') and stored_context is not None:
                    raise SourceError('CANONICAL_CONTEXT_MISMATCH')
                checksum = hashlib.sha256(fingerprint.encode())
                ids = json.dumps([row.event_id for row in candidates], separators=(',', ':'))
                rows = db.execute(
                    'SELECT event_id,payload,imported_at FROM p16h_audit_index_v1 '
                    'WHERE stream_id=? AND event_id IN (SELECT value FROM json_each(?)) '
                    'ORDER BY event_id,imported_at,payload', (stream_id, ids))
                for row in rows:
                    count += 1
                    raw = row['payload'].encode()
                    size += len(raw)
                    if count > len(candidates) or size > MAX_CANONICAL_BYTES:
                        raise SourceError('CANONICAL_COLLECTION_LIMIT')
                    checksum.update(json.dumps([row['event_id'], row['payload'], row['imported_at']],
                                               separators=(',', ':')).encode())
                    if row['event_id'] in page_ids:
                        if row['event_id'] in selected:
                            raise SourceError('CANONICAL_EVENT_IDENTITY_CONFLICT', 409)
                        selected[row['event_id']] = (row['payload'], row['imported_at'])
                generation = checksum.hexdigest()
                source = SourceAvailability(source_system='P16H', availability='AVAILABLE',
                    freshness_state=meta['freshness_state'], read_at=now,
                    data_as_of=meta.get('data_as_of'), generation=generation,
                    source_ref='sha256:' + generation, source_schema=meta['source_schema'],
                    context=stored_context, error_code=meta.get('last_error_code'))
                return selected, source, generation
        except (HTTPException, SourceError, sqlite3.Error, OSError, ValueError) as exc:
            code = error_code(exc, 'CANONICAL_SOURCE_UNAVAILABLE')
            return {}, absent('P16H', now, code), 'unavailable:' + code

    def registry(self, request, now, context):
        try:
            registry, sha = DefenseRegistry(request.app.state.settings.defense_source_registry_path).read()
            if registry.run_context != context:
                raise SourceError('DEFENSE_REGISTRY_CONTEXT_MISMATCH')
            summary = RegistrySummary.model_validate(summarize_registry(registry, sha, now).model_dump())
            source = SourceAvailability(source_system='DEFENSE_REGISTRY', availability='PARTIAL',
                freshness_state='HISTORICAL', read_at=now, source_ref='sha256:' + sha,
                generation=registry.generation, source_schema=registry.schema_version,
                context=registry.run_context, error_code='CONTENT_REVIEW_REQUIRED')
            return summary, source, digest(registry.generation + ':' + sha)
        except (DefenseBundleError, SourceError) as exc:
            code = error_code(exc, 'DEFENSE_REGISTRY_UNAVAILABLE')
            return None, absent('DEFENSE_REGISTRY', now, code), 'unavailable:' + code

    def analyst_case(self, request, incident, now, context):
        principal = getattr(request.state, 'business_principal', None)
        business = getattr(request.state, 'business_gate_service', None)
        if principal is None or business is None:
            code = 'OBSERVATION_READ_ONLY'
            return AnalystCase(availability='UNAVAILABLE', reason_codes=[code]), absent('PORTAL_BUSINESS', now, code)
        if (business.config.context == 'TEST') != (context == 'TEST'):
            code = 'PORTAL_BUSINESS_CONTEXT_MISMATCH'
            return AnalystCase(availability='UNAVAILABLE', reason_codes=[code]), absent('PORTAL_BUSINESS', now, code)
        ref = SourceRef('incident', incident.incident_id, incident.stream_id,
                        'TEST' if context == 'TEST' else 'HISTORICAL')
        try:
            overlay = business.overlay(principal, ref)
            section = AnalystCase(availability='AVAILABLE', overlay=overlay, reason_codes=[])
            source = SourceAvailability(source_system='PORTAL_BUSINESS', availability='AVAILABLE',
                freshness_state='FRESH', read_at=now, context=business.config.context)
            return section, source
        except BusinessError as exc:
            return AnalystCase(availability='UNAVAILABLE', reason_codes=[exc.code]), absent('PORTAL_BUSINESS', now, exc.code)
        except (sqlite3.Error, OSError, ValueError, TypeError):
            code = 'PORTAL_BUSINESS_SOURCE_UNAVAILABLE'
            return AnalystCase(availability='UNAVAILABLE', reason_codes=[code]), absent('PORTAL_BUSINESS', now, code)

    def alerts(self, snapshot, incident, error, now):
        try:
            records = read_alerts(snapshot, error)
            events = {row.event_id: row for row in snapshot.events}
            scoped = sorted((row for row in records if row['incident_id'] == incident.incident_id),
                            key=lambda row: (row['created_at'], row['alert_id']), reverse=True)
            items = []
            for row in scoped[:MAX_ALERTS]:
                event = events[row['event_refs'][0]]
                if event.stream_id != incident.stream_id:
                    raise SourceError('P17_ALERT_STREAM_MISMATCH')
                items.append(ScopedAlert(alert_id=row['alert_id'], incident_id=incident.incident_id,
                    stream_id=incident.stream_id, created_at=row['created_at'],
                    signal_code=row['signal_code'], severity=row['severity'],
                    trigger_event=EventReference(stream_id=event.stream_id,
                                                event_id=event.event_id, request_id=event.request_id)))
            return AlertsSection(availability='AVAILABLE', items=items, total_count=len(scoped),
                                 has_more=len(scoped) > MAX_ALERTS,
                                 reason_codes=['ALERTS_CAPPED'] if len(scoped) > MAX_ALERTS else [])
        except (AlertError, SourceError, KeyError, ValidationError):
            return AlertsSection(availability='UNAVAILABLE', items=[], total_count=None,
                                 reason_codes=['P17_ALERT_SOURCE_INVALID'])

    def member(self, snapshot, row, canonical_row, canonical_source):
        reasons = ['LEGACY_DETECTOR_PROFILE_UNPINNED', 'DIRECT_MEMBERSHIP_NOT_PROVIDED']
        canonical, state, join = None, 'UNAVAILABLE', 'RECONSTRUCTED_WINDOW'
        comparability = 'UNAVAILABLE'
        if canonical_row is not None:
            try:
                payload, imported_at = canonical_row
                view = canonical_audit.event_view(json.loads(payload), imported_at)
                canonical = canonical_projection(view)
                if (canonical.stream_id, canonical.event_id) != (row.stream_id, row.event_id):
                    raise SourceError('CANONICAL_IDENTITY_MISMATCH')
                state = 'AVAILABLE'
                if canonical.request_id is None:
                    reasons.append('CANONICAL_REQUEST_ID_UNAVAILABLE')
                elif canonical.request_id != row.request_id:
                    reasons.append('CANONICAL_REQUEST_ID_MISMATCH')
                    state, join, canonical = 'MISMATCH', 'MISMATCH', None
                if canonical is not None and view['source_ip'] != row.client_ip:
                    reasons.append('CANONICAL_SOURCE_IP_MISMATCH')
                    state, join, canonical = 'MISMATCH', 'MISMATCH', None
                if canonical is not None:
                    comparability = 'NOT_PROVEN' if canonical.payload_sha256 else 'UNAVAILABLE'
                    reasons.append('PAYLOAD_HASH_BASIS_NOT_PROVEN')
            except (SourceError, ValueError, KeyError, TypeError, ValidationError):
                state, join, canonical = 'MISMATCH', 'MISMATCH', None
                reasons.append('CANONICAL_RECORD_INVALID_OR_MISMATCH')
        else:
            reasons.append('CANONICAL_RECORD_NOT_FOUND' if canonical_source.availability == 'AVAILABLE'
                           else 'CANONICAL_SOURCE_UNAVAILABLE')
        return EventMember(event_ref=EventReference(stream_id=row.stream_id,
            event_id=row.event_id, request_id=row.request_id), projection=P17Projection(
            stream_sequence=row.stream_sequence, occurred_at=ms_iso(row.event_ms),
            ingested_at=row.received_utc, blocked=bool(row.blocked),
            event_class=row.event_class, live_eligible=bool(row.live_eligible),
            matched_rules=list(snapshot.rules[row.event_id]), risk=EventRisk(
                status=row.risk_status, score=row.risk_score if row.risk_status == 'OK' else None),
            payload_sha256=row.payload_sha256.lower()), canonical=canonical,
            canonical_availability=state, join_state=join, reason_codes=reasons,
            hash_comparability=comparability)

    def read(self, request, incident_id, stream_id, limit, cursor):
        now = self.clock()
        try:
            snapshot, error = request.app.state.p17_reader.read()
        except SnapshotError as exc:
            raise SourceError(exc.code) from None
        if snapshot.metadata['stream_id'] != stream_id:
            raise SourceError('INCIDENT_NOT_FOUND_IN_STREAM', 404)
        matches = [row for row in snapshot.incidents if (row.stream_id, row.incident_id) == (stream_id, incident_id)]
        if not matches:
            raise SourceError('INCIDENT_NOT_FOUND_IN_STREAM', 404)
        if len(matches) != 1:
            raise SourceError('INVESTIGATION_IDENTITY_CONFLICT', 409)
        incident = matches[0]
        candidates = snapshot.evidence(incident)
        available = candidates is not None
        candidates = sorted(candidates or [], key=lambda row: (row.event_ms, row.stream_sequence, row.event_id))
        context = 'TEST' if request.app.state.settings.p16h_import_context == 'TEST' else 'IMPORTED_UNVERIFIED'
        scope = digest(json.dumps([stream_id, incident_id, limit, context, 'LEGACY_UNPINNED']))
        after = self.decode_cursor(cursor, scope)
        remaining = [row for row in candidates if after is None or
                     (row.event_ms, row.stream_sequence, row.event_id) > after]
        page = remaining[:limit]
        canonical_rows, canonical_source, canonical_generation = self.canonical(
            request, stream_id, candidates, {row.event_id for row in page}, now, context)
        registry, registry_source, registry_generation = self.registry(request, now, context)
        source_generation = digest(json.dumps([snapshot.cursor_fingerprint, error,
            canonical_generation, registry_generation, 'LEGACY_UNPINNED']))
        if cursor and self.cursor_source(cursor) != source_generation:
            raise SourceError('INVESTIGATION_SOURCE_CHANGED', 409)
        more = len(remaining) > limit
        next_cursor = self.cursors.encode(scope, source_generation,
            [page[-1].event_ms, page[-1].stream_sequence, page[-1].event_id]) if more else None
        members = [self.member(snapshot, row, canonical_rows.get(row.event_id), canonical_source) for row in page]
        case, business_source = self.analyst_case(request, incident, now, context)
        alerts = self.alerts(snapshot, incident, error, now)
        primary_freshness = 'STALE' if error else 'HISTORICAL' if snapshot.remote_status is None else 'FRESH'
        p17_source = SourceAvailability(source_system='P17', availability='PARTIAL' if error else 'AVAILABLE',
            freshness_state=primary_freshness, read_at=now,
            captured_at=snapshot.export.exported_at,
            source_ref='sha256:' + snapshot.fingerprint, generation=snapshot.cursor_fingerprint,
            source_schema=snapshot.metadata['schema'], context=context, error_code=error,
            reason_codes=['DATA_AS_OF_NOT_PROVIDED', 'OBSERVATION_TIME_NOT_PROVIDED'])
        controller_error = 'CONTROLLER_SEMANTIC_PROJECTION_NOT_PROVIDED'
        response = None
        if self.service is not None and self.service.response_history_reader is not None:
            try:
                response, stamp = read_history(request, self.service, incident)
            except SourceError as exc:
                controller_error = exc.code
        missing = ['detection.detector_profile', 'decision.evaluation',
                   'event_members.direct_membership', 'canonical.coverage_complete']
        if response is None:
            response = DependentSection(reason_codes=[controller_error])
            controller_source = absent('CONTROLLER', now, controller_error)
            missing.append('response.controller_semantics')
        else:
            controller_source = SourceAvailability(source_system='CONTROLLER', availability='PARTIAL',
                freshness_state='HISTORICAL', read_at=now, source_ref=stamp.source_ref,
                generation=response.provenance.registry_generation, source_schema=stamp.source_schema,
                context=context, reason_codes=response.reason_codes)
        if not available:
            missing.append('event_members.candidates')
        if any(row.canonical_availability != 'AVAILABLE' for row in members) or canonical_source.availability == 'UNAVAILABLE':
            missing.append('event_members.canonical')
        if registry is None:
            missing.append('defense_registry')
        if case.availability == 'UNAVAILABLE':
            missing.append('analyst_case')
        if alerts.availability == 'UNAVAILABLE':
            missing.append('alerts')
        data = InvestigationData(identity=Identity(stream_id=stream_id, incident_id=incident_id),
            incident=RecordedIncident(stream_id=stream_id, incident_id=incident_id,
                signal_rule=incident.signal_rule, source_ip=incident.client_ip,
                source_key_hash=digest(incident.source_key), severity=incident.severity,
                status=incident.status, confidence=incident.confidence, evidence_count=incident.evidence_count,
                peak_p15=incident.peak_p15, source_verified=bool(incident.source_verified),
                isolation_authorized=bool(incident.isolation_authorized), first_seen=ms_iso(incident.first_ms),
                last_seen=ms_iso(incident.last_ms), created_at=incident.created_utc, updated_at=incident.updated_utc),
            event_members=MembersPage(available=available, items=members, authoritative_count=incident.evidence_count,
                total_candidates=len(candidates) if available else None,
                verified_linked_count=0 if available else None,
                membership='RECONSTRUCTED_WINDOW' if available else 'UNAVAILABLE',
                matches_recorded_count=len(candidates) == incident.evidence_count if available else None,
                limit=limit, has_more=more, next_cursor=next_cursor), alerts=alerts,
            detection=DependentSection(reason_codes=[detector_profile_reason(snapshot.metadata),
                'LEGACY_CANDIDATES_UNPINNED']),
            decision=DependentSection(reason_codes=['P17_3_DECISION_NOT_PROVIDED']),
            response=response,
            analyst_case=case, defense_registry=registry)
        meta = InvestigationMeta(request_id=request.state.request_id, read_at=now,
            data_as_of=None, source_context=context,
            freshness_state=primary_freshness,
            sources=[p17_source, canonical_source, registry_source, business_source,
                     absent('P17_3', now, 'P17_3_DECISION_NOT_PROVIDED'),
                     controller_source],
            missing_fields=missing, next_cursor=next_cursor,
            limitations=['Provisional handoff contract; no direct membership authority supplied.',
                'Legacy candidate window is unpinned; eligible_for_corr is unavailable.',
                'Registry metadata integrity does not create semantic evidence or response authorization.',
                'Canonical payload hashes have an unverified upstream basis; no payload equality claim.',
                'Historical records and current OpenStack observations are independent; no current SG synthesized.'])
        return InvestigationResponse(data=data, meta=meta)

    def decode_cursor(self, cursor, scope):
        if cursor is None:
            return None
        # Verify HMAC, expiry, filter scope and position using the existing codec.
        try:
            return self.cursors.decode(cursor, scope, self.cursor_source(cursor), (int, int, str))
        except (HTTPException, ValueError, TypeError, KeyError):
            raise SourceError('INVESTIGATION_CURSOR_INVALID', 422) from None

    @staticmethod
    def cursor_source(cursor):
        # This value is never trusted before CursorCodec verifies the signature.
        import base64
        try:
            encoded = cursor.split('.')[0]
            value = json.loads(base64.b64decode(encoded + '=' * (-len(encoded) % 4), altchars=b'-_', validate=True))
            source = value['source']
            if not isinstance(source, str) or len(source) != 64:
                raise ValueError()
            return source
        except (ValueError, TypeError, KeyError, UnicodeError):
            raise SourceError('INVESTIGATION_CURSOR_INVALID', 422) from None
