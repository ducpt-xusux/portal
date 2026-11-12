"""App-owned adapters for the C, D and E modules."""
import hashlib
from ipaddress import ip_address
import re

from .alerts import AlertError, read_alerts
from .defense_bundle import DefenseRegistry
from .n91_business.dto import EVIDENCE_EXPORT_LIMIT, EvidenceProjection, EvidenceReference
from .n91_business.models import SourceRef
from .n91_business.service import BusinessError
from .n91_evaluation.service import EvaluationSystemService
from .n91_evaluation.sources import SourceConfig, evaluation_source, system_source
from .n91_investigation.aggregate import detector_profile_reason
from .n91_investigation.service import InvestigationService
from .n91_investigation.response_history import ControllerArchiveReader
from .n91_investigation.sources import (
    ControllerReader, PinnedFile, PolicyReader, canonical_event_loader, decode_json,
    inventory_observation_loader, snapshot_incident_loader,
)
from .p17_snapshot import SnapshotError, ms_iso


UUID_REF = re.compile(r'[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}')
INCIDENT_REF = re.compile(r'INC-[a-f0-9]{20}')
TEST_SCOPE_REF = re.compile(r'TEST[-:][A-Za-z0-9][A-Za-z0-9-]{0,59}')
TEST_REF = re.compile(r'TEST-(?:event|request)-[0-9]{1,12}', re.IGNORECASE)
RULE_REF = re.compile(r'(?:CTX|INJ|OBJ|AUTH|SQL|NET|SYS|DDL|DML|PRIV|MON|QRY|META|SES)-[0-9]{3}')
RISK_STATES = frozenset({'OK', 'ERROR', 'UNKNOWN', 'UNAVAILABLE'})


def business_snapshot_resolver(reader, context):
    def resolve(kind, object_id, stream_id):
        try:
            snapshot, error = reader.read()
            if kind == 'incident':
                matches = [row.stream_id for row in snapshot.incidents if row.incident_id == object_id]
            else:
                matches = [snapshot.metadata['stream_id'] for row in read_alerts(snapshot, error)
                           if row['alert_id'] == object_id]
        except (SnapshotError, AlertError):
            raise BusinessError(503, 'SOURCE_REFERENCE_UNAVAILABLE') from None
        if stream_id is not None:
            matches = [stream for stream in matches if stream == stream_id]
        if len(matches) > 1:
            raise BusinessError(409, 'SOURCE_REFERENCE_AMBIGUOUS')
        if not matches:
            return None
        return SourceRef(kind, object_id, matches[0], 'TEST' if context == 'TEST' else 'HISTORICAL')
    return resolve


def business_evidence_loader(reader, context, source_context):
    def read(incident_id, stream_id):
        if (context == 'TEST') != (source_context == 'TEST'):
            raise BusinessError(409, 'SOURCE_CONTEXT_MISMATCH')
        if not (INCIDENT_REF.fullmatch(incident_id) and UUID_REF.fullmatch(stream_id)) and not (
                context == 'TEST' and TEST_SCOPE_REF.fullmatch(incident_id) and TEST_SCOPE_REF.fullmatch(stream_id)):
            raise BusinessError(422, 'INVALID_INCIDENT_SCOPE')
        try:
            snapshot, error = reader.read()
        except SnapshotError:
            raise BusinessError(503, 'EVIDENCE_SOURCE_UNAVAILABLE') from None
        if error:
            raise BusinessError(503, 'EVIDENCE_SOURCE_UNAVAILABLE')
        incident = snapshot.get_incident(incident_id)
        if incident is None or incident.stream_id != stream_id:
            raise BusinessError(404, 'SOURCE_OBJECT_NOT_FOUND')
        candidates = snapshot.evidence(incident)
        count = len(candidates) if candidates is not None else None
        has_more = count is not None and count > EVIDENCE_EXPORT_LIMIT
        reasons = ['DIRECT_MEMBERSHIP_NOT_PROVIDED', detector_profile_reason(snapshot.metadata),
                   'P17_PROJECTION_ONLY']
        if count is None:
            reasons.append('CANDIDATE_WINDOW_UNAVAILABLE')
        elif count != incident.evidence_count:
            reasons.append('CANDIDATE_COUNT_DIFFERS')
        if has_more:
            reasons.append('EXPORT_EVENT_LIMIT_REACHED')

        def safe_ref(value):
            if UUID_REF.fullmatch(value) or (context == 'TEST' and TEST_REF.fullmatch(value)):
                return value
            return None

        items = []
        omitted = False
        for row in (candidates or [])[:EVIDENCE_EXPORT_LIMIT]:
            event_id, request_id = safe_ref(row.event_id), safe_ref(row.request_id)
            risk_status = row.risk_status if row.risk_status in RISK_STATES else None
            rules = snapshot.rules[row.event_id]
            allowed_rules = list(dict.fromkeys(rule for rule in rules if RULE_REF.fullmatch(rule)))[:64]
            try:
                address = ip_address(row.client_ip) if '%' not in row.client_ip else None
            except ValueError:
                address = None
            omitted |= any(value is None for value in (event_id, request_id, risk_status, address))
            omitted |= len(allowed_rules) != len(set(rules))
            record_hash = hashlib.sha256(f'{snapshot.fingerprint}:{row.stream_sequence}'.encode()).hexdigest()
            items.append(EvidenceReference(stream_id=stream_id, event_id=event_id, request_id=request_id,
                stream_sequence=row.stream_sequence, occurred_at=ms_iso(row.event_ms),
                source_ip=str(address) if address else None, decision='BLOCK', risk_status=risk_status,
                risk_score=row.risk_score if risk_status == 'OK' else None, matched_rules=allowed_rules,
                source_ref='p17-ref:' + record_hash, payload_sha256=row.payload_sha256.lower()))
        if omitted:
            reasons.append('UNSAFE_REFERENCE_FIELDS_OMITTED')
        return EvidenceProjection(incident_id=incident_id, stream_id=stream_id,
            signal_rule=incident.signal_rule, complete=False, has_more=has_more,
            evidence_membership='UNAVAILABLE' if count is None else 'RECONSTRUCTED_WINDOW',
            recorded_evidence_count=incident.evidence_count, candidate_count=count,
            exported_event_count=len(items), event_limit=EVIDENCE_EXPORT_LIMIT,
            reason_codes=reasons, source_system='P17', source_schema='p17-incident-durable-1',
            source_mode='SNAPSHOT' if snapshot.remote_status is None else 'REMOTE_READONLY',
            execution_mode='TEST' if context == 'TEST' else 'HISTORICAL',
            captured_at=snapshot.export.exported_at, snapshot_sha256=snapshot.fingerprint, items=items)
    return read


def investigation_sources(settings):
    policy = None
    if settings.investigation_policy_path:
        path = settings.investigation_policy_path
        adapter = {'adapter': decode_json} if path.suffix.lower() == '.json' else {}
        policy = PolicyReader(PinnedFile(path, settings.investigation_policy_sha256),
                              settings.investigation_policy_version, **adapter)
    controller = None
    if settings.investigation_controller_path:
        controller = ControllerReader(PinnedFile(settings.investigation_controller_path,
                                                 settings.investigation_controller_sha256))
    response_history = None
    if settings.investigation_controller_archive_path:
        binding = None
        if settings.investigation_controller_binding_path:
            binding = PinnedFile(settings.investigation_controller_binding_path,
                                 settings.investigation_controller_binding_sha256)
        response_history = ControllerArchiveReader(settings.investigation_controller_archive_path,
            DefenseRegistry(settings.defense_source_registry_path), binding)
    return InvestigationService(
        mode=settings.p16h_import_context if settings.p16h_import_context in {'TEST', 'EVALUATION'} else 'LIVE',
        policy_reader=policy,
        controller_reader=controller,
        event_loader=canonical_event_loader,
        incident_loader=snapshot_incident_loader,
        neutron_loader=inventory_observation_loader,
        response_history_reader=response_history,
    )


def evaluation_sources(settings, registry):
    context = settings.evaluation_source_context
    return EvaluationSystemService(
        evaluations=evaluation_source(SourceConfig(
            settings.evaluation_observations_path, settings.evaluation_observations_sha256, context)),
        system=system_source(SourceConfig(
            settings.system_observations_path, settings.system_observations_sha256, context)),
        evidence=registry,
    )
