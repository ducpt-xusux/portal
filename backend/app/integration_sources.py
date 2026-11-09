"""App-owned adapters for the C, D and E modules."""
from .alerts import AlertError, read_alerts
from .n91_business.models import SourceRef
from .n91_business.service import BusinessError
from .n91_evaluation.service import EvaluationSystemService
from .n91_evaluation.sources import SourceConfig, evaluation_source, system_source
from .n91_investigation.service import InvestigationService
from .n91_investigation.sources import (
    ControllerReader, PinnedFile, PolicyReader, canonical_event_loader, decode_json,
    inventory_observation_loader, snapshot_incident_loader,
)
from .p17_snapshot import SnapshotError


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
    return InvestigationService(
        mode=settings.p16h_import_context if settings.p16h_import_context in {'TEST', 'EVALUATION'} else 'LIVE',
        policy_reader=policy,
        controller_reader=controller,
        event_loader=canonical_event_loader,
        incident_loader=snapshot_incident_loader,
        neutron_loader=inventory_observation_loader,
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
