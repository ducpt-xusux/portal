"""Read-only 07D Controller history and explicit P17 stream binding."""
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
import re
from typing import Annotated, Literal, get_args

from pydantic import AwareDatetime, Field, ValidationError

from ..defense_bundle import DefenseBundleError, DefenseRegistry, digest, verified_archive_artifacts
from ..defense_bundle_models import OriginMode
from .models import (
    ArmContext, ClockMark, Containment, ControllerBundle, ControllerCycle, DTO, DurationMetric,
    Hash, ID, Refs, SgHistory, SgSnapshot, SourceStamp,
)
from .service import check_mode, durations
from .sources import PinnedFile, SourceError, decode_json


class ArchiveBinding(DTO):
    """A hash-pinned operator projection of a P17 export from the same run."""
    schema_version: Literal['portal-p17-controller-binding-1']
    run_id: ID
    archive_sha256: Hash
    stream_id: ID
    incident_id: ID
    port_id: ID
    vm_id: ID
    project_id: ID
    source_ref: ID


HistoryArtifact = Literal['CONTAINMENT', 'CLONE_BEFORE', 'CLONE_AFTER', 'SG_SAMPLER',
                          'CONTROLLER_WATCH', 'RESTORE_VERIFICATION']


class ArtifactRef(DTO):
    label: HistoryArtifact
    source_ref: ID
    sha256: Hash


class HistoryProvenance(DTO):
    run_id: ID
    archive_sha256: Hash
    registry_generation: Hash
    origin_mode: OriginMode
    scope: Literal['LAB', 'UNKNOWN']
    source_context: Literal['TEST', 'IMPORTED_UNVERIFIED']
    artifacts: Annotated[list[ArtifactRef], Field(min_length=1, max_length=6)]


class NeutronSg(DTO):
    source_ref: ID
    observed_at: AwareDatetime
    expires_at: AwareDatetime
    security_group_ids: Refs


class ResponseCycle(DTO):
    cycle_id: ID
    id_authority: Literal['PORTAL_PROJECTION_ID'] = 'PORTAL_PROJECTION_ID'
    state: ID
    port_id: ID
    vm_id: ID
    project_id: ID | None
    original_sgs: Refs | None
    quarantine_sg: ID | None
    clock_marks: Annotated[list[ClockMark], Field(max_length=32)]
    metrics: Annotated[list[DurationMetric], Field(max_length=4)]
    history: SgHistory
    current: NeutronSg | None
    current_state: Literal['UNKNOWN', 'DRIFT', 'QUARANTINED', 'RESTORED']
    current_reason: ID | None


class ResponseHistory(DTO):
    schema_version: Literal['portal-response-history-1'] = 'portal-response-history-1'
    availability: Literal['PARTIAL'] = 'PARTIAL'
    incident_id: ID
    stream_id: ID | None
    binding_source_ref: ID | None
    provenance: HistoryProvenance
    arm_context: ArmContext | None
    cycles: Annotated[list[ResponseCycle], Field(min_length=1, max_length=256)]
    reason_codes: Refs


class PortSnapshot(DTO):
    id: ID
    project_id: ID
    device_id: ID
    security_group_ids: Refs


@dataclass(frozen=True)
class ArchivedHistory:
    bundle: ControllerBundle
    provenance: HistoryProvenance
    binding: ArchiveBinding | None
    reasons: tuple[str, ...]
    arm_context: ArmContext | None = None


@dataclass(frozen=True)
class ControllerArchiveReader:
    path: Path
    registry: DefenseRegistry
    binding_file: PinnedFile | None = None

    def read(self):
        try:
            registry, _ = self.registry.read()
            manifest, data = verified_archive_artifacts(self.path, registry, 'controller')
            archive = next(a for a in registry.archives if a.source_host == 'controller')
            refs = [ArtifactRef(label=label, source_ref=row.artifact_id, sha256=row.sha256)
                    for label, (row, _) in data.items() if label in get_args(HistoryArtifact)]
            row, raw = data['CONTAINMENT']
            provenance = HistoryProvenance(run_id=registry.run_id, archive_sha256=archive.archive_sha256,
                registry_generation=registry.generation, origin_mode=row.origin_mode, scope=row.scope,
                source_context=registry.run_context, artifacts=refs)
            source = SourceStamp(source_system='CONTROLLER', source_ref=row.artifact_id,
                source_sha256=row.sha256, source_schema=row.source_schema,
                execution_mode='TEST' if registry.run_context == 'TEST' else 'HISTORICAL')
            cycle, reasons = project_cycle(raw, data, source)
            if cycle.incident_id != manifest.incident_id:
                raise SourceError('CONTROLLER_MANIFEST_INCIDENT_MISMATCH')
            arm = lab_arm_context(*data['CONTROLLER_WATCH']) if row.scope == 'LAB' else None
            bundle = ControllerBundle(schema_version='investigation-controller-bundle-1', source=source, cycles=[cycle])
        except DefenseBundleError as exc:
            raise SourceError(exc.code) from None
        except (KeyError, TypeError, ValueError, ValidationError):
            raise SourceError('CONTROLLER_PROJECTION_INVALID') from None

        binding = None
        if self.binding_file is not None:
            try:
                candidate = ArchiveBinding.model_validate(decode_json(self.binding_file.read()))
                if matches_binding(candidate, provenance, cycle):
                    binding = candidate
                else:
                    reasons.append('P17_BINDING_MISMATCH')
            except (SourceError, ValidationError):
                reasons.append('P17_BINDING_UNAVAILABLE')
        return ArchivedHistory(bundle, provenance, binding, tuple(reasons), arm)


def matches_binding(binding, provenance, cycle):
    return (binding.run_id, binding.archive_sha256, binding.incident_id, binding.port_id,
            binding.vm_id, binding.project_id) == (
        provenance.run_id, provenance.archive_sha256, cycle.incident_id, cycle.containment.port_id,
        cycle.containment.vm_id, cycle.project_id)


def lab_arm_context(row, raw):
    stamps = re.findall(rb'\bP17_5_ARMED_UTC=(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|\+00:00))(?=\s|$)', raw)
    if len(stamps) != 1:
        return None
    try:
        at = datetime.fromisoformat(stamps[0].decode('ascii').replace('Z', '+00:00'))
    except ValueError:
        return None
    return ArmContext(kind='OWNER_ARM', timestamp=at, link_quality='CONTEXT_ONLY', source_ref=row.artifact_id)


def project_cycle(raw, artifacts, source):
    doc = decode_json(raw)
    if not isinstance(doc, dict) or doc.get('schema') != 'p17-5-lab-containment-1':
        raise SourceError('CONTROLLER_PROFILE_UNSUPPORTED')
    fields = ('incident_id', 'port_id', 'vm_id', 'status', 'original_sgs', 'quarantine_sg',
              'quarantined_at_utc', 'restored_at_utc')
    containment = Containment.model_validate({key: doc[key] for key in fields if key in doc})
    # The native source has neither an action ID nor a cycle ID. The immutable
    # artifact identity and its bytes are the basis of this Portal-owned ID.
    cycle_id = 'CYC-' + digest(f'{source.source_ref}:{source.source_sha256}'.encode())
    snapshots = []
    reasons = []
    candidates = {}
    for phase in ('BEFORE', 'AFTER'):
        row, blob = artifacts['CLONE_' + phase]
        try:
            port = decode_json(blob)
            snapshot = PortSnapshot.model_validate({key: port[key] for key in PortSnapshot.model_fields})
        except (SourceError, KeyError, TypeError, ValidationError):
            reasons.append(f'SG_{phase}_UNAVAILABLE')
            continue
        if (snapshot.id, snapshot.device_id) != (containment.port_id, containment.vm_id):
            reasons.append(f'SG_{phase}_IDENTITY_MISMATCH')
            continue
        candidates[phase] = (snapshot, row.artifact_id)
    projects = {port.project_id for port, _ in candidates.values()}
    project_id = next(iter(projects)) if len(projects) == 1 else None
    if len(projects) > 1:
        reasons.append('SG_PROJECT_MISMATCH')
    if project_id:
        for phase, (port, ref) in candidates.items():
            snapshots.append(SgSnapshot(phase=phase, cycle_id=cycle_id, incident_id=containment.incident_id,
                project_id=project_id, port_id=port.id, server_id=port.device_id,
                security_group_ids=port.security_group_ids, observed_at=None, source_ref=ref))
        reasons.append('SG_CAPTURE_TIME_UNAVAILABLE')
    after = next((s for s in snapshots if s.phase == 'AFTER'), None)
    if containment.status == 'RESTORED' and after and containment.original_sgs is not None:
        if set(after.security_group_ids) != set(containment.original_sgs):
            reasons.append('SG_RESTORE_MISMATCH')
    reasons.append('SG_DURING_IDENTITY_UNAVAILABLE')

    marks = []
    for kind, at in (
        ('PREPARED', doc.get('prepared_at_utc')),
        ('QUARANTINE_APPLIED', containment.quarantined_at_utc),
        ('RESTORE_SUCCESS', containment.restored_at_utc if containment.status == 'RESTORED' else None),
    ):
        if at is None:
            continue
        mark = ClockMark(incident_id=containment.incident_id, cycle_id=cycle_id, kind=kind, timestamp=at,
            clock_id=source.source_ref, time_basis='CONTROLLER_CONTAINMENT_UTC', source_ref=source.source_ref)
        if mark.timestamp.utcoffset() == timedelta(0):
            marks.append(mark)
        else:
            reasons.append('CONTROLLER_CLOCK_BASIS_UNAVAILABLE')
    return ControllerCycle(schema_version='investigation-controller-1', action_id=cycle_id,
        incident_id=containment.incident_id, cycle_id=cycle_id, project_id=project_id,
        source=source, containment=containment, actions=[], snapshots=snapshots, clock_marks=marks), reasons


def read_history(request, service, incident=None, *, include_current=True):
    """Standalone history is never an incident join. Direct history requires an exact P17 row."""
    if service.response_history_reader is None:
        raise SourceError('CONTROLLER_SEMANTIC_PROJECTION_NOT_PROVIDED')
    archive = service.response_history_reader.read()
    check_mode(archive.bundle.source.execution_mode, service.mode)
    binding = archive.binding
    reasons = list(archive.reasons)
    if incident is None:
        cycles = archive.bundle.cycles
        if not cycles or len({cycle.incident_id for cycle in cycles}) != 1:
            raise SourceError('CONTROLLER_HISTORY_SCOPE_AMBIGUOUS')
        reasons.append('P17_STREAM_UNVERIFIED' if binding is None else 'CONTROLLER_HISTORY_STANDALONE')
    else:
        if binding is None or (binding.stream_id, binding.incident_id) != (incident.stream_id, incident.incident_id):
            raise SourceError('P17_STREAM_UNVERIFIED')
        cycles = [cycle for cycle in archive.bundle.cycles if matches_binding(binding, archive.provenance, cycle)]
        if not cycles:
            raise SourceError('P17_BINDING_MISMATCH')
    if len(cycles) > 1:
        reasons.append('CONTROLLER_MULTIPLE_CYCLES')
    return ResponseHistory(incident_id=cycles[0].incident_id, stream_id=incident.stream_id if incident else None,
        binding_source_ref=binding.source_ref if incident else None, provenance=archive.provenance,
        arm_context=archive.arm_context,
        cycles=[project_view(request, service, cycle, len(cycles) == 1, include_current) for cycle in cycles],
        reason_codes=list(dict.fromkeys(reasons))), archive.bundle.source


def project_view(request, service, cycle, single, include_current):
    observation, state, reason = None, 'UNKNOWN', None
    if not single:
        reason = 'CONTROLLER_MULTIPLE_CYCLES'
    elif cycle.project_id is None:
        reason = 'NEUTRON_TARGET_IDENTITY_UNAVAILABLE'
    elif not include_current:
        reason = 'NEUTRON_CURRENT_NOT_REQUESTED'
    else:
        _, observation, state, warnings = service.cycle_view(request, cycle)
        if observation is None:
            reason = warnings[-1]
        elif cycle.containment.status == 'RESTORED' and cycle.containment.original_sgs is not None and state != 'RESTORED':
            state, reason = 'DRIFT', 'RESPONSE_STATE_MISMATCH'
        elif cycle.containment.original_sgs is None and state == 'DRIFT':
            state, reason = 'UNKNOWN', 'NEUTRON_BASELINE_UNAVAILABLE'
    phases = {snapshot.phase: snapshot for snapshot in cycle.snapshots}
    return ResponseCycle(cycle_id=cycle.cycle_id, state=cycle.containment.status, project_id=cycle.project_id,
        port_id=cycle.containment.port_id, vm_id=cycle.containment.vm_id,
        original_sgs=cycle.containment.original_sgs, quarantine_sg=cycle.containment.quarantine_sg,
        clock_marks=cycle.clock_marks, metrics=durations(cycle),
        history=SgHistory(BEFORE=phases.get('BEFORE'), DURING=phases.get('DURING'), AFTER=phases.get('AFTER')),
        current=NeutronSg(source_ref=observation.source.source_ref, observed_at=observation.observed_at,
                         expires_at=observation.expires_at, security_group_ids=observation.security_group_ids)
                if observation else None, current_state=state, current_reason=reason)
