export function historyFixture(incidentId, streamId = null) {
  const identity = { incident_id: incidentId, cycle_id: 'TEST-cycle' }
  const target = { port_id: 'TEST-port', project_id: 'TEST-project' }
  const sourceRef = 'TEST-controller'
  const hash = 'a'.repeat(64)
  return {
    schema_version: 'portal-response-history-1',
    availability: 'PARTIAL',
    incident_id: incidentId,
    stream_id: streamId,
    binding_source_ref: streamId ? 'TEST-P17-export' : null,
    arm_context: null,
    provenance: {
      run_id: 'TEST-run',
      archive_sha256: hash,
      registry_generation: hash,
      origin_mode: 'LIVE_LAB',
      scope: 'LAB',
      source_context: 'TEST',
      artifacts: [{ label: 'CONTAINMENT', source_ref: sourceRef, sha256: hash }],
    },
    cycles: [{
      cycle_id: identity.cycle_id,
      id_authority: 'PORTAL_PROJECTION_ID',
      state: 'RESTORED',
      ...target,
      vm_id: 'TEST-vm',
      original_sgs: [],
      quarantine_sg: 'TEST-qsg',
      clock_marks: [],
      metrics: [
        {
          ...identity,
          metric: 'quarantine_duration',
          seconds: 20.125,
          unit: 'seconds',
          start_kind: 'QUARANTINE_APPLIED',
          end_kind: 'RESTORE_SUCCESS',
          clock_id: sourceRef,
          time_basis: 'CONTROLLER_CONTAINMENT_UTC',
          source_refs: [sourceRef, sourceRef],
          unavailable_reason: null,
        },
        {
          ...identity,
          metric: 'detection_response',
          seconds: null,
          unit: 'seconds',
          start_kind: 'DETECTED',
          end_kind: 'QUARANTINE_APPLIED',
          clock_id: null,
          time_basis: null,
          source_refs: [],
          unavailable_reason: 'MISSING_CLOCK_MARK',
        },
      ],
      history: {
        BEFORE: null,
        DURING: null,
        AFTER: {
          ...identity,
          ...target,
          phase: 'AFTER',
          server_id: 'TEST-vm',
          security_group_ids: [],
          observed_at: null,
          source_ref: 'TEST-controller-after',
        },
      },
      current: null,
      current_state: 'UNKNOWN',
      current_reason: 'NEUTRON_CURRENT_STALE',
    }],
    reason_codes: ['SG_DURING_IDENTITY_UNAVAILABLE'],
  }
}
