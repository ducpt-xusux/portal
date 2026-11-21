import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { DetailView } from './DetailView'
import { FieldGrid, PageHeading } from './PortalUI'
import { AnalysisPage } from '../features/n91-vnext/AnalysisPage'
import { EventDetail } from './EventPages'
import { mapEvent } from '../services/portalApi'
import { WorkloadDetail } from './WorkloadPages'
import N91CompactDashboard from './N91CompactDashboard'
import GaleraPanel from './GaleraPanel'
import ReportEvidencePanel from './ReportEvidencePanel'

const state = vi.hoisted(() => ({ resources: {} }))
vi.mock('./PortalContext', () => ({ usePortal: () => ({ timezone: 'UTC', sessionAuthEnabled: true,
  workloadQuarantineAvailable: true, auth: { status: 'authenticated', csrfToken: 'TEST-csrf', user: { roles: ['Executor'] } } }), useSourceDisplay: () => ({}) }))
vi.mock('./IncidentPages', () => ({
  useV4Resource: (path, options = {}) => {
    const item = state.resources[path] || { data: null }
    const chosen = item.bySource ? item.bySource[options.params?.source || 'p17'] : item
    return { loading: false, error: null, meta: null, refresh: vi.fn(), ...chosen }
  },
  useCursor: () => ({ history: [] }),
}))
afterEach(cleanup)
beforeEach(() => { state.resources = {} })

describe('native Proxy UI integration', () => {
  it('renders Galera source data and preserves its sample timestamps on the dashboard and system page', () => {
    const observed = '2026-11-21T15:55:00Z'
    const scope = { source_mode: 'SNAPSHOT', scope: 'LOCAL_SOCKET_WSREP' }
    state.resources['/system/galera'] = {
      meta: { ...scope, collection_mode: 'PERIODIC', freshness_state: 'FRESH' },
      data: { summary: { current_status: 'HEALTHY', observed_nodes: 1, expected_nodes: 3 },
        nodes: [{ ...scope, node_id: 'galera-1', read_ok: true, source_ref: 'TEST-source',
          observed_at: observed, observation_freshness_state: 'FRESH', wsrep_cluster_size: 3,
          wsrep_cluster_status: 'Primary', wsrep_local_state_comment: 'Synced', wsrep_ready: 'ON',
          wsrep_connected: 'ON' }] },
    }
    const view = render(<N91CompactDashboard />)
    expect(screen.getByText('Cụm chính')).toBeTruthy()
    expect(screen.getByText('Bật / Bật')).toBeTruthy()
    view.rerender(<GaleraPanel standalone />)
    expect(screen.getByText('Cụm chính')).toBeTruthy()
    expect(screen.getByText('Đã đồng bộ')).toBeTruthy()
    expect(screen.getByText('Bật / Bật')).toBeTruthy()
    expect(screen.getAllByText(/15:55:00/).length).toBeGreaterThan(0)
  })

  it('shows Vietnamese report field names and retains source zero, false and hash', () => {
    const hash = 'a'.repeat(64)
    state.resources['/system/report-evidence'] = { data: { artifacts: [{ evidence_id: 'TEST-report',
      title: 'TLS thử nghiệm', scope: 'Thử nghiệm', source_sha256: hash,
      facts: [{ key: 'GALERA_1_TLS_VERSION', value: 'TLSv1.3' }, { key: 'BLOCKED_REQUEST_COUNT', value: 0 },
        { key: 'BUSINESS_WRITES', value: false }, { key: 'BACKUP_SHA256', value: hash }],
    }] } }
    render(<ReportEvidencePanel />)
    expect(screen.getByText('Galera 1 · Phiên bản TLS')).toBeTruthy()
    expect(screen.getByText('TLSv1.3')).toBeTruthy()
    expect(screen.getByText('0')).toBeTruthy()
    expect(screen.getByText('Không')).toBeTruthy()
    expect(screen.getAllByText(hash)).toHaveLength(2)
  })

  it('renders live VM ports and the Controller operation in their separate panels', () => {
    const id = 'TEST-vm'; const port = { port_id: 'TEST-port', fixed_ips: ['192.0.2.10'], floating_ips: [],
      fixed_ip_details: [], security_groups: [], security_groups_provided: true, network_state: 'QUARANTINED' }
    state.resources[`/workloads/${id}`] = { data: { server_id: id, name: 'TEST-clone', incident_refs: [], ports: [port],
      network_observation: { state: 'QUARANTINED' } } }
    state.resources[`/workloads/${id}/ports`] = { data: [port] }
    state.resources[`/workloads/${id}/quarantine`] = { data: { allowed: true, state: 'QUARANTINED',
      automatic_response: true, incident_id: 'TEST-incident', policy_version: 'TEST-policy', operation_id: 'TEST-operation' } }
    render(<WorkloadDetail id={id} />)
    expect(screen.getByText('Cổng mạng 1')).toBeTruthy()
    expect(screen.getByText('Ứng phó tự động theo chính sách thử nghiệm')).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Khôi phục' }).disabled).toBe(false)
    expect(screen.getByRole('link', { name: 'Xem quyết định, xác minh nguồn và bằng chứng' })
      .closest('.vm-control-panel')).toBeTruthy()
  })
  it('has one title action and restores full fields without losing zero', () => {
    render(<DetailView kind="events"><PageHeading title="Chi tiết sự kiện" /><FieldGrid rows={[
      ['Điểm rủi ro', 0], ['Mã yêu cầu nội bộ', 'test-request'],
    ]} /></DetailView>)
    expect(screen.getAllByRole('button', { name: 'Xem đầy đủ' })).toHaveLength(1)
    expect(screen.getByText('0')).toBeTruthy()
    expect(screen.queryByText('test-request')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Xem đầy đủ' }))
    expect(screen.getByText('test-request')).toBeTruthy()
    expect(screen.getAllByRole('button', { name: 'Xem gọn' })).toHaveLength(1)
  })

  it('filters real returned cases and never synthesizes cases on a 503', () => {
    state.resources['/p17-vnext/cases'] = { data: { cases: [
      { case_id: 'case-a', source_ip: '192.0.2.10', signals: ['CORR-002'], evidence_count: 3, peak_p15: 100 },
      { case_id: 'case-b', source_ip: '192.0.2.20', evidence_count: 0, peak_p15: 0 },
    ] } }
    const view = render(<AnalysisPage params={{}} />)
    expect(screen.getAllByRole('link', { name: 'Xem hồ sơ →' })).toHaveLength(2)
    fireEvent.change(screen.getByRole('searchbox'), { target: { value: '192.0.2.20' } })
    expect(screen.getAllByRole('link', { name: 'Xem hồ sơ →' })).toHaveLength(1)
    expect(screen.getByText(/0 truy vấn làm bằng chứng/)).toBeTruthy()
    state.resources['/p17-vnext/cases'] = { error: { status: 503, code: 'VNEXT_SOURCE_NOT_CONFIGURED' } }
    view.rerender(<AnalysisPage params={{}} />)
    expect(screen.getByRole('alert').textContent).toContain('VNEXT_SOURCE_NOT_CONFIGURED')
    expect(screen.queryByRole('link', { name: 'Xem hồ sơ →' })).toBeNull()
  })

  it('rejects conflicting Canonical identity and does not display its masked SQL', () => {
    const event = mapEvent({ event_id: 'event-1', stream_id: 'stream-1', source_ip: '192.0.2.10', occurred_at: '2026-11-18T00:00:00Z', decision: 'ALLOW', risk: { score: 0, status: 'OK' }, view_kind: 'P17_EVENT_PROJECTION' })
    const canonical = { ...event, view_kind: 'P16H_CANONICAL_AUDIT', source_ip: '192.0.2.20', masked_query: 'SELECT masked_conflicting_source' }
    state.resources['/events/event-1'] = { bySource: { p17: { data: event }, canonical: { data: canonical } } }
    render(<DetailView kind="events"><EventDetail id="event-1" params={{ source: 'p17' }} /></DetailView>)
    expect(screen.getByText('Chưa xác minh được sự tương ứng giữa hai bản ghi.')).toBeTruthy()
    expect(screen.queryByText('SELECT masked_conflicting_source')).toBeNull()
    expect(screen.getAllByRole('button', { name: 'Xem đầy đủ' })).toHaveLength(1)
    expect(screen.getByText('0')).toBeTruthy()
  })
})
