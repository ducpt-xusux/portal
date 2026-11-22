import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import { DetailView } from './DetailView'
import { FieldGrid, PageHeading } from './PortalUI'
import { AnalysisPage } from '../features/n91-vnext/AnalysisPage'
import { EventDetail, EventsPage, EventTable } from './EventPages'
import { CurrentMapping } from './InvestigationUI'
import { mapEvent, mapIncident, mapWorkload } from '../services/portalApi'
import { WorkloadDetail, WorkloadsPage } from './WorkloadPages'
import N91CompactDashboard from './N91CompactDashboard'
import GaleraPanel from './GaleraPanel'
import ReportEvidencePanel from './ReportEvidencePanel'
import ReportEventEvidence from './ReportEventEvidence'
import SystemPage from './SystemPage'

const state = vi.hoisted(() => ({ resources: {} }))
vi.mock('./PortalContext', () => ({ usePortal: () => ({ timezone: 'UTC', sessionAuthEnabled: true,
  workloadQuarantineAvailable: true, auth: { status: 'authenticated', csrfToken: 'TEST-csrf', user: { roles: ['Executor'] } } }), useSourceDisplay: () => ({}) }))
vi.mock('./IncidentPages', () => ({
  useV4Resource: (path, options = {}) => {
    const item = options.enabled === false ? {} : state.resources[path] || {}
    const chosen = item.byIncident ? item.byIncident[options.params?.incident_ref]
      : item.bySignal ? item.bySignal[options.params?.signal_rule]
      : item.bySource ? item.bySource[options.params?.source || 'p17'] : item
    return { data: null, loading: false, error: null, meta: null, refresh: vi.fn(), ...chosen }
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
    expect(screen.getByText('Primary')).toBeTruthy()
    expect(screen.getByText('Synced')).toBeTruthy()
    expect(screen.queryByRole('columnheader', { name: 'Sẵn sàng / kết nối cụm' })).toBeNull()
    view.rerender(<GaleraPanel standalone />)
    expect(screen.getByText('Cụm chính')).toBeTruthy()
    expect(screen.getByText('Đã đồng bộ')).toBeTruthy()
    expect(screen.getByText('Bật / Bật')).toBeTruthy()
    expect(screen.getAllByText(/15:55:00/).length).toBeGreaterThan(0)
  })

  it('shows timing and diagnostics per data source', () => {
    const observed = new Date().toISOString()
    state.resources['/system/data-sources'] = {
      meta: { read_at: observed, source_mode: 'STATUS_REPORT', freshness_state: 'FRESH' },
      data: [{ source_system: 'Proxy systemd snapshot', source_schema: 'portal-proxy-services-1',
        freshness_state: 'FRESH', observation_freshness_state: 'FRESH', coverage_state: 'PARTIAL',
        observation_to: observed, last_attempt: observed, last_success: observed, last_error_code: 'TEST_PARTIAL' }],
    }
    render(<SystemPage tab="sources" />)
    const card = within(screen.getByRole('article'))
    expect(card.getByRole('heading', { name: 'Trạng thái dịch vụ trên Proxy' })).toBeTruthy()
    expect(card.getByText('Chưa đầy đủ', { selector: '.v4-badge' })).toBeTruthy()
    expect(card.getByText('Dữ liệu đến').nextElementSibling.dateTime).toBe(observed)
    expect(card.getByText('TEST_PARTIAL').closest('details').open).toBe(false)
  })

  it('keeps the Proxy snapshot timestamp in source details only', () => {
    const observed = new Date().toISOString()
    state.resources['/system/proxy-services'] = {
      meta: { source_mode: 'SNAPSHOT', scope: 'SYSTEMD_STATUS_ONLY', source_ref: 'TEST-source',
        freshness_state: 'FRESH', data_as_of: observed, read_at: observed },
      data: [],
    }
    render(<SystemPage />)
    expect(screen.queryByText('Bản chụp lúc', { exact: false })).toBeNull()
    expect(screen.queryByText('Bản ghi lịch sử')).toBeNull()
    expect(screen.getByText('Dữ liệu đến').closest('details').querySelector('summary').textContent).toBe('Thông tin nguồn')
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
    expect(screen.getByText('Port 1')).toBeTruthy()
    expect(screen.getByText('Ứng phó tự động theo chính sách thử nghiệm')).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Khôi phục' }).disabled).toBe(false)
    expect(screen.getByRole('link', { name: 'Xem quyết định, xác minh nguồn và bằng chứng' })
      .closest('.vm-control-panel')).toBeTruthy()
  })

  it('lists source Security Group names once per VM across its ports', () => {
    const group = { id: 'TEST-group-id', name: 'sg-management' }
    state.resources['/workloads'] = {
      data: [mapWorkload({
        server_id: 'TEST-vm', name: 'p17-lab-clone',
        ports: [
          { port_id: 'test-port-a', security_group_ids: [group.id] },
          { port_id: 'test-port-b', security_groups: [group, { id: 'TEST-app', name: 'sg-app' }] },
        ],
      })],
    }
    render(<WorkloadsPage params={{}} />)
    const row = within(screen.getByRole('row', { name: /Attack/ }))
    expect(row.getAllByText('sg-management')).toHaveLength(1)
    expect(row.getByText('sg-app')).toBeTruthy()
    expect(row.queryByText(group.id)).toBeNull()
  })

  it('shows Nova and network status from a fresh Controller inventory export', () => {
    const observed = new Date().toISOString()
    state.resources['/workloads'] = {
      meta: { source_mode: 'REMOTE_READONLY', source_schema: 'openstack-inventory-1',
        collection_mode: 'SSH_EXPORT', freshness_state: 'FRESH', read_at: observed, data_as_of: observed,
        stale_after_seconds: 45, network_stale_after_seconds: 45, refresh_seconds: 8 },
      data: [mapWorkload({ server_id: 'TEST-vm', name: 'TEST-node', nova_status: 'ACTIVE',
        network_observation: { observed_at: observed, state: 'NORMAL', verification: 'LIVE_NEUTRON_READ' } })],
    }
    const view = render(<WorkloadsPage params={{}} />)
    expect(screen.getByText('Đang hoạt động')).toBeTruthy()
    const row = within(screen.getByRole('row', { name: /TEST-node/ }))
    expect(row.getByText('Bình thường')).toBeTruthy()
    expect(screen.getByText('Nguồn OpenStack')).toBeTruthy()

    state.resources['/workloads'].meta.freshness_state = 'STALE'
    view.rerender(<WorkloadsPage params={{}} />)
    expect(screen.queryByText('Đang hoạt động')).toBeNull()
    expect(row.getAllByText('Dữ liệu cũ')).toHaveLength(2)
  })

  it('shows the VM link alone for a fresh match in the incident list', () => {
    const observed = new Date().toISOString()
    const mapping = {
      state: 'MATCHED', server_id: 'TEST-vm', server_name: 'p17-lab-clone', port_id: 'TEST-port',
      observation_from: observed, observed_at: observed, ttl_seconds: 45,
      source: { source_mode: 'LIVE', read_at: observed, stale_after_seconds: 45, freshness_state: 'FRESH' },
    }
    const view = render(<CurrentMapping compact mapping={mapping} />)
    expect(screen.getByRole('link', { name: 'Attack' }).getAttribute('href')).toBe('#/workloads/TEST-vm?port_id=TEST-port')
    expect(screen.queryByText(/Khớp IP/)).toBeNull()

    view.rerender(<CurrentMapping compact mapping={{ ...mapping, state: 'NO_MATCH' }} />)
    expect(screen.queryByRole('link')).toBeNull()
    expect(screen.getByText('Chưa tìm thấy VM')).toBeTruthy()
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

  it('gives each detected signal and matched rule its own list item', () => {
    const eventId = 'test-analysis-event'
    state.resources[`/p17-vnext/events/${eventId}`] = {
      data: {
        event_id: eventId,
        trace: {
          p14: { matched_rules: ['TEST-rule-1', 'TEST-rule-2'] },
          p17: { matched_signals: ['CORR-001', 'CORR-012'] },
        },
      },
    }
    render(<AnalysisPage params={{ event_id: eventId }} />)
    const items = (name) => within(screen.getByRole('heading', { name }).closest('section'))
      .getAllByRole('listitem').map((item) => item.textContent)
    expect(items('Phát hiện hành vi')).toEqual([
      'Vi phạm chính sách lặp lại',
      'Truy cập từ nguồn không được phép',
    ])
    expect(items('Kiểm soát truy vấn')).toEqual(['TEST-rule-1', 'TEST-rule-2'])
  })

  it('uses the same visible group label and evidence link for events in the same incident', () => {
    const shared = { incident_id: 'INC-test11111111', signal_rule: 'CORR-002' }
    const second = { incident_id: 'INC-test22222222', signal_rule: 'CORR-001' }
    const events = [
      mapEvent({ stream_id: 'test-stream', event_id: 'test-1', recorded_incidents: [shared] }),
      mapEvent({ stream_id: 'test-stream', event_id: 'test-2', recorded_incidents: [shared, second] }),
      mapEvent({ stream_id: 'test-stream', event_id: 'test-3', recorded_incidents: [] }),
    ]
    render(<EventTable events={events} />)
    const sameGroup = screen.getAllByRole('link', { name: /Nhóm 11111111/ })
    expect(sameGroup).toHaveLength(2)
    expect(sameGroup[0].dataset.tone).toBe(sameGroup[1].dataset.tone)
    expect(sameGroup[1].getAttribute('href')).toBe('#/events?view=incidents&incident_ref=INC-test11111111&stream_id=test-stream')
    expect(screen.getByRole('link', { name: /Nhóm 22222222/ })).toBeTruthy()
    expect(screen.getByText('Chưa có liên kết')).toBeTruthy()
  })

  it('shows each incident with only its recorded members, including evidence shared by two incidents', () => {
    const streamId = 'test-stream'
    const sql = 'INC-test11111111'
    const policy = 'INC-test22222222'
    const incident = (id, rule, count) => mapIncident({
      incident_id: id, stream_id: streamId, signal_rule: rule, evidence_count: count,
      evidence_membership: 'DIRECT_PERSISTED',
    })
    const event = (id, refs) => mapEvent({ stream_id: streamId, event_id: id, incident_refs: refs })
    const shared = event('aaaaaaaa-event', [sql, policy])
    const policyOnly = event('bbbbbbbb-event', [policy])
    state.resources['/incidents'] = { data: [incident(sql, 'CORR-002', 1), incident(policy, 'CORR-001', 2)] }
    state.resources['/events'] = { byIncident: {
      [sql]: { data: [shared], meta: { total_count: 1 } },
      [policy]: { data: [policyOnly, shared], meta: { total_count: 2 } },
    } }
    const view = render(<EventsPage params={{}} />)
    const sqlMembers = within(screen.getByRole('region', { name: 'Dấu hiệu chèn mã SQL lặp lại' }))
    expect(sqlMembers.getByRole('link', { name: 'aaaaaaaa-event' })).toBeTruthy()
    expect(sqlMembers.queryByRole('link', { name: 'bbbbbbbb-event' })).toBeNull()
    expect(sqlMembers.getByText('Bằng chứng do bộ phát hiện lưu')).toBeTruthy()
    const policyGroup = screen.getByRole('link', { name: /Vi phạm chính sách lặp lại/ })
    const selectedParams = Object.fromEntries(new URLSearchParams(policyGroup.getAttribute('href').split('?')[1]))
    view.rerender(<EventsPage params={selectedParams} />)
    const policyMembers = within(screen.getByRole('region', { name: 'Vi phạm chính sách lặp lại' }))
    expect(policyMembers.getByRole('link', { name: 'aaaaaaaa-event' })).toBeTruthy()
    expect(policyMembers.getByRole('link', { name: 'bbbbbbbb-event' })).toBeTruthy()
    expect(policyMembers.getByText('2 sự kiện')).toBeTruthy()
    view.rerender(<EventsPage params={{ ...selectedParams, stream_id: 'other-stream' }} />)
    expect(screen.getByText('Không tìm thấy sự cố trong luồng dữ liệu này')).toBeTruthy()
    expect(screen.queryByRole('table')).toBeNull()
  })

  it('filters grouped events by the detector signal across the source history', () => {
    const stream = 'test-stream'
    const incidentId = 'INC-test-sensitive'
    state.resources['/incidents'] = { bySignal: {
      'CORR-003': { data: [mapIncident({
        incident_id: incidentId, stream_id: stream, signal_rule: 'CORR-003',
        evidence_count: 1, evidence_membership: 'RECONSTRUCTED_WINDOW',
      })] },
      'CORR-004': { data: [] },
    } }
    state.resources['/events'] = { byIncident: {
      [incidentId]: { data: [mapEvent({
        event_id: 'test-member', stream_id: stream, incident_refs: [incidentId],
      })] },
    } }
    state.resources['/p17-vnext/cases'] = { data: [
      { case_id: 'test-mixed', stream_id: stream, source_ip: '192.0.2.10', signals: ['CORR-004'] },
      { case_id: 'test-other', stream_id: stream, source_ip: '192.0.2.11', signals: ['CORR-001'] },
    ] }
    const view = render(<EventsPage params={{ view: 'incidents', signal_rule: 'CORR-003' }} />)
    const picker = screen.getByRole('combobox', { name: 'Loại sự cố' })
    expect(picker.value).toBe('CORR-003')
    expect(screen.getByRole('link', { name: /Truy cập dữ liệu nhạy cảm lặp lại/ }).getAttribute('href'))
      .toBe(`#/events?view=incidents&incident_ref=${incidentId}&stream_id=${stream}&signal_rule=CORR-003`)
    expect(screen.getByText('Đối chiếu theo mốc thời gian')).toBeTruthy()
    expect(screen.getByRole('link', { name: 'test-member' })).toBeTruthy()
    view.rerender(<EventsPage params={{ view: 'incidents', signal_rule: 'CORR-004' }} />)
    expect(screen.getByText('Chưa có hồ sơ sự cố loại này')).toBeTruthy()
    expect(screen.getByRole('link', { name: 'Mở phân tích · 192.0.2.10' }).getAttribute('href'))
      .toBe(`#/incidents?analysis=1&case_id=test-mixed&stream_id=${stream}`)
    expect(screen.queryByRole('link', { name: 'Mở phân tích · 192.0.2.11' })).toBeNull()
    expect(screen.queryByRole('table')).toBeNull()
  })

  it('translates audit reasons while keeping raw identifiers in the report fields', () => {
    const hash = 'a'.repeat(64)
    render(<ReportEventEvidence event={{
      risk: { status: 'OK', score: 80 },
      source_provenance: { payload_sha256: hash },
      score_breakdown: [
        { rule_id: 'INJ-001', category: 'injection', score: 40, reason: 'Tautological predicate detected' },
        { rule_id: 'ALLOW-READER-001', category: 'allow', score: 0, reason: 'Approved reader workload' },
      ],
    }} />)
    expect(screen.getByText('Phát hiện điều kiện luôn đúng')).toBeTruthy()
    expect(screen.getByText('Truy vấn thuộc phạm vi đọc được phép')).toBeTruthy()
    expect(screen.queryByText('Tautological predicate detected')).toBeNull()
    const details = screen.getByText('Trường kiểm toán theo báo cáo').closest('summary').parentElement
    expect(details.open).toBe(false)
    expect(within(details).getByText(hash).tagName).toBe('CODE')
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
