import { cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { IncidentWorkbenchView } from '../IncidentWorkbench.jsx'
import { PortalContext } from '../../../portal/PortalContext.js'
import { DetailView } from '../../../portal/DetailView.jsx'
import { EventInvestigationLinks } from '../../../portal/InvestigationFlow.jsx'
import recorded from './workbench-test-partial.json'

const remote = vi.hoisted(() => ({ data: null, projection: null, journal: null }))
vi.mock('../../../portal/ReviewEvidence.jsx', () => ({ EvidenceExports: () => null }))
vi.mock('../../../hooks/usePortalResource.js', () => ({
  default: (path) => ({
    data: path.startsWith('/events/') ? remote.projection : path.endsWith('/journal') ? remote.journal : remote.data,
    error: null,
    loading: false,
  }),
}))
afterEach(() => {
  cleanup()
  remote.data = null
  remote.projection = null
  remote.journal = null
})

it('keeps recorded detector flags collapsed while showing independent authorization and execution', () => {
  const payload = structuredClone(recorded)
  const { incident_id, stream_id } = payload.data.identity
  expect(payload.data.incident.isolation_authorized).toBe(false)
  remote.data = {
    configured: true,
    decisions: [{
      incident_id,
      stream_id,
      request_id: 'TEST-automatic-request',
      operation_id: 'TEST-operation',
      decided_at: '2026-11-18T00:01:00Z',
      state: 'QUARANTINED',
      evidence: {
        decision: 'AUTHORIZED',
        incident: { evidence: [] },
        checks: {},
        reason_codes: [],
      },
    }],
  }
  const page = (tab) => (
    <PortalContext.Provider value={{
      sessionAuthEnabled: true, timezone: 'UTC',
      auth: { status: 'authenticated', user: { roles: ['Analyst'] } },
    }}>
      <DetailView kind="incidents">
        <IncidentWorkbenchView id={incident_id} streamId={stream_id}
          params={{ wb_tab: tab }} resource={{ payload }} />
      </DetailView>
    </PortalContext.Provider>
  )
  const view = render(page('response'))
  expect(screen.getByRole('heading', { name: 'Máy ảo đang cách ly' })).toBeTruthy()
  expect(screen.getByText('Cấp phép cách ly')).toBeTruthy()
  for (const label of screen.queryAllByText('Chưa đầy đủ')) {
    expect(label.closest('details:not([open])')).toBeTruthy()
  }
  expect(screen.queryByText('Nguồn và phạm vi của hồ sơ')).toBeNull()
  fireEvent.click(screen.getByRole('button', { name: 'Xem đầy đủ' }))
  expect(screen.getByText('Nguồn và phạm vi của hồ sơ').closest('details').open).toBe(false)
  expect(screen.getByText('Cờ cấp phép trong hồ sơ phát hiện').nextElementSibling.textContent).toBe('Không')
  view.rerender(page('overview'))
  expect(screen.queryByText('Thông tin kỹ thuật do bộ phát hiện ghi nhận')).toBeNull()
  expect(screen.queryByText('Cờ cấp phép trong hồ sơ phát hiện')).toBeNull()
  expect(screen.queryByText('Được phép cách ly (bộ phát hiện)')).toBeNull()
})

it('shows only this decision and keeps earlier evaluations in full detail', () => {
  const payload = structuredClone(recorded)
  const { incident_id, stream_id } = payload.data.identity
  const event = { event_id: 'TEST-shared-event', request_id: 'TEST-shared-request' }
  const row = {
    incident_id, stream_id, request_id: 'TEST-later-evaluation',
    state: 'REVIEW_REQUIRED', policy_sha256: 'TEST-policy',
    evidence: {
      decision: 'REVIEW_REQUIRED', incident: { correlation_rule: 'CORR-001', evidence: [event] },
      checks: { incident_policy: 'FAIL' }, reason_codes: ['AUTO_RULE_NOT_APPROVED'],
    },
  }
  const related = {
    incident_id: 'TEST-related-incident', stream_id, operation_id: 'TEST-related-operation',
    request_id: 'TEST-related-evaluation', state: 'RESTORED',
    evidence: { decision: 'AUTHORIZED', incident: { correlation_rule: 'CORR-002', evidence: [event] } },
  }
  remote.data = {
    policy_sha256: 'TEST-policy', policy: { rule: 'CORR-002' },
    decisions: [row, { ...row, request_id: 'TEST-earlier-evaluation' }, related],
  }
  render(
    <PortalContext.Provider value={{
      sessionAuthEnabled: true, timezone: 'UTC',
      auth: { status: 'authenticated', user: { roles: ['Analyst'] } },
    }}>
      <DetailView kind="incidents">
        <IncidentWorkbenchView id={incident_id} streamId={stream_id}
          params={{ wb_tab: 'response' }} resource={{ payload }} />
      </DetailView>
    </PortalContext.Provider>,
  )
  const latest = screen.getByRole('region', { name: 'Kết quả ứng phó' })
  expect(within(latest).getByRole('heading', { name: 'Sự cố này không kích hoạt cách ly' })).toBeTruthy()
  expect(within(latest).getByRole('link', { name: 'Xem hồ sơ phát hiện' })
    .getAttribute('href')).toContain('wb_tab=detection')
  expect(within(latest).queryByRole('link', { name: 'Dấu hiệu chèn mã SQL lặp lại' })).toBeNull()
  expect(screen.queryByRole('region', { name: 'Truy vấn dùng để quyết định' })).toBeNull()
  expect(screen.queryByText('Các lần đánh giá trước (1)')).toBeNull()
  fireEvent.click(screen.getByRole('button', { name: 'Xem đầy đủ' }))
  const previous = screen.getByText('Các lần đánh giá trước (1)').closest('details')
  expect(previous.open).toBe(false)
})

it('shows all three observed timestamps for the exact operation and keeps technical details closed', () => {
  const payload = structuredClone(recorded)
  const { incident_id, stream_id } = payload.data.identity
  const hash = 'b'.repeat(64)
  remote.data = {
    configured: true,
    decisions: [{
      incident_id, stream_id, operation_id: 'verified-operation', request_id: 'test-request',
      decided_at: '2026-11-21T15:52:04Z', state: 'RESTORED', policy_sha256: hash,
      evidence: {
        decision: 'AUTHORIZED', checks: { incident_policy: 'PASS' }, reason_codes: [],
        policy_version: 'TEST-policy-version',
        source_verification: { server_id: 'target-vm' },
        incident: {
          correlation_rule: 'CORR-002', evidence_count_recorded: 1,
          evidence: [{ event_id: 'test-event', request_id: 'test-query', seq: 1019, p15: 100 }],
        },
      },
    }],
  }
  remote.journal = {
    operations: [
      { server_id: 'other-vm', operation_id: 'verified-operation', quarantined_at: '2026-11-21T15:51:00Z' },
      {
        server_id: 'target-vm', operation_id: 'verified-operation', state: 'RESTORED',
        quarantined_at: '2026-11-21T15:52:05Z', restored_at: '2026-11-21T15:56:22Z', restore_trigger: 'MANUAL',
      },
    ],
  }
  const page = (tab) => (
    <PortalContext.Provider value={{
      sessionAuthEnabled: true, timezone: 'Asia/Ho_Chi_Minh',
      auth: { status: 'authenticated', user: { roles: ['Analyst'] } },
    }}>
      <DetailView kind="incidents">
        <IncidentWorkbenchView id={incident_id} streamId={stream_id} params={{ wb_tab: tab }} resource={{ payload, history: [] }} />
      </DetailView>
    </PortalContext.Provider>
  )
  const view = render(page('response'))
  const timeline = screen.getByRole('list', { name: 'Các mốc xử lý đã ghi nhận' })
  expect(within(timeline).getAllByRole('listitem').map((step) => step.querySelector('time')?.dateTime)).toEqual([
    '2026-11-21T15:52:04Z', '2026-11-21T15:52:05Z', '2026-11-21T15:56:22Z',
  ])
  expect(screen.getByRole('heading', { name: 'Đã khôi phục máy ảo' })).toBeTruthy()
  const basis = screen.getByText('Căn cứ quyết định').closest('details')
  expect(within(basis).getByText('Chính sách đã dùng')).toBeTruthy()
  expect(within(basis).getByText('Điều kiện đã đạt')).toBeTruthy()
  expect(screen.queryByText(hash)).toBeNull()
  fireEvent.click(screen.getByRole('button', { name: 'Xem đầy đủ' }))
  const details = screen.getByText('Mã hồ sơ và chính sách').closest('details')
  expect(details.open).toBe(false)
  expect(within(details).getByText(hash).tagName).toBe('CODE')
  expect(screen.getByText('Chi tiết đối chiếu').closest('details').open).toBe(false)
  view.rerender(page('detection'))
  for (const heading of ['Cách liên kết truy vấn với sự cố', 'Cấu hình bộ phát hiện', 'Nguồn và phạm vi của hồ sơ']) {
    expect(screen.queryByText(heading)).toBeNull()
  }
})

it('links an event back to its incident only for the same stream, event and request', () => {
  const event = { stream_id: 'TEST-stream', event_id: 'TEST-event', request_id: 'TEST-request' }
  remote.projection = { ...event, request_id: 'OTHER-request', incident_refs: ['TEST-incident'],
    incident_membership: 'DIRECT_PERSISTED' }
  const page = () => (
    <PortalContext.Provider value={{ mode: 'v4', auth: { status: 'authenticated' } }}>
      <EventInvestigationLinks event={event} />
    </PortalContext.Provider>
  )
  const view = render(page())
  expect(screen.queryByRole('link', { name: 'TEST-incident' })).toBeNull()
  remote.projection = { ...remote.projection, request_id: event.request_id }
  view.rerender(page())
  expect(screen.getByRole('link', { name: 'TEST-incident' }).getAttribute('href'))
    .toBe('#/incidents/TEST-incident?stream_id=TEST-stream&wb_tab=detection')
})
