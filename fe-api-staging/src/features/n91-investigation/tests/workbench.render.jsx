import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import assert from 'node:assert/strict'
import { IncidentWorkbenchView } from '../IncidentWorkbench.jsx'
import { IncidentBusinessPanel } from '../../n91-business/IncidentBusinessPanel.jsx'
import { PortalContext } from '../../../portal/PortalContext.js'
import { BusinessSessionBridge } from '../../n91-business/BusinessSession.jsx'
import { historyFixture } from './responseHistoryFixture.js'

export function runRenderCases(fixture) {
  let checks = 0
  const pair = fixture.data.identity
  const observation = {
    timezone: 'UTC',
    sessionAuthEnabled: false,
    auth: { status: 'local_snapshot' },
  }
  const base = {
    payload: fixture,
    loading: false,
    error: null,
    notice: '',
    history: [],
    refresh() {},
    next() {},
    previous() {},
    first() {},
  }
  const render = (tab, { portal = observation, resource = base, businessSession } = {}) => {
    const workbench = (
      <IncidentWorkbenchView
        id={pair.incident_id}
        streamId={pair.stream_id}
        params={{ wb_tab: tab }}
        resource={resource}
      />
    )
    return renderToStaticMarkup(
      <PortalContext.Provider value={portal}>
        {businessSession ? (
          <BusinessSessionBridge {...businessSession}>{workbench}</BusinessSessionBridge>
        ) : workbench}
      </PortalContext.Provider>
    )
  }
  for (const tab of [
    'overview',
    'timeline',
    'detection',
    'response',
    'notes',
  ]) {
    const html = render(tab)
    assert.equal((html.match(/role="tab"/g) || []).length, 5)
    assert.equal((html.match(/aria-selected="true"/g) || []).length, 1)
    assert.match(html, /role="tabpanel"/)
    assert.match(html, /Nguồn đã xác minh/)
    assert.match(html, /Được phép cách ly/)
    assert.match(html, /Cao/)
    assert.doesNotMatch(html, /undefined|NaN|<form/)
    checks++
  }
  const detectionCases = [
    ['DETECTOR_PROFILE_UNAVAILABLE', /Thiếu phiên bản hoặc mã SHA256/],
    ['DETECTOR_PROFILE_MISMATCH', /Phiên bản hoặc mã SHA256 không khớp/],
    ['DETECTOR_PROFILE_INCOMPLETE', /Định danh khớp hồ sơ ngày 10\/11/],
  ]
  for (const [reason, expectedText] of detectionCases) {
    const payload = structuredClone(fixture)
    payload.data.detection.reason_codes[0] = reason
    const html = render('detection', { resource: { ...base, payload } })
    assert.match(html, expectedText)
    assert.match(html, /Số bằng chứng P17 ghi nhận/)
    assert.match(html, /Ứng viên tái dựng/)
    assert.match(html, /Liên kết trực tiếp<\/span><strong>—<\/strong>/)
    assert.match(html, /Liên kết dựng lại theo cửa sổ thời gian/)
    assert.doesNotMatch(html, /DETECTOR_PROFILE_|Ngưỡng tương quan|Yêu cầu đủ điều kiện/)
    checks++
  }
  const timeline = render('timeline')
  assert.match(timeline, /1 · Phát hiện/)
  assert.match(timeline, /2 · Quyết định/)
  assert.match(timeline, /3 · Xử lý/)
  assert.match(timeline, /Liên kết dựng lại theo cửa sổ thời gian/)
  assert.match(timeline, /Chưa xác định phiên bản bộ phát hiện/)
  assert.ok(
    timeline.indexOf('Phân trang sự kiện nghi vấn') <
      timeline.indexOf('class="n91-wb-event"')
  )
  assert.match(timeline, /<details class="n91-wb-event"><summary>/)
  checks++
  const historyPayload = structuredClone(fixture)
  historyPayload.data.response = historyFixture(pair.incident_id, pair.stream_id)
  const responseHistory = render('response', { resource: { ...base, payload: historyPayload } })
  assert.match(responseHistory, /20,125 giây/)
  assert.match(responseHistory, /Chưa có đủ hai mốc thời gian/)
  assert.match(responseHistory, /Đã quan sát tập SG rỗng/)
  assert.match(responseHistory, /Chưa có quan sát/)
  assert.match(responseHistory, /Quan sát Neutron đã hết hạn/)
  assert.match(render('response'), /#\/incidents\?response_history=1/)
  checks++
  const viewer = render('timeline', {
    portal: {
      ...observation,
      sessionAuthEnabled: true,
      auth: { status: 'authenticated', user: { roles: ['Viewer'] } },
    },
  })
  assert.doesNotMatch(viewer, /TEST-event|Nguồn đã xác minh|role="tab"/)
  assert.match(viewer, /quyền đọc bằng chứng/)
  checks++
  const denied = render('timeline', {
    resource: {
      ...base,
      payload: null,
      error: {
        status: 403,
        code: 'INVESTIGATION_FORBIDDEN',
        message: 'Denied',
      },
    },
  })
  assert.doesNotMatch(denied, /TEST-event|Nguồn đã xác minh/)
  assert.match(denied, /Dữ liệu điều tra đã được ẩn/)
  checks++
  const stale = render('overview', {
    resource: {
      ...base,
      error: {
        status: 503,
        code: 'TEST_SOURCE_OFFLINE',
        message: 'Unavailable',
      },
    },
  })
  assert.match(stale, /Chưa cập nhật/)
  assert.match(stale, /bản đọc thành công trước/)
  assert.match(stale, /Nguồn đã xác minh/)
  checks++
  const notes = render('notes')
  assert.match(notes, /Chưa có dữ liệu/)
  assert.match(notes, /Chế độ quan sát chỉ đọc/)
  assert.doesNotMatch(notes, /<form|<textarea/)
  checks++
  const sessionPayload = structuredClone(fixture)
  sessionPayload.data.analyst_case = {
    availability: 'AVAILABLE',
    overlay: {
      kind: 'incident', object_id: pair.incident_id, stream_id: pair.stream_id,
      execution_mode: 'TEST', review_state: 'UNREAD', acknowledged: false,
      assignee_id: null, priority: 'UNSET', version: 0, updated_at: null,
      actor_id: null, owner: 'PORTAL_ANNOTATION', source_status_changed: false,
    },
    write_enabled: false,
    reason_codes: [],
  }
  const analystCase = render('notes', {
    portal: { ...observation, sessionAuthEnabled: true,
      auth: { status: 'authenticated', user: { roles: ['Analyst'] } } },
    resource: { ...base, payload: sessionPayload },
    businessSession: {
      status: 'authenticated', session: { roles: ['Analyst'] },
      capabilities: { can_triage: true, can_read_notes: true }, client: { adoptSession() {} },
    },
  })
  assert.match(analystCase, /Hồ sơ xử lý sự cố/)
  assert.match(analystCase, /Đang tải hồ sơ xử lý/)
  assert.doesNotMatch(analystCase, /ĐIỀU TRA · CHỈ ĐỌC/)
  checks++
  const exportView = {
    portal: { ...observation, sessionAuthEnabled: true,
      auth: { status: 'authenticated', user: { roles: ['Analyst'] } } },
    businessSession: {
      status: 'authenticated', session: { roles: ['Analyst'], csrf_token: 'TEST-csrf' },
      capabilities: { can_export_evidence: true }, client: { adoptSession() {} },
    },
  }
  assert.match(render('overview', exportView), /Tải JSON/)
  assert.match(render('overview', exportView), /Tải CSV/)
  assert.doesNotMatch(render('overview', exportView), /disabled=""[^>]*>[^<]*Tải CSV/)
  assert.doesNotMatch(render('overview'), /Tải CSV/)
  assert.doesNotMatch(render('overview', { ...exportView,
    businessSession: { ...exportView.businessSession, capabilities: { can_read_notes: true } },
  }), /Tải JSON/)
  const failedSource = render('overview', {
    ...exportView, resource: { ...base, error: { status: 503, code: 'TEST_SOURCE_UNAVAILABLE' } },
  })
  assert.match(failedSource, /Hãy đọc lại dữ liệu nguồn để bật chức năng xuất/)
  checks++
  const readonly = renderToStaticMarkup(
    <BusinessSessionBridge
      status="authenticated"
      session={{ roles: ['Analyst'] }}
      capabilities={{ can_triage: true, can_read_notes: true }}
      client={{ adoptSession() {} }}
    >
      <IncidentBusinessPanel
        id={pair.incident_id}
        streamId={pair.stream_id}
        readOnly
      />
    </BusinessSessionBridge>
  )
  assert.doesNotMatch(readonly, /<form|<textarea|Thêm ghi chú|Lưu rà soát/)
  checks++
  return { checks, kind: 'REACT_SSR', browser_interaction_verified: false }
}
