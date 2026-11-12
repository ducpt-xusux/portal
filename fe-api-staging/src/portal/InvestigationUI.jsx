import { useEffect, useState } from 'react'
import {
  mappingState,
  mapDecision,
  mapSgHistory,
  riskExposureState,
  currentMappingState,
} from '../services/portalApi'
import { Badge, display, FieldGrid, useTime } from './PortalUI'

function useObservationClock() {
  const [, tick] = useState(0)
  useEffect(() => {
    const timer = setInterval(() => tick((value) => value + 1), 5000)
    return () => clearInterval(timer)
  }, [])
  return Date.now()
}

export function VerifiedSource({ mapping, meta, error, compact = false }) {
  const time = useTime(),
    now = useObservationClock()
  const state = mappingState(mapping, meta, Boolean(error), now)
  return (
    <div className="v4-verification">
      <div>
        <Badge value={state.verification} />
        <Badge value={state.freshness} />
      </div>
      <small>Đối chiếu: {time(mapping?.observed_at)}</small>
      <small>
        TTL:{' '}
        {mapping?.ttl_seconds == null
          ? 'Chưa cung cấp'
          : `${mapping.ttl_seconds}s`}
      </small>
      {!compact && (
        <p className="v4-panel-note">
          {state.verification === 'VERIFIED'
            ? 'Danh tính nguồn được xác minh trong TTL. Trạng thái mạng vẫn cần quan sát Neutron riêng.'
            : "Chưa có đối chiếu được xác minh còn hiệu lực. Thông tin dưới đây được giữ theo nguồn."}
          {mapping?.reason && (
            <>
              <br />
              {mapping.reason}
            </>
          )}
        </p>
      )}
    </div>
  )
}

const mappingLabels = {
  MATCHED: 'Khớp IP hiện tại',
  AMBIGUOUS: 'Trùng nhiều port',
  NO_MATCH: 'Chưa tìm thấy VM',
  STALE: "Dữ liệu đối chiếu quá hạn",
  UNKNOWN: "Chưa đọc được đối chiếu",
}
const mappingReasons = {
  OPENSTACK_CONNECTION_FAILED: 'Chưa kết nối được API OpenStack.',
  OPENSTACK_NOT_CONFIGURED: 'Backend chưa cấu hình nguồn OpenStack.',
  MULTIPLE_CURRENT_PORT_MATCHES:
    "IP nguồn xuất hiện trên nhiều port; chưa đủ thông tin để chọn VM.",
  NO_CURRENT_PORT_MATCH_IN_PROJECT:
    'Không có port khớp IP trong project đang đọc.',
  PORT_NOT_ATTACHED_TO_KNOWN_COMPUTE_VM:
    'Port chưa gắn với VM compute có trong inventory.',
}

export function CurrentMapping({ mapping, error, compact = false }) {
  const time = useTime(),
    now = useObservationClock()
  const state = currentMappingState(mapping, Boolean(error), now)
  return (
    <div className="v4-verification">
      <div>
        <Badge
          value={
            state.state === 'MATCHED'
              ? 'FRESH'
              : state.state === 'AMBIGUOUS'
                ? 'REVIEW_REQUIRED'
                : state.state
          }
        >
          {mappingLabels[state.state]}
        </Badge>
        <Badge value={state.freshness} />
      </div>
      {state.href && (
        <a className="v4-id-link" href={state.href}>
          {mapping.server_name || mapping.server_id}
          {compact ? '' : " → Mở máy ảo / port"}
        </a>
      )}
      <small>
        Neutron: {time(mapping?.observed_at)} · TTL{' '}
        {mapping?.ttl_seconds == null ? '—' : `${mapping.ttl_seconds}s`}
      </small>
      <small>Danh tính lúc sự cố: chưa xác minh</small>
      {compact && state.state !== 'MATCHED' && (
        <small>
          {mappingReasons[mapping?.reason] ||
            mapping?.reason ||
            'Chưa có dữ liệu Neutron.'}
        </small>
      )}
      {!compact && (
        <>
          <p className="v4-panel-note">
            Đối chiếu IP với Nova/Neutron trong project hiện tại để điều hướng.
            IP có thể được cấp lại; kết quả này chưa chứng minh VM sở hữu IP tại
            thời điểm sự cố.
          </p>
          {mapping?.reason && mapping.reason !== 'UNIQUE_CURRENT_IP_MATCH' && (
            <p className="v4-panel-note">
              {mappingReasons[mapping.reason] || mapping.reason}
            </p>
          )}
          <FieldGrid
            rows={[
              ['VM tại lần quan sát', display(mapping?.server_name)],
              ["Mã máy ảo", display(mapping?.server_id)],
              ['Port', display(mapping?.port_id)],
              ['Project', display(mapping?.project_id)],
              ['Network', display(mapping?.network_id)],
              ["IP nội bộ", mapping?.fixed_ips?.join(' · ') || '—'],
              ['Floating IP', mapping?.floating_ips?.join(' · ') || '—'],
              ['Khớp theo', mapping?.matched_by?.join(' · ') || '—'],
              ['Số port khớp IP', display(mapping?.candidate_count)],
            ]}
          />
        </>
      )}
    </div>
  )
}

export function SecurityGroups({ groups = [], provided = true }) {
  if (!provided) return <span className="v4-muted">Chưa cung cấp SG</span>
  if (!groups.length)
    return <span className="v4-muted">Không có SG trong bản ghi</span>
  return (
    <ul className="v4-security-groups">
      {groups.map((group) => (
        <li key={group.id}>
          <strong>{group.name || 'Tên chưa cung cấp'}</strong>
          <code>{group.id}</code>
        </li>
      ))}
    </ul>
  )
}

export function SgHistory({ data }) {
  const time = useTime()
  const history = mapSgHistory(data)
  const rows = history.length
    ? history
    : [{ port_id: null, before: {}, during: {}, after: {} }]
  return (
    <div className="v4-sg-history">
      <h3 className="v4-subheading">
        Security Group trước / trong / sau hành động
      </h3>
      <p className="v4-panel-note">
        Các mốc đã ghi nhận là bằng chứng lịch sử; trạng thái hiện tại lấy từ
        quan sát Neutron ở trên.
      </p>
      {rows.map((row, index) => (
        <div
          className="v4-sg-history-record"
          key={`${row.action_id || ''}:${row.port_id || index}`}
        >
          <div className="v4-copy-row">
            <strong>Port: {row.port_id || 'Chưa cung cấp'}</strong>
            {row.action_id && (
              <a
                className="v4-text-link"
                href={`#/actions/${encodeURIComponent(row.action_id)}`}
              >
                {row.action_id}
              </a>
            )}
          </div>
          <div className="v4-sg-stages">
            {[
              ['before', 'Trước hành động'],
              ['during', 'Trong cách ly'],
              ['after', 'Sau khôi phục'],
            ].map(([key, label]) => (
              <article key={key}>
                <h4>{label}</h4>
                <SecurityGroups
                  groups={row[key].groups}
                  provided={row[key].provided === true}
                />
                <small>{time(row[key].observed_at)}</small>
                {row[key].source_ref && (
                  <code className="v4-provenance-ref">
                    {row[key].source_ref}
                  </code>
                )}
              </article>
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}

export function DecisionChecklist({ data }) {
  const decision = mapDecision(data)
  const checks = [
    ['qualified', "Bằng chứng đủ điều kiện"],
    ['source_verified', "Đối chiếu nguồn đã xác minh"],
    ['workload_allowed', "Máy ảo nằm trong lab / allowlist"],
    ['operator_approved', 'Phê duyệt của operator'],
    ['source_fresh', 'Nguồn đánh giá còn mới'],
  ]
  return (
    <>
      <ul className="v4-decision-checks">
        {checks.map(([key, label]) => (
          <li key={key}>
            <span>{label}</span>
            <Badge
              value={
                decision[key] === true
                  ? 'VERIFIED'
                  : decision[key] === false
                    ? 'REVIEW_REQUIRED'
                    : 'UNKNOWN'
              }
            >
              {decision[key] === true
                ? 'Đạt theo bản ghi'
                : decision[key] === false
                  ? 'Chưa đạt'
                  : 'Chưa cung cấp'}
            </Badge>
          </li>
        ))}
      </ul>
      <h3 className="v4-subheading">Lý do chưa cho phép phản ứng</h3>
      {decision.blocking_reasons.length ? (
        <ul className="v4-reasons">
          {decision.blocking_reasons.map((reason, index) => (
            <li key={index}>
              {reason.code && <code>{reason.code}</code>}
              {reason.message && <p>{reason.message}</p>}
              {!reason.code &&
                !reason.message &&
                'Chưa có lý do chi tiết từ nguồn.'}
            </li>
          ))}
        </ul>
      ) : (
        <p className="v4-panel-note">
          Chưa có lý do chi tiết được cung cấp. Không suy ra được phép cách ly
          từ việc thiếu lý do.
        </p>
      )}
      <p className="v4-panel-note">
        Kết quả dry-run không cấp quyền thực thi hoặc thay đổi trạng thái phát
        hiện .
      </p>
    </>
  )
}

export function RiskExposure({ exposure, meta, error, compact = false }) {
  const now = useObservationClock(),
    time = useTime()
  const state = riskExposureState(exposure, meta, Boolean(error), now)
  if (!exposure)
    return (
      <div className="v4-risk-exposure">
        <Badge value="UNKNOWN" />
        <small>Chưa có tổng hợp sự cố gần đây.</small>
      </div>
    )
  return (
    <div className="v4-risk-exposure">
      <div>
        <Badge value={state} />
        {exposure.severity && <Badge value={exposure.severity} />}
      </div>
      <strong>
        {display(exposure.incident_count)} sự cố trong cửa sổ nguồn
      </strong>
      <small>
        {time(exposure.window_from)} → {time(exposure.window_to)}
      </small>
      {!compact && (
        <>
          <FieldGrid
            rows={[
              ['Quan sát lúc', time(exposure.observed_at)],
              ["Tham chiếu nguồn", display(exposure.source_ref)],
            ]}
          />
          <div className="v4-link-list">
            {exposure.incident_refs.map((id) => (
              <a key={id} href={`#/incidents/${encodeURIComponent(id)}`}>
                {id}
              </a>
            ))}
          </div>
          <p className="v4-panel-note">
            Exposure chỉ phản ánh sự cố gần đây trong cửa sổ trên, không kết
            luận VM đã bị xâm nhập. Nhãn Chưa xác định/STALE giữ nguyên khi thiếu thời
            điểm hoặc TTL hợp lệ.
          </p>
        </>
      )}
    </div>
  )
}
