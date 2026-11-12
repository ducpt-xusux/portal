import { useEffect, useState } from 'react'
import usePortalResource from '../../hooks/usePortalResource.js'
import { Badge, FieldGrid, Panel, useTime } from '../../portal/PortalUI'
import { uiLabel } from '../../services/uiLanguage.js'
import { parseResponseHistory } from './workbenchModel.js'

const phaseNames = {
  BEFORE: 'Trước cách ly',
  DURING: 'Trong cách ly',
  AFTER: 'Sau khôi phục',
}
const markNames = {
  PREPARED: 'Chuẩn bị',
  QUARANTINE_APPLIED: 'Áp dụng cách ly',
  RESTORE_SUCCESS: 'Khôi phục',
}
const metricNames = {
  detection_response: 'Thời gian phản ứng từ lúc phát hiện',
  trigger_to_quarantine: 'Từ lúc nhận yêu cầu đến lúc cách ly',
  quarantine_duration: 'Thời gian cách ly',
}

const seconds = new Intl.NumberFormat('vi-VN', { maximumFractionDigits: 6 })

function Groups({ ids }) {
  if (ids === null) return 'Chưa có quan sát'
  if (ids.length === 0) return 'Đã quan sát tập SG rỗng'
  return (
    <ul>
      {ids.map((id) => <li key={id}><code>{id}</code></li>)}
    </ul>
  )
}

function CurrentGroups({ cycle }) {
  const time = useTime()
  const { current } = cycle
  const expiry = current ? Date.parse(current.expires_at) : null
  const [, update] = useState(0)
  useEffect(() => {
    if (expiry === null || expiry <= Date.now()) return
    const timer = setTimeout(() => update((revision) => revision + 1), expiry - Date.now() + 10)
    return () => clearTimeout(timer)
  }, [expiry])
  const expired = expiry !== null && expiry <= Date.now()
  const reason = expired ? 'NEUTRON_CURRENT_STALE' : cycle.current_reason
  return (
    <section>
      <h4>Security Group hiện tại · Neutron</h4>
      <Badge value={expired ? 'UNKNOWN' : cycle.current_state} />
      {reason && <p>{uiLabel(reason)}</p>}
      {current && !expired && (
        <>
          <Groups ids={current.security_group_ids} />
          <p>Quan sát lúc {time(current.observed_at)} · <code>{current.source_ref}</code></p>
        </>
      )}
    </section>
  )
}

export function ResponseHistoryView({ history }) {
  const time = useTime()
  return (
    <section className="n91-wb-response">
      <h3>Lịch sử xử lý từ Controller</h3>
      <p><Badge value={history.availability} /> · Nguồn gốc {uiLabel(history.provenance.origin_mode)}</p>
      <p>Incident do Controller ghi nhận · <code>{history.incident_id}</code></p>
      {history.binding_source_ref && (
        <p>Nguồn liên kết P17 · <code>{history.binding_source_ref}</code></p>
      )}
      {history.arm_context && (
        <p>Owner ARM trong lab · {time(history.arm_context.timestamp)} · <code>{history.arm_context.source_ref}</code></p>
      )}
      <ul className="n91-wb-reasons">
        {history.reason_codes.map((reason) => <li key={reason}>{uiLabel(reason)}</li>)}
      </ul>
      {history.cycles.map((cycle) => (
        <section key={cycle.cycle_id}>
          <h4>Lần xử lý · <Badge value={cycle.state} /></h4>
          <FieldGrid rows={[
            ['Mã lần xử lý do Portal tạo', <code>{cycle.cycle_id}</code>],
            ['Port', <code>{cycle.port_id}</code>],
            ['Máy ảo', <code>{cycle.vm_id}</code>],
            ['Project', cycle.project_id ? <code>{cycle.project_id}</code> : 'Chưa xác định'],
            ['SG cách ly do Controller ghi nhận', cycle.quarantine_sg ? <code>{cycle.quarantine_sg}</code> : 'Chưa có dữ liệu'],
            ['SG gốc do Controller ghi nhận', <Groups ids={cycle.original_sgs} />],
          ]} />
          {cycle.clock_marks.length > 0 && (
            <ul>
              {cycle.clock_marks.map((mark) => (
                <li key={[mark.kind, mark.timestamp, mark.source_ref].join(':')}>
                  {markNames[mark.kind] || uiLabel(mark.kind)} · {time(mark.timestamp)} · <code>{mark.source_ref}</code>
                </li>
              ))}
            </ul>
          )}
          <FieldGrid rows={cycle.metrics.filter((metric) => metricNames[metric.metric]).map((metric) => [
            metricNames[metric.metric],
            metric.seconds === null
              ? uiLabel(metric.unavailable_reason)
              : `${seconds.format(metric.seconds)} giây · ${uiLabel(metric.time_basis)}`,
          ])} />
          <h4>Lịch sử Security Group</h4>
          <dl>
            {Object.entries(phaseNames).map(([phase, label]) => {
              const snapshot = cycle.history[phase]
              return (
                <div key={phase}>
                  <dt>{label}</dt>
                  <dd>
                    <Groups ids={snapshot?.security_group_ids ?? null} />
                    {snapshot && <p>{time(snapshot.observed_at)} · <code>{snapshot.source_ref}</code></p>}
                  </dd>
                </div>
              )
            })}
          </dl>
          <CurrentGroups cycle={cycle} />
        </section>
      ))}
      <details>
        <summary>Nguồn bằng chứng</summary>
        <p>Run · <code>{history.provenance.run_id}</code></p>
        <ul>
          {history.provenance.artifacts.map(({ label, source_ref }) => (
            <li key={source_ref}>{uiLabel(label)} · <code>{source_ref}</code></li>
          ))}
        </ul>
      </details>
    </section>
  )
}

function HistoryResource() {
  const [readCurrent, setReadCurrent] = useState(false)
  const resource = usePortalResource('/portal/investigation/response-history', {
    interval: 0,
    transform: parseResponseHistory,
  })
  const history = resource.data
  const cycle = history?.cycles[0]
  const canReadCurrent = !resource.error && history?.cycles.length === 1 && cycle.project_id !== null
  const current = usePortalResource('/portal/investigation/response-history', {
    params: { current: true },
    interval: 0,
    enabled: readCurrent && canReadCurrent,
    transform: parseResponseHistory,
  })
  const observed = current.data?.cycles[0]
  const matches =
    canReadCurrent &&
    !current.error &&
    current.data?.cycles.length === 1 &&
    history.incident_id === current.data.incident_id &&
    history.provenance.registry_generation === current.data.provenance.registry_generation &&
    history.provenance.archive_sha256 === current.data.provenance.archive_sha256 &&
    cycle.cycle_id === observed.cycle_id
  const view = matches ? {
    ...history,
    cycles: [{
      ...cycle,
      current: observed.current,
      current_state: observed.current_state,
      current_reason: observed.current_reason,
    }],
  } : history
  return (
    <Panel title="Lịch sử xử lý và Security Group" resource={resource}>
      {resource.error
        ? <p>{uiLabel(resource.error.code)}</p>
        : view && <ResponseHistoryView history={view} />}
      {canReadCurrent && (
        <>
          <button type="button" className="text-button" disabled={current.loading}
            onClick={() => readCurrent ? current.refresh() : setReadCurrent(true)}>
            {current.loading ? 'Đang đọc Security Group hiện tại…' : 'Đọc Security Group hiện tại'}
          </button>
          {current.error && <p role="status">Chưa đọc được quan sát hiện tại từ Neutron.</p>}
          {!current.error && current.data && !matches && (
            <p role="status">Nguồn lịch sử đã đổi. Tải lại lịch sử để đối chiếu quan sát hiện tại.</p>
          )}
        </>
      )}
    </Panel>
  )
}

export function StandaloneResponseHistory({ initiallyOpen }) {
  const [open, setOpen] = useState(initiallyOpen)
  return (
    <div className="n91-workbench">
      <button type="button" className="text-button" aria-expanded={open} onClick={() => setOpen(!open)}>
        {open ? 'Đóng lịch sử xử lý từ Controller' : 'Mở lịch sử xử lý từ Controller'}
      </button>
      {open && <HistoryResource />}
    </div>
  )
}
