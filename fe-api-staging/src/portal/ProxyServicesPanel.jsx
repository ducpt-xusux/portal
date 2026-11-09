import { Activity, ArrowUpRight, RefreshCw } from 'lucide-react'
import { readCollection } from '../services/portalApi'
import { useV4Resource } from './IncidentPages'
import { Badge, FieldGrid, Panel, display, useTime } from './PortalUI'
import './ProxyServicesPanel.css'

export default function ProxyServicesPanel({ system = false }) {
  const time = useTime()
  const resource = useV4Resource('/system/proxy-services', {
    interval: 15000, transform: data => readCollection(data, 'components'),
  })
  const labels = { RUNNING: 'Đang chạy lúc chụp', STOPPED: 'Đã dừng lúc chụp', FAILED: 'Lỗi lúc chụp', UNKNOWN: 'Chưa xác định' }
  const sourceOk = resource.meta?.source_mode === 'SNAPSHOT' && resource.meta?.scope === 'SYSTEMD_STATUS_ONLY' &&
    typeof resource.meta?.source_ref === 'string' && !resource.meta?.last_error_code
  const validObservation = row => sourceOk && row.source_mode === 'SNAPSHOT' && row.scope === 'SYSTEMD_STATUS_ONLY' &&
    row.source_ref === resource.meta.source_ref && row.read_ok === true && Number.isFinite(Date.parse(row.observed_at))

  if (!system) return <Panel title="Dịch vụ trên Proxy" subtitle="Bản chụp systemd · trạng thái tiến trình" resource={resource}
    action={<a className="v4-text-link" href="#/system/health">Xem chi tiết tại System<ArrowUpRight size={14} /></a>}>
    <div className="v4-proxy-compact-grid">{resource.data?.map(row => {
      const valid = validObservation(row)
      const state = valid && Object.hasOwn(labels, row.process_state) ? row.process_state : 'UNKNOWN'
      return <article className="v4-proxy-compact-service" key={row.component_id}>
        <strong>{display(row.name)}</strong><div><Badge value={state}>{labels[state]}</Badge><Badge value={valid ? row.observation_freshness_state : 'UNKNOWN'} /></div>
      </article>
    })}</div>
    <p className="v4-panel-note">Trạng thái tại thời điểm chụp; chưa xác nhận health hiện tại.{resource.meta?.last_error_code && <span role="status"> Lỗi đọc nguồn: {resource.meta.last_error_code}.</span>}</p>
  </Panel>

  return <Panel title="Dịch vụ trên Proxy" subtitle="Trạng thái tiến trình từ systemd · tách riêng health chức năng" resource={resource}
    action={<div className="v4-proxy-actions"><button className="button secondary" disabled={resource.loading} onClick={resource.refresh}><RefreshCw size={14} />Đọc lại tệp</button>{!system && <a className="v4-text-link" href="#/system/health">System<ArrowUpRight size={14} /></a>}</div>}>
    <div className="v4-proxy-snapshot"><Badge value="HISTORICAL">Bản chụp</Badge><span>{sourceOk ? <>Máy <strong>{display(resource.meta.source_host)}</strong> · Thu thập {time(resource.meta.data_as_of)}</> : 'Chưa có bản chụp hợp lệ.'}</span></div>
    <p className="v4-panel-note">Đọc lại tệp chỉ cập nhật bản xuất local; chưa tự thu thập từ Proxy. Trạng thái bên dưới mô tả thời điểm chụp, không xác nhận service hiện đang chạy.</p>
    {resource.meta?.last_error_code && <p className="v4-inline-warning" role="status">Chưa đọc được nguồn systemd: {resource.meta.last_error_code}</p>}
    <div className="v4-proxy-services">{resource.data?.map(row => {
      const valid = validObservation(row)
      const state = valid && Object.hasOwn(labels, row.process_state) ? row.process_state : 'UNKNOWN'
      return <article className="v4-proxy-service" key={row.component_id}>
        <div className="v4-proxy-service-title"><Activity size={17} /><h3>{display(row.name)}</h3><Badge value={state}>{labels[state]}</Badge></div>
        <code className="v4-proxy-unit">{display(row.unit)}</code>
        <FieldGrid rows={[
          ['PID lúc chụp', valid ? display(row.pid) : '—'],
          ['Systemd lúc chụp', valid ? `${display(row.load_state)} / ${display(row.active_state)} / ${display(row.sub_state)}` : 'Chưa xác định'],
          ['Quan sát trên Proxy', time(row.observed_at)],
          ['Độ mới quan sát', <Badge value={valid ? row.observation_freshness_state : 'UNKNOWN'} />],
          ['Health chức năng', 'Chưa xác minh'],
          ...(system ? [['Lần thử trên Proxy', time(row.last_attempt)], ['Result systemd', valid ? display(row.result) : '—']] : []),
          ...(row.last_error_code ? [['Lỗi đọc', display(row.last_error_code)]] : []),
        ]} />
      </article>
    })}</div>
    <p className="v4-panel-note">Chưa kiểm tra SQL/TLS, tiến độ P16H/P17 hoặc kết nối Galera qua Proxy.</p>
    {system && sourceOk && <p className="v4-proxy-ref">Nguồn bản chụp: <code>{resource.meta.source_ref}</code></p>}
  </Panel>
}
