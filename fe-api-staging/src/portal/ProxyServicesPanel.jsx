import { Activity, ArrowUpRight, RefreshCw } from 'lucide-react'
import { readCollection } from '../services/portalApi'
import { useV4Resource } from './IncidentPages'
import { uiLabel } from '../services/uiLanguage'
import { Badge, FieldGrid, ObservationAgeBadge, Panel, display, useTime } from './PortalUI'
import './ProxyServicesPanel.css'

const serviceNames = {
  'db-firewall.service': 'Bộ kiểm soát truy vấn SQL',
  'db-firewall-audit.service': 'Bộ thu nhật ký',
  'db-firewall-p17.service': 'Bộ phát hiện hành vi và sự cố',
}

export default function ProxyServicesPanel({ system = false }) {
  const time = useTime()
  const resource = useV4Resource('/system/proxy-services', {
    interval: 15000,
    transform: (data) => readCollection(data, 'components'),
  })
  const labels = {
    RUNNING: 'Đang chạy lúc chụp',
    STOPPED: 'Đã dừng lúc chụp',
    FAILED: 'Lỗi lúc chụp',
    UNKNOWN: 'Chưa xác định',
  }
  const sourceOk =
    resource.meta?.source_mode === 'SNAPSHOT' &&
    resource.meta?.scope === 'SYSTEMD_STATUS_ONLY' &&
    typeof resource.meta?.source_ref === 'string'
  const validObservation = (row) =>
    sourceOk &&
    row.source_mode === 'SNAPSHOT' &&
    row.scope === 'SYSTEMD_STATUS_ONLY' &&
    row.source_ref === resource.meta.source_ref &&
    row.read_ok === true &&
    Number.isFinite(Date.parse(row.observed_at))

  // The service reader is optional. An unconfigured source is not a service failure.
  // Show one clear source warning, not three large cards of invented UNKNOWN values.
  if (system && !sourceOk) {
    return (
      <Panel title="Dịch vụ bảo mật trên Proxy" resource={resource}>
        <p className="v4-inline-warning" role="status">
          Chưa kết nối nguồn theo dõi dịch vụ trên Proxy. Không thể kết luận trạng thái chạy từ dữ liệu này.
        </p>
        <a className="v4-text-link" href="#/system/sources">Kiểm tra nguồn dữ liệu</a>
      </Panel>
    )
  }

  if (!system)
    return (
      <Panel
        title="Dịch vụ trên Proxy"
        resource={resource}
        action={
          <a className="v4-text-link" href="#/system/health">
            Xem chi tiết tại Hệ thống
            <ArrowUpRight size={14} />
          </a>
        }
      >
        <div className="v4-proxy-compact-grid">
          {resource.data?.map((row) => {
            const valid = validObservation(row)
            const state =
              valid && Object.hasOwn(labels, row.process_state)
                ? row.process_state
                : 'UNKNOWN'
            return (
              <article
                className="v4-proxy-compact-service"
                key={row.component_id}
              >
                <strong>{serviceNames[row.unit] || display(row.name)}</strong>
                <div>
                  <Badge value={state}>{labels[state]}</Badge>
                  <ObservationAgeBadge
                    value={valid ? row.observation_freshness_state : 'UNKNOWN'}
                  />
                </div>
              </article>
            )
          })}
        </div>
        {resource.meta?.last_error_code && (
          <p className="v4-panel-note" role="status">
            {sourceOk ? 'Thiếu kết quả từ một hoặc nhiều dịch vụ.' : 'Chưa đọc được bản chụp systemd.'}
          </p>
        )}
      </Panel>
    )

  return (
    <Panel
      title="Dịch vụ trên Proxy"
      resource={resource}
      sourceDetailsOnly
      action={
        <div className="v4-proxy-actions">
          <button
            className="button secondary"
            disabled={resource.loading}
            onClick={resource.refresh}
          >
            <RefreshCw size={14} />
            Làm mới
          </button>
        </div>
      }
    >
      {resource.meta?.last_error_code && (
        <p className="v4-inline-warning" role="status">
          {sourceOk ? 'Thiếu kết quả từ một hoặc nhiều dịch vụ.' : 'Chưa đọc được bản chụp systemd.'}
        </p>
      )}
      <div className="v4-proxy-services">
        {resource.data?.map((row) => {
          const valid = validObservation(row)
          const state =
            valid && Object.hasOwn(labels, row.process_state)
              ? row.process_state
              : 'UNKNOWN'
          return (
            <article className="v4-proxy-service" key={row.component_id}>
              <div className="v4-proxy-service-title">
                <Activity size={17} />
                <h3>{serviceNames[row.unit] || display(row.name)}</h3>
                <Badge value={state}>{labels[state]}</Badge>
              </div>
              <details className="v4-proxy-diagnostics">
                <summary>Chi tiết dịch vụ</summary>
                <code className="v4-proxy-unit">{row.unit}</code>
                <FieldGrid
                  rows={[
                    ['PID lúc chụp', valid ? display(row.pid) : '—'],
                    [
                      'Trạng thái systemd',
                      valid
                        ? [row.load_state, row.active_state, row.sub_state].map(uiLabel).join(' / ')
                        : 'Chưa xác định',
                    ],
                    ['Quan sát trên Proxy', time(row.observed_at)],
                    ['Hiệu lực quan sát', <ObservationAgeBadge value={valid ? row.observation_freshness_state : 'UNKNOWN'} />],
                    ['Lần thử trên Proxy', time(row.last_attempt)],
                    ['Kết quả systemd', valid ? uiLabel(row.result) : '—'],
                    ...(row.last_error_code ? [['Lỗi đọc', display(row.last_error_code)]] : []),
                  ]}
                />
              </details>
            </article>
          )
        })}
      </div>
      {sourceOk && (
        <details className="v4-proxy-diagnostics">
          <summary>Phạm vi bản chụp dịch vụ</summary>
          <FieldGrid rows={[
            ['Máy nguồn', display(resource.meta.source_host)],
            ['Mức độ bao phủ dịch vụ', uiLabel(resource.meta.coverage_state)],
            ['Tham chiếu bản chụp', <code>{resource.meta.source_ref}</code>],
          ]} />
          <a href="#/system/report-evidence">Xem bằng chứng kết nối TLS</a>
        </details>
      )}
    </Panel>
  )
}
