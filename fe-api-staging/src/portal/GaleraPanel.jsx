import { ArrowUpRight, RefreshCw } from 'lucide-react'
import { count } from '../services/portalApi'
import { useV4Resource } from './IncidentPages'
import { Badge, Empty, FieldGrid, ObservationAgeBadge, Panel, display, useTime } from './PortalUI'

export default function GaleraPanel({ compact = false }) {
  const time = useTime()
  const resource = useV4Resource('/system/galera', { interval: 15000 })
  const nodes = Array.isArray(resource.data?.nodes) ? resource.data.nodes : []
  const summary = resource.data?.summary
  const historical =
    resource.meta?.source_mode === 'SNAPSHOT' &&
    resource.meta?.scope === 'LOCAL_SOCKET_WSREP'
  const valid = (node) =>
    historical &&
    node.source_mode === 'SNAPSHOT' &&
    node.scope === 'LOCAL_SOCKET_WSREP' &&
    node.read_ok === true &&
    typeof node.source_ref === 'string' &&
    Number.isFinite(Date.parse(node.observed_at))
  const agreement =
    summary?.consistency === 'MATCHING_AT_OBSERVATIONS'
      ? 'UUID và cấu hình cluster khớp tại các lần đo'
      : summary?.consistency === 'MISMATCH'
        ? 'Có khác biệt giữa các node'
        : 'Chưa đủ dữ liệu để đối chiếu'
  return (
    <Panel
      title="Galera · wsrep từng node"
      subtitle="Quan sát qua socket nội bộ trên từng máy Galera"
      resource={resource}
      action={
        <div className="v4-proxy-actions">
          <button
            className="button secondary"
            disabled={resource.loading}
            onClick={resource.refresh}
          >
            <RefreshCw size={14} />
            Đọc lại wsrep
          </button>
          {compact && (
            <a className="v4-text-link" href="#/system/galera">
              Chi tiết Galera
              <ArrowUpRight size={14} />
            </a>
          )}
        </div>
      }
    >
      {historical && (
        <>
          <div className="v4-proxy-snapshot">
            <Badge value="HISTORICAL">Bản chụp</Badge>
            {resource.meta?.coverage_state && <Badge value={resource.meta.coverage_state} />}
            <span>
              Quan sát {time(summary?.observation_from)} →{' '}
              {time(summary?.observation_to)}
            </span>
          </div>
        </>
      )}
      {resource.data && (
        <>
          <div className="v4-galera-summary">
            <div>
              <span>Node có kết quả đo</span>
              <strong>
                {display(count(summary?.observed_nodes))} /{' '}
                {display(count(summary?.expected_nodes))}
              </strong>
            </div>
            <div>
              <span>Quan sát đạt điều kiện wsrep</span>
              <strong>
                {historical
                  ? display(count(summary?.healthy_node_observations))
                  : '—'}{' '}
                / {display(count(summary?.expected_nodes))}
              </strong>
            </div>
            <div>
              <span>Đối chiếu bản chụp</span>
              <strong>{agreement}</strong>
            </div>
            <div>
              <span>Trạng thái hiện tại</span>
              <Badge value="UNKNOWN">Chưa xác minh</Badge>
            </div>
          </div>
          {resource.meta?.last_error_code && (
            <p className="v4-inline-warning" role="status">
              Thiếu kết quả wsrep từ một hoặc nhiều node.
            </p>
          )}
          {!compact &&
            (nodes.length ? (
              <>
                <div className="table-scroll">
                  <table className="v4-table v4-galera-table">
                    <thead>
                      <tr>
                        <th>NODE</th>
                        <th>TRẠNG THÁI CỤM</th>
                        <th>SỐ NODE BÁO CÁO</th>
                        <th>TRẠNG THÁI NODE</th>
                        <th>WSREP READY / CONNECTED</th>
                        <th>QUAN SÁT TRÊN NODE</th>
                        <th>ĐỘ MỚI</th>
                      </tr>
                    </thead>
                    <tbody>
                      {nodes.map((node) => (
                        <tr key={node.node_id}>
                          <td>
                            <strong>
                              {display(node.name || node.node_id)}
                            </strong>
                            <small>
                              {node.last_error_code ||
                                (valid(node)
                                  ? 'Kết quả lúc chụp'
                                  : 'Chưa có kết quả hợp lệ')}
                            </small>
                          </td>
                          <td>
                            <Badge
                              value={
                                valid(node)
                                  ? node.wsrep_cluster_status
                                  : 'UNKNOWN'
                              }
                            />
                          </td>
                          <td>
                            {valid(node)
                              ? display(node.wsrep_cluster_size)
                              : '—'}
                          </td>
                          <td>
                            <Badge
                              value={
                                valid(node)
                                  ? node.wsrep_local_state_comment
                                  : 'UNKNOWN'
                              }
                            />
                          </td>
                          <td>
                            {valid(node)
                              ? `${display(node.wsrep_ready)} / ${display(node.wsrep_connected)}`
                              : '—'}
                          </td>
                          <td>{time(node.observed_at)}</td>
                          <td>
                            <ObservationAgeBadge
                              value={
                                valid(node)
                                  ? node.observation_freshness_state
                                  : 'UNKNOWN'
                              }
                            />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div className="v4-galera-details">
                  {nodes.map((node) => (
                    <details key={node.node_id}>
                      <summary>Đối chiếu UUID · {display(node.name)}</summary>
                      <FieldGrid
                        rows={[
                          [
                            'Cluster state UUID',
                            valid(node)
                              ? display(node.wsrep_cluster_state_uuid)
                              : '—',
                          ],
                          [
                            'Local state UUID',
                            valid(node)
                              ? display(node.wsrep_local_state_uuid)
                              : '—',
                          ],
                          [
                            'Cluster conf ID',
                            valid(node)
                              ? display(node.wsrep_cluster_conf_id)
                              : '—',
                          ],
                          [
                            'Đánh giá tại lúc đo',
                            valid(node) ? (
                              <Badge value={node.health_at_observation} />
                            ) : (
                              <Badge value="UNKNOWN" />
                            ),
                          ],
                          ['Lần thử trên node', time(node.attempted_at)],
                          ['Chốt bản chụp', time(node.collected_at)],
                          ["Tham chiếu nguồn", display(node.source_ref)],
                        ]}
                      />
                    </details>
                  ))}
                </div>
              </>
            ) : (
              <Empty
                title="Chưa có kết quả wsrep"
                text="Chưa nhận được bản chụp từ các node Galera."
              />
            ))}
        </>
      )}
    </Panel>
  )
}
