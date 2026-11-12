import { uiLabel, uiRoleList } from '../services/uiLanguage.js'
import { ArrowRight, ArrowUpRight } from 'lucide-react'
import { readCollection } from '../services/portalApi'
import {
  dashboardHref,
  funnelTitles,
  metricTitles,
  funnelReasons,
  readFunnel,
  funnelLink,
  readEvaluationRun,
} from '../services/dashboardFunnel'
import { useV4Resource } from './IncidentPages'
import { useSourceDisplay } from './PortalContext'
import { sourceState } from '../services/portalApi'
import {
  Badge,
  Empty,
  FieldGrid,
  PageHeading,
  Panel,
  useTime,
} from './PortalUI'

export function DecisionFunnel({
  window = '15m',
  end,
  context = 'LIVE',
  runId,
}) {
  const time = useTime()
  const { hideSourceSystem } = useSourceDisplay()
  const resource = useV4Resource('/dashboard/decision-funnel', {
    params: { window, end, context, run_id: runId },
    interval: context === 'LIVE' ? 10000 : 0,
    enabled: context === 'LIVE' || Boolean(runId),
    transform: (data) => readFunnel(data, context, runId),
  })
  const data = resource.data
  return (
    <Panel
      title="Luồng xử lý yêu cầu"
      subtitle="Yêu cầu → Phân tích → Cho phép / Chặn → Cảnh báo → Sự cố → Xử lý"
      resource={context === 'LIVE' || runId ? resource : undefined}
    >
      {data ? (
        <>
          <p className="v4-funnel-window">
            {time(data.window_from)} → {time(data.window_to)} ·{' '}
            <Badge value={context}>{uiLabel(context)}</Badge>
          </p>
          <div className="v4-funnel-grid">
            {data.stages.map((row, index) => (
              <article className="v4-funnel-stage" key={row.stage}>
                <div className="v4-funnel-stage-title">
                  <span>{index + 1}</span>
                  <h3>{uiLabel(funnelTitles[row.stage])}</h3>
                  {index < 5 && <ArrowRight size={14} />}
                </div>
                <Badge
                  value={
                    resource.error
                      ? 'STALE'
                      : hideSourceSystem && row.status === 'HISTORICAL'
                        ? 'SNAPSHOT'
                        : row.status
                  }
                />
                <dl>
                  {row.metrics.map((metric) => {
                    const href = funnelLink(data, row, metric)
                    const content = (
                      <>
                        <strong>{metric.count ?? '—'}</strong>{' '}
                        {uiLabel(metricTitles[metric.key] || metric.unit)}
                      </>
                    )
                    return (
                      <div key={metric.key}>
                        <dt className="sr-only">
                          {uiLabel(metricTitles[metric.key] || metric.unit)}
                        </dt>
                        <dd>
                          {href ? (
                            <a
                              href={href}
                              title={
                                row.stage === 'INCIDENT'
                                  ? "Xem danh sách sự cố."
                                  : undefined
                              }
                            >
                              {content}
                              <ArrowUpRight size={12} />
                            </a>
                          ) : (
                            content
                          )}
                        </dd>
                      </div>
                    )
                  })}
                </dl>
                <p>{uiLabel(row.reason_code)}</p>
                {!hideSourceSystem && (
                  <small>
                    {uiLabel(row.source.source_system)} · {row.source.coverage_kind}
                  </small>
                )}
                <small>
                  Độ mới nguồn:{' '}
                  {resource.error
                    ? 'STALE'
                    : hideSourceSystem
                      ? sourceState(
                          {
                            freshness_state: row.source.freshness_state,
                          },
                          false
                        )
                      : row.source.freshness_state}
                </small>
                <small>Dữ liệu đến: {time(row.source.data_as_of)}</small>
                <details>
                  <summary>Nguồn và giới hạn</summary>
                  <small>Đọc lúc: {time(row.source.read_at)}</small>
                  <small>Mốc đếm: {row.time_basis}</small>
                  <code>{row.source.source_ref || "Chưa có nguồn ref"}</code>
                  {row.source.error_code && (
                    <code>{row.source.error_code}</code>
                  )}
                </details>
              </article>
            ))}
          </div>
        </>
      ) : !runId && context === 'EVALUATION' ? (
        <Empty
          title="Chọn run đánh giá"
          text="Funnel evaluation tách khỏi dữ liệu runtime và KPI live."
        />
      ) : null}
    </Panel>
  )
}

export function EvaluationDashboard({ params }) {
  const time = useTime()
  const runs = useV4Resource('/evaluations/runs', {
    interval: 0,
    transform: (data) => readCollection(data).map(readEvaluationRun),
  })
  const runId = params.run_id
  const detail = useV4Resource(
    runId ? `/evaluations/runs/${encodeURIComponent(runId)}` : null,
    { interval: 0, enabled: Boolean(runId), transform: readEvaluationRun }
  )
  const run = detail.data
  return (
    <>
      <PageHeading
        eyebrow="ĐÁNH GIÁ · KẾT QUẢ ĐÃ LƯU"
        title="Tổng quan đánh giá"
        description="Kết quả đánh giá theo từng lần thực hiện."
      />
      <div className="v4-context-banner evaluation">
        <strong>EVALUATION · dữ liệu đánh giá</strong>
        <p>
          Kết quả đánh giá giữ đúng phạm vi thực hiện. Chưa thực hiện không đồng nghĩa với đạt.
        </p>
        <a href={dashboardHref('LIVE', params.window || '15m')}>
          Trở về Trang chủ LIVE
        </a>
      </div>
      <Panel
        title="Chọn đánh giá run"
        subtitle="Chỉ đọc registry đã chuẩn hóa, có nguồn SHA256"
        resource={runs}
      >
        <label className="v4-filter">
          <span>Lần thực hiện đánh giá</span>
          <select
            value={runId || ''}
            disabled={!runs.data?.length}
            onChange={(event) => {
              window.location.hash = dashboardHref(
                'EVALUATION',
                params.window || '15m',
                event.target.value
              )
            }}
          >
            <option value="">Chọn run</option>
            {runs.data?.map((row) => (
              <option key={row.run_id} value={row.run_id}>
                {row.run_id} · {row.dataset} · {row.run_kind}
              </option>
            ))}
          </select>
        </label>
        {runs.error && (
          <p className="v4-panel-note">
            Chưa có bộ kết quả đánh giá đã được kiểm tra để hiển thị.
          </p>
        )}
        {runs.data?.length === 0 && (
          <Empty
            title="Registry chưa có run"
            text="Chưa có kết quả đánh giá được nhập."
          />
        )}
      </Panel>
      {runId && (
        <Panel title="Kết quả run" resource={detail}>
          {run && (
            <>
              <FieldGrid
                rows={[
                  ["Lần thực hiện ID", run.run_id],
                  ['Dataset', run.dataset],
                  ['Nguồn run', run.run_kind],
                  ['Trạng thái', uiLabel(run.status)],
                  ["Rà soát", uiLabel(run.review_state)],
                  ['Bắt đầu', time(run.started_at)],
                  ['Kết thúc', time(run.completed_at)],
                  ['SHA256', run.source_sha256],
                ]}
              />
              <div className="v4-evaluation-counts">
                {Object.entries(run.counts).map(([key, value]) => (
                  <article key={key}>
                    <span>{key.toUpperCase()}</span>
                    <strong>{value}</strong>
                    <small>ca kiểm thử / {run.case_count}</small>
                  </article>
                ))}
              </div>
              <ul>
                {run.limitations.map((note, i) => (
                  <li key={i}>{note}</li>
                ))}
              </ul>
            </>
          )}
        </Panel>
      )}
      <DecisionFunnel
        context="EVALUATION"
        runId={runId}
        window={params.window || '15m'}
      />
    </>
  )
}
