import { ArrowRight, ArrowUpRight } from 'lucide-react'
import { readCollection } from '../services/portalApi'
import { dashboardHref, funnelTitles, metricTitles, funnelReasons, readFunnel, funnelLink, readEvaluationRun } from '../services/dashboardFunnel'
import { useV4Resource } from './IncidentPages'
import { Badge, Empty, FieldGrid, PageHeading, Panel, useTime } from './PortalUI'

export function DecisionFunnel({ window = '15m', end, context = 'LIVE', runId }) {
  const time = useTime()
  const resource = useV4Resource('/dashboard/decision-funnel', { params: { window, end, context, run_id: runId },
    interval: context === 'LIVE' ? 10000 : 0, enabled: context === 'LIVE' || Boolean(runId), transform: data => readFunnel(data,context,runId) })
  const data = resource.data
  return <Panel title="Decision funnel" subtitle="Request → Parse → ALLOW/BLOCK → Alert → Incident → Action" resource={context === 'LIVE' || runId ? resource : undefined}>
    <p className="v4-panel-note">Mỗi bước dùng counter và đơn vị riêng. Chưa xác minh cùng một tập request xuyên suốt, vì vậy không tính tỷ lệ chuyển đổi hoặc suy số incident từ số alert.</p>
    {data ? <><p className="v4-funnel-window">{time(data.window_from)} → {time(data.window_to)} · <Badge value={context}>{context}</Badge></p>
      <div className="v4-funnel-grid">{data.stages.map((row,index) => <article className="v4-funnel-stage" key={row.stage}>
        <div className="v4-funnel-stage-title"><span>{index+1}</span><h3>{funnelTitles[row.stage]}</h3>{index < 5 && <ArrowRight size={14} />}</div>
        <Badge value={resource.error ? 'STALE' : row.status} />
        <dl>{row.metrics.map(metric => { const href=funnelLink(data,row,metric); const content=<><strong>{metric.count ?? '—'}</strong> {metricTitles[metric.key] || metric.unit}</>
          return <div key={metric.key}><dt className="sr-only">{metricTitles[metric.key] || metric.unit}</dt><dd>{href ? <a href={href} title={row.stage === 'INCIDENT' ? 'Mở toàn bộ incidents; danh sách lọc last_seen, funnel đếm created_utc.' : undefined}>{content}<ArrowUpRight size={12}/></a> : content}</dd></div> })}</dl>
        <p>{funnelReasons[row.reason_code] || row.reason_code}</p>
        <small>{row.source.source_system} · {row.source.coverage_kind}</small><small>Độ mới nguồn: {resource.error ? 'STALE' : row.source.freshness_state}</small>
        <small>Dữ liệu đến: {time(row.source.data_as_of)}</small>
        <details><summary>Nguồn và giới hạn</summary><small>Đọc lúc: {time(row.source.read_at)}</small><small>Mốc đếm: {row.time_basis}</small><code>{row.source.source_ref || 'Chưa có source ref'}</code>{row.source.error_code && <code>{row.source.error_code}</code>}</details>
      </article>)}</div></> : !runId && context === 'EVALUATION' ? <Empty title="Chọn run evaluation" text="Funnel evaluation tách khỏi dữ liệu runtime và KPI live."/> : null}
  </Panel>
}

export function EvaluationDashboard({ params }) {
  const time = useTime()
  const runs = useV4Resource('/evaluations/runs', { interval: 0, transform: data => readCollection(data).map(readEvaluationRun) })
  const runId = params.run_id
  const detail = useV4Resource(runId ? `/evaluations/runs/${encodeURIComponent(runId)}` : null, { interval: 0, enabled: Boolean(runId), transform: readEvaluationRun })
  const run = detail.data
  return <><PageHeading eyebrow="EVALUATION · FROZEN RUNS" title="Evaluation Overview" description="Kết quả theo run riêng · không phải KPI hoặc cảnh báo mới từ nguồn live." />
    <div className="v4-context-banner evaluation"><strong>EVALUATION · dữ liệu đánh giá</strong><p>Fixture expected, observed và trạng thái review được giữ theo nguồn. Run OFFLINE/HISTORICAL không trở thành live; NOT_EXECUTED không phải PASS.</p><a href={dashboardHref('LIVE',params.window || '15m')}>Trở về Dashboard LIVE</a></div>
    <Panel title="Chọn evaluation run" subtitle="Chỉ đọc registry đã chuẩn hóa, có source SHA256" resource={runs}>
      <label className="v4-filter"><span>Run đánh giá</span><select value={runId || ''} disabled={!runs.data?.length} onChange={event => { window.location.hash=dashboardHref('EVALUATION',params.window || '15m',event.target.value) }}><option value="">Chọn run</option>{runs.data?.map(row=><option key={row.run_id} value={row.run_id}>{row.run_id} · {row.dataset} · {row.run_kind}</option>)}</select></label>
      {runs.error && <p className="v4-panel-note">Chưa có nguồn evaluation để hiển thị. Cần nhập registry run đã sanitize và kiểm tra SHA256; Portal không lấy dữ liệu live hoặc sinh dữ liệu mẫu để thay thế.</p>}
      {runs.data?.length === 0 && <Empty title="Registry chưa có run" text="Chưa có kết quả đánh giá được nhập." />}
    </Panel>
    {runId && <Panel title="Kết quả run" resource={detail}>{run && <><FieldGrid rows={[
      ['Run ID',run.run_id],['Dataset',run.dataset],['Nguồn run',run.run_kind],['Trạng thái',run.status],['Review',run.review_state],['Bắt đầu',time(run.started_at)],['Kết thúc',time(run.completed_at)],['SHA256',run.source_sha256],
    ]}/><div className="v4-evaluation-counts">{Object.entries(run.counts).map(([key,value])=><article key={key}><span>{key.toUpperCase()}</span><strong>{value}</strong><small>case / {run.case_count}</small></article>)}</div><ul>{run.limitations.map((note,i)=><li key={i}>{note}</li>)}</ul></>}</Panel>}
    <DecisionFunnel context="EVALUATION" runId={runId} window={params.window || '15m'} />
  </>
}
