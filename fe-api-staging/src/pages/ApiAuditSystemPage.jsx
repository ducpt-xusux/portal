import { useEffect, useState } from 'react'
import { ArrowLeft, Database, FileCheck2, RefreshCw, ShieldCheck } from 'lucide-react'
import { auditRequest } from '../services/auditApi'
import AuditSourceNotice from '../components/AuditSourceNotice'
import { dateTimeLabel } from '../utils/format'


function FieldType({ field }) {
  const parts = field.anyOf || [field]
  return <code>{parts.map(p => p.type || p.$ref?.split('/').pop() || 'object').join(' | ')}{field.format ? ` · ${field.format}` : ''}</code>
}

export default function ApiAuditSystemPage({ tab, ruleId }) {
  const [active, setActive] = useState(tab === 'rules' ? 'rules' : 'overview')
  const [payload, setPayload] = useState({})
  const [errors, setErrors] = useState({})
  const [busy, setBusy] = useState(true)
  const [reload, setReload] = useState(0)
  const [auto, setAuto] = useState(true)
  useEffect(() => { setActive(tab === 'rules' ? 'rules' : 'overview') }, [tab, ruleId])
  useEffect(() => {
    const controller = new AbortController()
    setBusy(true)
    const panels = [['health', '/system/health'], ['schema', '/system/audit-schema'], ['rules', '/rules']]
    Promise.allSettled(panels.map(([, path]) => auditRequest(path, { signal: controller.signal }))).then(results => {
      if (controller.signal.aborted) return
      const next = {}, failures = {}
      results.forEach((result, index) => {
        const name = panels[index][0]
        if (result.status === 'fulfilled') next[name] = result.value
        else failures[name] = result.reason.message
      })
      setPayload(previous => ({ ...previous, ...next })); setErrors(failures); setBusy(false)
    })
    return () => controller.abort()
  }, [reload])
  useEffect(() => {
    if (!auto) return
    const timer = setInterval(() => setReload(n => n + 1), 10000)
    return () => clearInterval(timer)
  }, [auto])
  const health = payload.health?.data
  const schema = payload.schema?.data
  const rules = payload.rules?.data
  const displayedRules = ruleId ? rules?.rules.filter(rule => rule.rule_id === ruleId) : rules?.rules
  const panelError = errors[active === 'overview' ? 'health' : active]
  return <div className="api-audit-page api-system-page">
    <div className="page-heading"><div><div className="eyebrow">SYSTEM · P16 AUDIT PIPELINE</div><h1>Trạng thái audit<span className="title-dot">.</span></h1><p>Kiểm tra bộ đọc, SQLite và metadata từ các bản ghi P16.</p></div><button className="button primary" disabled={busy} onClick={() => setReload(n => n + 1)}><RefreshCw size={15} className={busy ? 'spin' : ''} />Làm mới</button></div>
    <AuditSourceNotice meta={payload.health?.meta} error={errors.health} hasCache={Boolean(health)} />
    <div className="api-system-tabs"><div className="segmented" role="group" aria-label="Nội dung System P16">{[['overview', 'Tổng quan audit'], ['schema', 'Schema · 39 trường'], ['rules', 'Rules đã ghi nhận']].map(([id, name]) => <button key={id} className={active === id ? 'selected' : ''} aria-pressed={active === id} onClick={() => setActive(id)}>{name}</button>)}</div><label className="api-auto-control"><input type="checkbox" checked={auto} onChange={e => setAuto(e.target.checked)} />Tự cập nhật mỗi 10 giây</label></div>
    {panelError && <div className="audit-error" role="alert">{panelError} {payload[active === 'overview' ? 'health' : active] ? 'Đang giữ kết quả trước đó · STALE.' : 'Chưa có dữ liệu cho mục này.'}</div>}
    {active === 'overview' && <>
      <section className="incident-kpis" aria-label="Chỉ số pipeline audit" aria-busy={busy}>{[
        ['Events trong SQLite', health?.cached_events, Database], ['Nguồn JSONL', health?.audit_source.state, FileCheck2], ['SQLite đọc / ghi', health?.sqlite, Database], ['Trường audit bắt buộc', schema?.field_count, ShieldCheck],
      ].map(([name, value, Icon]) => <article className="stat-card" key={name}><div className="stat-top"><span>{name}</span><span className="stat-icon blue"><Icon size={17} /></span></div><div className="stat-value api-state-value">{value ?? '—'}</div><div className="stat-note">{errors.health && health ? 'STALE · lần kiểm tra trước' : 'Theo API Portal'}</div></article>)}</section>
      <div className="api-system-grid"><section className="panel api-context-panel"><h2>Đồng bộ & lưu trữ</h2><dl>{[
        ['Chế độ nguồn', health?.audit_source.mode === 'snapshot' ? 'Bản chụp lịch sử' : health?.audit_source.mode === 'live' ? 'Theo dõi file live' : 'UNKNOWN'],
        ['Lần kiểm tra nguồn', health?.audit_source.last_sync_at ? dateTimeLabel(health.audit_source.last_sync_at) : 'Chưa đọc được'],
        ['Sự kiện đầu tiên', health?.first_event_at ? dateTimeLabel(health.first_event_at) : 'Không có'],
        ['Sự kiện cuối', health?.last_event_at ? dateTimeLabel(health.last_event_at) : 'Không có'],
        ['Bản ghi lỗi', health?.audit_source.invalid_records ?? '—'], ['ID trùng đã bỏ qua', health?.audit_source.duplicate_records ?? '—'],
        ['ID xung đột', health?.audit_source.conflicting_records ?? '—'], ['Byte đang chờ nhập', health?.audit_source.pending_bytes ?? '—'],
        ['Định dạng nguồn', 'JSONL · UTF-8'], ['Quyền truy cập nguồn', 'Chỉ đọc'], ['Khóa chống trùng', 'event_id'], ['Probe SQLite', 'Ghi thử trong transaction và rollback'],
      ].map(([name, value]) => <div key={name}><dt>{name}</dt><dd>{value}</dd></div>)}</dl></section>
      <section className="panel api-context-panel"><h2>Giới hạn của thông tin audit</h2><p>Đọc được file và biết thời điểm event cuối chưa chứng minh tiến trình ghi log đang khỏe. Audit writer hiện chưa có probe độc lập.</p><dl>{[
        ['Audit writer process', 'UNKNOWN · chưa probe'], ['Firewall listener', 'Chưa kết nối'], ['OpenStack / Nova / Neutron', 'Ngoài phạm vi P16'], ['Galera Primary / Synced', 'Chưa có probe'], ['VM / Security Groups', 'Chưa có inventory'], ['Correlation / isolation', 'Chưa triển khai'],
      ].map(([name, value]) => <div key={name}><dt>{name}</dt><dd>{value}</dd></div>)}</dl><p>Không kết luận DOWN khi chưa có dữ liệu kiểm tra. Những phần này sẽ được nối theo các phase tiếp theo.</p></section></div>
      <section className="panel api-context-panel"><h2>Phiên bản từng được ghi trong audit</h2><p>Metadata lịch sử từ bản ghi, không phải kết quả đọc cấu hình đang chạy trên Proxy.</p><div className="table-scroll"><table className="events-table"><thead><tr><th>POLICY</th><th>RISK</th><th>RUNTIME MODE</th><th>EVENTS</th><th>LẦN CUỐI</th></tr></thead><tbody>{health?.metadata?.versions?.map((item, index) => <tr key={index}><td>{item.policy_id} · {item.policy_version}</td><td>{item.risk_id || 'UNKNOWN'} · {item.risk_version || 'UNKNOWN'}</td><td>{item.runtime_mode}</td><td>{item.event_count}</td><td>{dateTimeLabel(item.last_seen)}</td></tr>)}</tbody></table></div>{health && !health.metadata?.versions?.length && <p>Chưa có metadata từ sự kiện.</p>}</section>
    </>}
    {active === 'schema' && schema && <section className="panel api-context-panel"><h2>Audit {schema.audit_version} · {schema.field_count} trường bắt buộc</h2><p>Hợp đồng bộ đọc FastAPI đã đối chiếu với schema P16 bạn cung cấp. Không tự suy diễn đây là cấu hình hiện tại của Proxy.</p><div className="api-schema-note"><b>Privacy:</b> chỉ nhận <code>query_masked</code>; từ chối <code>{schema.privacy.forbidden_fields.join(', ')}</code>. Masking lỗi thì query phải null; risk lỗi không được mang điểm giả.</div><div className="table-scroll"><table className="events-table"><thead><tr><th>TRƯỜNG</th><th>KIỂU / FORMAT</th><th>BẮT BUỘC</th><th>GIÁ TRỊ CHO PHÉP</th></tr></thead><tbody>{Object.entries(schema.fields).map(([name, field]) => <tr key={name}><td><code>{name}</code></td><td><FieldType field={field} /></td><td>{schema.required_fields.includes(name) ? 'Có' : 'Không'}</td><td>{(field.enum || field.anyOf?.find(p => p.enum)?.enum || []).join(', ') || (field.const !== undefined ? String(field.const) : '—')}</td></tr>)}</tbody></table></div></section>}
    {active === 'rules' && rules && <section className="panel api-context-panel">{ruleId && <a className="incident-back" href="#/system/rules"><ArrowLeft size={14} />Mọi rule đã ghi nhận</a>}<h2>{ruleId || `${rules.total_observed_rules} rule từng xuất hiện trong audit`}</h2><p>Chỉ là những rule có trong dữ liệu P16 đang đọc; chưa phải catalog đầy đủ và chưa xác nhận enabled/disabled. Default-deny được ghi nhận ở {rules.default_deny_event_count} sự kiện.</p><div className="table-scroll"><table className="events-table"><thead><tr><th>RULE</th><th>MÔ TẢ TRONG AUDIT</th><th>ĐIỂM</th><th>PHÂN LOẠI</th><th>POLICY / RISK</th><th>SỐ EVENT</th><th>ENABLED</th></tr></thead><tbody>{displayedRules?.map((rule, index) => <tr key={index}><td><a href={`#/system/rules/${encodeURIComponent(rule.rule_id)}`}>{rule.rule_id}</a></td><td>{rule.description}</td><td>{rule.score}</td><td>{rule.category}</td><td>{rule.policy_version} / {rule.risk_version}</td><td>{rule.event_count}</td><td>Chưa xác nhận</td></tr>)}</tbody></table></div>{!displayedRules?.length && <p>Không có rule phù hợp trong các bản ghi hiện tại.</p>}</section>}
    <footer className="dashboard-footer"><span>Phạm vi P16 · chỉ đọc · chưa triển khai lên Proxy</span><span>{payload.health && `Đọc API ${dateTimeLabel(payload.health.meta.timestamp)}`}</span></footer>
  </div>
}
