import { useEffect, useState } from "react";
import { ArrowUpRight, ChevronDown, Check, CircleCheck, CircleX, Clock3, ShieldAlert, ShieldCheck } from "lucide-react";
import usePortalResource from "../hooks/usePortalResource";
import { usePortal } from "./PortalContext";
import { useDetailView } from "./DetailView";
import { Badge, CopyId, Panel, ResourceNotice, useTime } from "./PortalUI";
import { analysisEventHref, incidentSectionHref, workloadJournalHref } from "../services/incidentLinks";
import { eventHref } from "../features/n91-investigation/workbenchModel";
import { InvestigationFlow } from "./InvestigationFlow";
import "./AutomaticResponse.css";
import { signalName, uiLabel } from "../services/uiLanguage";

const checks = {
  incident_policy: "Sự cố thuộc chính sách ứng phó",
  evidence_integrity: "Bằng chứng trực tiếp, yêu cầu độc lập, mã băm khớp",
  source_verification: "Xác minh IP → Port → máy ảo trên Neutron",
  target_allowlist: "Máy ảo thuộc danh sách được phép tự động cách ly",
  policy_authorization: "Chính sách cấp phép cách ly",
  recovery_ready: "Nhật ký Security Group và bộ giám sát phục hồi sẵn sàng",
};
const reasonNames = {
  AUTO_RULE_NOT_APPROVED:
    "Chính sách chưa cho phép tự động cách ly loại sự cố này.",
  AUTO_CANONICAL_EVIDENCE_NOT_VERIFIED:
    "Chưa đối chiếu được đầy đủ bằng chứng trong nhật ký kiểm toán chuẩn hóa.",
  AUTO_DIRECT_MEMBERSHIP_REQUIRED:
    "Thiếu liên kết sự kiện được bộ phát hiện lưu trực tiếp.",
  AUTO_INCIDENT_NOT_QUALIFIED:
    "Sự cố chưa đạt điều kiện định danh, thời điểm hoặc phiên bản bộ phát hiện.",
  AUTO_EVIDENCE_COUNT_INVALID:
    "Số bằng chứng chưa đủ hoặc không khớp bản chụp đã lưu.",
  AUTO_EVIDENCE_NOT_VERIFIED:
    "Bằng chứng thiếu xác minh, trùng yêu cầu hoặc không đúng mốc kích hoạt.",
  AUTO_WINDOW_OR_THRESHOLD_INVALID:
    "Chuỗi bằng chứng chưa đạt cửa sổ thời gian/ngưỡng đã cấu hình.",
  AUTO_CLONE_MAPPING_OR_BASELINE_CHANGED:
    "Định danh máy ảo, Port, IP hoặc Security Group gốc đã thay đổi.",
  AUTO_WATCHDOG_NOT_ACTIVE: "Bộ giám sát phục hồi chưa hoạt động.",
  AUTO_WATCHDOG_HEARTBEAT_MISSING_OR_STALE:
    "Không có nhịp hoạt động của bộ giám sát phục hồi còn hiệu lực.",
  AUTO_ALREADY_ISOLATED:
    "Máy ảo đang cách ly từ lần xử lý trước.",
  AUTO_SOURCE_OWNERSHIP_WINDOW_UNPROVEN:
    "Thiếu mẫu Neutron đủ mới trước hoặc sau cửa sổ sự kiện; chưa chứng minh quyền sở hữu nguồn.",
  AUTO_SOURCE_OWNERSHIP_CHANGED_DURING_EVIDENCE:
    "Định danh, phiên bản cấu hình hoặc Security Group của Port thay đổi trong cửa sổ sự kiện; không tự cô lập.",
  CORR002_VERIFIED_DISTINCT_LIVE_INJECTION:
    "CORR-002 có chuỗi yêu cầu trực tiếp, độc lập đã đối chiếu.",
  DEDICATED_CLONE_MAPPING_VERIFIED:
    "Đã đối chiếu đúng máy ảo thử nghiệm và Port tại thời điểm phản ứng.",
  OWNER_POLICY_ALLOWLIST_MATCH:
    "Đúng phạm vi chính sách thử nghiệm đã được chủ hệ thống cho phép.",
  DURABLE_RECOVERY_AND_WATCHDOG_READY:
    "Có nhật ký bền vững, kiểm tra phiên bản Port và bộ giám sát phục hồi còn hiệu lực.",
};
function recent(value, maximum) {
  const age = (Date.now() - Date.parse(value)) / 1000;
  return Number.isFinite(age) && age >= -1 && age <= maximum;
}
function timestampFromMs(value) {
  if (!Number.isFinite(value)) return null;
  const date = new Date(value);
  return Number.isFinite(date.valueOf()) ? date.toISOString() : null;
}
function decisionTitle(proof) {
  if (proof.reason_codes.includes("AUTO_RULE_NOT_APPROVED"))
    return `Sự cố ${proof.incident.correlation_rule || ""} nằm ngoài chính sách tự động`;
  if (proof.decision === "AUTHORIZED") return "Sự cố đủ điều kiện cách ly theo chính sách";
  const reason = proof.reason_codes.find((code) => reasonNames[code]);
  return reason ? reasonNames[reason] : "Quyết định đang cần rà soát";
}

function outcomeLabel(state, authorized) {
  const labels = {
    RESTORED: "Đã khôi phục máy ảo",
    QUARANTINED: "Máy ảo đang cách ly",
    APPLYING: "Đang áp dụng cách ly",
    RESTORING: "Đang khôi phục máy ảo",
    RESTORE_FAILED: "Chưa khôi phục được máy ảo",
  };
  return labels[state] || (authorized ? "Đã cấp phép cách ly" : "Sự cố này không kích hoạt cách ly");
}

function Decision({ row, open, currentPolicy }) {
  const time = useTime();
  const proof = row.evidence;
  const incident = proof.incident;
  const mapping = proof.source_verification;
  const detectionUrl = incidentSectionHref(row.incident_id, row.stream_id, "detection");
  const workloadUrl = workloadJournalHref(mapping?.server_id, row.operation_id);
  const ruleRejected = proof.reason_codes.includes("AUTO_RULE_NOT_APPROVED");
  return (
    <details className="auto-response-decision" open={open}>
      <summary>
        <span className="auto-response-identity">
          <strong>{row.incident_id}</strong>
          <time dateTime={row.decided_at}>{time(row.decided_at)}</time>
        </span>
        <span className="auto-response-tags">
          <Badge value={proof.decision === "AUTHORIZED" ? "VERIFIED" : "WARNING"}>
            {proof.decision === "AUTHORIZED" ? "Chính sách cho phép cách ly" : "Chính sách yêu cầu rà soát"}
          </Badge>
          <Badge value={row.state}>
            {!row.operation_id && row.state === "REVIEW_REQUIRED"
              ? "Không thực thi cách ly"
              : row.state === "QUARANTINED"
              ? "Thực thi: Đang cách ly"
              : row.state === "RESTORED"
                ? "Thực thi: Đã khôi phục"
                : uiLabel(row.state)}
          </Badge>
          <ChevronDown size={17} className="auto-response-chevron" aria-hidden="true" />
        </span>
      </summary>
      <section className="investigation-related" aria-label="Căn cứ quyết định">
        <strong>{decisionTitle(proof)}</strong>
        <p>
          Tín hiệu của sự cố: <b>{incident.correlation_rule || "Chưa ghi nhận"}</b>
          {signalName(incident.correlation_rule) && ` · ${signalName(incident.correlation_rule)}`}.
        </p>
        {currentPolicy?.rule && (
          <p>Chính sách áp dụng chấp nhận <b>{currentPolicy.rule}</b>
            {signalName(currentPolicy.rule) && ` · ${signalName(currentPolicy.rule)}`}.
          </p>
        )}
        {Number.isInteger(incident.evidence_count_recorded) && (
          <p>
            <b>{incident.evidence.length}/{incident.evidence_count_recorded} sự kiện</b> có chi tiết trong quyết định.
          </p>
        )}
        {ruleRejected && (
          <p>Bộ ứng phó dừng ở bước kiểm tra tín hiệu. Các điều kiện còn lại chưa được đánh giá.</p>
        )}
        {detectionUrl && <a href={detectionUrl}>Xem căn cứ phát hiện</a>}
        <a href="#/system/automatic-response">
          {currentPolicy ? "Xem chính sách đã áp dụng" : "Xem chính sách hiện tại"}
        </a>
        {workloadUrl && <a href={workloadUrl}>Xem lần cách ly trong nhật ký máy ảo</a>}
      </section>
      <DecisionDetails row={row} />
    </details>
  );
}

function TechnicalFields({ title, rows }) {
  return (
    <section className="auto-response-field-group">
      <h4>{title}</h4>
      <dl>
        {rows.map(([label, value, copyable]) => (
          <div key={label}>
            <dt>{label}</dt>
            <dd>
              {copyable && value ? (
                <><code>{value}</code><CopyId value={value} /></>
              ) : value ?? "—"}
            </dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

function DecisionDetails({ row }) {
  const time = useTime();
  const proof = row.evidence;
  const incident = proof.incident;
  const mapping = proof.source_verification;
  const ownership = mapping?.ownership_window;
  return (
    <>
      <details className="auto-response-detail">
      <summary>Điều kiện đã kiểm tra</summary>
      <div className="auto-response-checks">
        {Object.entries(checks).map(([key, label]) => {
          const status = proof.checks[key];
          const Icon =
            status === "PASS"
              ? CircleCheck
              : status === "FAIL"
                ? CircleX
                : Clock3;
          return (
            <div key={key} data-result={status}>
              <Icon size={19} />
              <span>
                {label}
                <small>
                  {status === "PASS"
                    ? "Đã xác minh"
                    : status === "FAIL"
                      ? "Chưa đạt"
                      : "Chưa đánh giá"}
                </small>
              </span>
            </div>
          );
        })}
      </div>
      <h4>Căn cứ quyết định</h4>
      <ul>
        {proof.reason_codes.map((reason) => (
          <li key={reason}>{reasonNames[reason] || reason}</li>
        ))}
      </ul>
      {row.error_code && (
        <p role="alert">
          Lỗi thực thi: {reasonNames[row.error_code] || row.error_code}
        </p>
      )}
      </details>
      <details className="auto-response-detail">
        <summary>Mã hồ sơ và chính sách</summary>
        <TechnicalFields title="Mã hồ sơ" rows={[
          ["Mã luồng", row.stream_id, true],
          ["Mã yêu cầu ứng phó", row.request_id, true],
          ["Mã lượt xử lý", row.operation_id, true],
          ["Mã bản chụp bằng chứng", incident.snapshot_id, true],
        ]} />
        <TechnicalFields title="Phiên bản và mã băm" rows={[
          ["Chính sách", uiLabel(proof.policy_version)],
          ["SHA-256 chính sách", row.policy_sha256, true],
          ["Phiên bản bộ phát hiện", uiLabel(incident.detector_version)],
          ["SHA-256 bộ phát hiện", incident.detector_sha256, true],
          ["SHA-256 bộ thực thi", proof.executor_code_sha256, true],
        ]} />
      </details>
      <details className="auto-response-detail">
        <summary>Xác minh máy ảo và Port</summary>
        {mapping ? (
          <TechnicalFields title="Ánh xạ Neutron" rows={[
            ["Xác minh lúc", time(mapping.observed_at)],
            ["IP nguồn", mapping.source_ip],
            ["Mã máy ảo", mapping.server_id, true],
            ["Mã dự án", mapping.project_id, true],
            ["Mã mạng", mapping.network_id, true],
            ["Mã Port", mapping.port_id, true],
            ["Phiên bản Port", mapping.revision_number],
            ["SHA-256 bản ánh xạ", mapping.snapshot_sha256, true],
          ]} />
        ) : <p>Hồ sơ chưa có ánh xạ máy ảo đã xác minh.</p>}
        <TechnicalFields title="Giám sát phục hồi" rows={[
          ["Lần ghi nhận trước khi cấp phép", proof.recovery_readiness ? time(proof.recovery_readiness.watchdog_last_success) : null],
        ]} />
        {ownership && (
          <details className="auto-response-window">
            <summary>Đối chiếu cấu hình mạng trước và sau truy vấn</summary>
            <TechnicalFields title="Khoảng đối chiếu" rows={[
              ["Bắt đầu", time(timestampFromMs(ownership.evidence_from_ms))],
              ["Kết thúc", time(timestampFromMs(ownership.evidence_to_ms))],
              ["Số mẫu Neutron đã kiểm tra", ownership.observations_checked],
              ["Phiên bản cổng trong khoảng này", "Ổn định"],
            ]} />
            {[
              ["Mẫu trước truy vấn", ownership.before],
              ["Mẫu sau truy vấn", ownership.after],
            ].map(([title, sample]) => (
              <TechnicalFields key={title} title={title} rows={[
                ["Quan sát lúc", time(sample.observed_at)],
                ["Phiên bản Port", sample.revision_number],
                ["SHA-256 bản ghi", sample.snapshot_sha256, true],
              ]} />
            ))}
          </details>
        )}
      </details>
      <details className="auto-response-detail">
        <summary>
          Truy vấn làm bằng chứng ({incident.evidence.length})
        </summary>
        <div className="table-scroll">
          <table className="v4-table">
            <thead>
              <tr>
                <th>Sự kiện / yêu cầu</th>
                <th>Thứ tự / thời gian yêu cầu</th>
                <th>Điểm rủi ro / quy tắc</th>
                <th>SHA-256 nhật ký chuẩn hóa</th>
              </tr>
            </thead>
            <tbody>
              {incident.evidence.map((event) => {
                const ref = { ...event, stream_id: row.stream_id };
                const sourceUrl = eventHref(ref, event.canonical_hash_verified ? "canonical" : "p17");
                const analysisUrl = analysisEventHref(ref);
                return (
                <tr key={event.event_id}>
                  <td>
                    {sourceUrl ? <a href={sourceUrl}>{event.event_id}</a> : event.event_id}
                    <small>{event.canonical_hash_verified ? "Nhật ký kiểm toán" : "Bản ghi bộ phát hiện"}</small>
                    <small>{event.request_id}</small>
                    {analysisUrl && <small><a href={analysisUrl}>Xem phân tích truy vấn</a></small>}
                  </td>
                  <td>
                    {event.seq}
                    <small>{time(timestampFromMs(event.ms))}</small>
                    <small>Mốc bộ phát hiện: lúc tiếp nhận yêu cầu</small>
                    {event.audit_occurred_at && <small>Nhật ký kiểm toán: {time(event.audit_occurred_at)}</small>}
                  </td>
                  <td>
                    {event.p15}
                    {(event.matched_rules || event.injection_rules || []).map((rule) => (
                      <small key={rule}>{rule}</small>
                    ))}
                    {event.db_user && <small>{event.db_user}</small>}
                  </td>
                  <td>
                    {event.payload_sha256}
                    <small>
                      {event.canonical_hash_verified
                        ? "Đã đối chiếu mã băm"
                        : "Chưa xác minh"}
                    </small>
                  </td>
                </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </details>
    </>
  );
}

function IncidentDecision({ row, currentPolicy, stale, children }) {
  const time = useTime();
  const { sessionVersion } = usePortal();
  const { compact } = useDetailView();
  const proof = row.evidence;
  const incident = proof.incident;
  const serverId = proof.source_verification?.server_id;
  const journalUrl = workloadJournalHref(serverId, row.operation_id);
  const journal = usePortalResource(
    journalUrl ? `/workloads/${encodeURIComponent(serverId)}/journal` : "",
    {
      scope: `response-journal:${sessionVersion}:${row.operation_id}:${row.state}`,
      enabled: Boolean(journalUrl),
      interval: 15000,
    },
  );
  const operation = journal.error ? null : journal.data?.operations?.find(
    (item) => item.server_id === serverId && item.operation_id === row.operation_id,
  );
  const authorized = proof.decision === "AUTHORIZED";
  const policyRejected = proof.reason_codes.includes("AUTO_RULE_NOT_APPROVED");
  const restoredAt = operation?.restored_at || row.restored_at;
  const quarantinedAt = operation?.quarantined_at;
  const restored = row.state === "RESTORED" || (operation?.state === "RESTORED" && Boolean(restoredAt));
  const state = restored ? "RESTORED" : row.state;
  const outcome = outcomeLabel(state, authorized);
  const OutcomeIcon = restored ? ShieldCheck : state === "RESTORE_FAILED" || !authorized ? ShieldAlert : Clock3;
  const sourceUrl = incidentSectionHref(row.incident_id, row.stream_id, "detection");
  const members = incident.evidence;
  const failedChecks = Object.keys(checks).filter((check) => proof.checks[check] === "FAIL");
  const passedChecks = Object.keys(checks).filter((check) => proof.checks[check] === "PASS").length;
  const hasBasis = failedChecks.length > 0 || passedChecks > 0 || Boolean(proof.policy_version || currentPolicy);
  const steps = [
    { label: "Cấp phép cách ly", stamp: row.decided_at, note: "Đã cấp phép", done: true },
    {
      label: "Cách ly kết nối",
      stamp: quarantinedAt,
      note: state === "QUARANTINED" ? "Đã xác nhận cách ly" : "Chưa có mốc cách ly được xác minh",
      done: Boolean(quarantinedAt) || state === "QUARANTINED",
    },
    {
      label: "Khôi phục kết nối",
      stamp: restoredAt,
      note: restored ? "Đã ghi nhận kết quả" : state === "QUARANTINED" ? "Chờ khôi phục từ Portal" : uiLabel(state),
      done: restored,
    },
  ];
  return (
    <>
      <section className="incident-outcome" data-state={state} aria-label="Kết quả ứng phó">
        <header className="incident-outcome-heading">
          <span className="incident-outcome-icon"><OutcomeIcon size={22} aria-hidden="true" /></span>
          <div>
            <h2>{outcome}</h2>
            {policyRejected ? (
              <p>Chính sách yêu cầu rà soát loại sự cố này.</p>
            ) : !authorized ? (
              <p>{decisionTitle(proof)}</p>
            ) : operation?.restore_trigger === "MANUAL" && restored ? <p>Khôi phục thủ công</p> : null}
            {stale && <p role="status">Đang xem kết quả từ lần đọc trước.</p>}
          </div>
          {journalUrl && (
            <a className="button secondary incident-outcome-journal" href={journalUrl}>
              Nhật ký máy ảo <ArrowUpRight size={15} aria-hidden="true" />
            </a>
          )}
        </header>
        {authorized ? (
          <ol className="incident-outcome-steps" aria-label="Các mốc xử lý đã ghi nhận">
            {steps.map(({ label, stamp, note, done }) => (
              <li key={label} data-done={done}>
                <span className="incident-outcome-marker" aria-hidden="true">{done && <Check size={13} />}</span>
                <div><strong>{label}</strong>{stamp ? <time dateTime={stamp}>{time(stamp)}</time> : <span>{note}</span>}</div>
              </li>
            ))}
          </ol>
        ) : (
          <div className="incident-outcome-evaluated">
            {row.decided_at && <span>Đánh giá lúc <time dateTime={row.decided_at}>{time(row.decided_at)}</time></span>}
            {sourceUrl && <a href={sourceUrl}>Xem hồ sơ phát hiện</a>}
          </div>
        )}
        {row.error_code && !proof.reason_codes.includes(row.error_code) && (
          <p className="incident-outcome-evaluated" role="status">{reasonNames[row.error_code] || uiLabel(row.error_code)}</p>
        )}
      </section>
      {authorized && (
      <section className="panel incident-decision-evidence" aria-label="Truy vấn dùng để quyết định">
        <div className="incident-decision-evidence-heading">
          <h3>{members.length ? `${members.length} truy vấn làm bằng chứng` : "Truy vấn làm bằng chứng"}</h3>
          {sourceUrl && <a href={sourceUrl}>Xem hồ sơ phát hiện <ArrowUpRight size={14} aria-hidden="true" /></a>}
        </div>
        {members.length ? (
          <ul>
            {members.map((event) => {
              const ref = { ...event, stream_id: row.stream_id };
              const href = eventHref(ref, event.canonical_hash_verified ? "canonical" : "p17");
              const stamp = event.audit_occurred_at || timestampFromMs(event.ms);
              const label = Number.isInteger(event.seq) ? `Truy vấn ${event.seq}` : event.event_id;
              return (
                <li key={event.event_id}>
                  {href ? <a href={href}>{label} <ArrowUpRight size={13} aria-hidden="true" /></a> : <strong>{label}</strong>}
                  {stamp && <time dateTime={stamp}>{time(stamp)}</time>}
                  {Number.isFinite(event.p15) && <span>Rủi ro {event.p15}/100</span>}
                </li>
              );
            })}
          </ul>
        ) : <p>Quyết định này chưa ghi chi tiết từng truy vấn.</p>}
        {Number.isInteger(incident.evidence_count_recorded) && members.length !== incident.evidence_count_recorded && (
          <p>Hồ sơ ghi nhận {incident.evidence_count_recorded} sự kiện. Quyết định có chi tiết của {members.length} sự kiện.</p>
        )}
      </section>
      )}
      {!compact ? (
        <details key="full" className="panel portal-provenance incident-decision-technical">
          <summary>Chi tiết đối chiếu</summary>
          <DecisionDetails row={row} />
          {children}
        </details>
      ) : hasBasis && (
        <details key="compact" className="panel portal-provenance incident-decision-basis">
          <summary>Căn cứ quyết định</summary>
          <dl>
            {failedChecks.length > 0 ? (
              <div>
                <dt>Điều kiện chưa đạt</dt>
                <dd>
                  {failedChecks.map((check) => <span key={check}>{checks[check]}</span>)}
                </dd>
              </div>
            ) : passedChecks > 0 && (
              <div>
                <dt>Điều kiện đã đạt</dt>
                <dd>{passedChecks}/{Object.keys(checks).length}</dd>
              </div>
            )}
            {proof.policy_version && <div><dt>Chính sách đã dùng</dt><dd>{uiLabel(proof.policy_version)}</dd></div>}
          </dl>
          {currentPolicy && <a href="#/system/automatic-response">Xem chính sách đã áp dụng</a>}
        </details>
      )}
    </>
  );
}

export default function AutomaticResponsePanel({ incidentId, streamId, summaryOnly = false, children }) {
  const { sessionAuthEnabled, sessionVersion } = usePortal();
  const { compact } = useDetailView();
  const extra = compact ? null : children;
  const time = useTime();
  const [, tick] = useState(0);
  const resource = usePortalResource("/system/automatic-response", {
    interval: 5000,
    scope: `automatic:${sessionVersion}`,
    enabled: sessionAuthEnabled,
  });
  useEffect(() => {
    const id = setInterval(() => tick((value) => value + 1), 5000);
    return () => clearInterval(id);
  }, []);
  const data = resource.data;
  if (!sessionAuthEnabled || (incidentId && data?.configured === false)) {
    return incidentId && !summaryOnly ? (
      <>
        <Panel title="Ứng phó"><p>Chưa có nguồn ứng phó tự động trong chế độ truy cập hiện tại.</p></Panel>
        {extra}
      </>
    ) : null;
  }
  const rows =
    data?.decisions?.filter(
      (row) =>
        !incidentId ||
        (row.incident_id === incidentId && row.stream_id === streamId),
    ) || [];
  const firstByIncident = new Set();
  const previousRows = [];
  const latestRows = rows.filter((row) => {
    const key = JSON.stringify([row.stream_id, row.incident_id]);
    if (firstByIncident.has(key)) {
      previousRows.push(row);
      return false;
    }
    firstByIncident.add(key);
    return true;
  });
  const feedFresh =
    data?.armed &&
    !data.source?.last_error &&
    recent(data.source?.last_success, data.policy.max_feed_age_seconds);
  const watchdogFresh = recent(data?.watchdog_last_success, 20);
  if (summaryOnly) {
    const row = latestRows[0];
    const responseUrl = incidentSectionHref(incidentId, streamId, "response");
    if (!row || !responseUrl || resource.error) return null;
    return (
      <section className="panel incident-overview-response" aria-label="Kết quả ứng phó của sự cố">
        <strong>{outcomeLabel(row.state, row.evidence.decision === "AUTHORIZED")}</strong>
        <a href={responseUrl}>Xem diễn biến ứng phó <ArrowUpRight size={14} aria-hidden="true" /></a>
      </section>
    );
  }
  if (incidentId && latestRows.length) {
    const row = latestRows[0];
    const policyAt = (decision) => decision.policy_sha256 && decision.policy_sha256 === data.policy_sha256 ? data.policy : null;
    return (
      <IncidentDecision
        row={row}
        currentPolicy={policyAt(row)}
        stale={Boolean(resource.error)}
      >
        {previousRows.length > 0 && (
          <details className="auto-response-detail">
            <summary>Các lần đánh giá trước ({previousRows.length})</summary>
            {previousRows.map((previous) => (
              <Decision key={previous.request_id} row={previous} currentPolicy={policyAt(previous)} />
            ))}
          </details>
        )}
        {extra}
      </IncidentDecision>
    );
  }
  return (
    <>
    {!incidentId && <InvestigationFlow current="response" />}
    <Panel
      title={incidentId ? "Quyết định ứng phó" : "Ứng phó tự động"}
    >
      <ResourceNotice resource={resource} />
      {data?.configured === false ? (
        <p>Chưa cấu hình kết nối bộ ứng phó tự động cho bản Portal này.</p>
      ) : (
        data && (
          <>
            {!incidentId && (
              <>
                <div className="auto-response-summary">
                  <div>
                    <small>Chính sách</small>
                    <strong>{data.armed ? "Đã kích hoạt" : "Chưa kích hoạt"}</strong>
                    <span>{uiLabel(data.policy.version)}</span>
                  </div>
                  <div>
                    <small>Nguồn sự cố</small>
                    <Badge value={feedFresh ? "FRESH" : "STALE"} />
                    <span>{time(data.source?.last_success)}</span>
                  </div>
                  <div>
                    <small>Giám sát phục hồi</small>
                    <Badge value={watchdogFresh ? "FRESH" : "STALE"} />
                    <span>{time(data.watchdog_last_success)}</span>
                  </div>
                  <div>
                    <small>Xác minh nguồn Neutron</small>
                    <Badge
                      value={
                        recent(
                          data.latest_source_verification?.observed_at,
                          data.policy.source_observation_max_gap_seconds,
                        )
                          ? "FRESH"
                          : "STALE"
                      }
                    />
                    <span>
                      {time(data.latest_source_verification?.observed_at)}
                    </span>
                  </div>
                  <div>
                    <small>Cách khôi phục</small>
                    <strong>Thủ công từ Portal</strong>
                    <span>Giám sát phục hồi chỉ xử lý lỗi / dang dở</span>
                  </div>
                </div>
                <p className="v4-proxy-snapshot">
                  CORR-002 · ≥ {data.policy.minimum_events} yêu cầu độc lập /{" "}
                  {data.policy.window_ms / 1000} giây · điểm rủi ro cao nhất ≥{" "}
                  {data.policy.minimum_peak_score} · Có đủ 6 điều kiện mới cấp
                  phép.
                </p>
                <details>
                  <summary>Mốc kích hoạt và phiên bản chính sách</summary>
                  <dl className="auto-response-facts">
                    <div>
                      <dt>Kích hoạt lúc</dt>
                      <dd>{time(data.source?.armed_at)}</dd>
                    </div>
                    <div>
                      <dt>Bỏ qua sự kiện đến thứ tự</dt>
                      <dd>{data.source?.watermark}</dd>
                    </div>
                    <div>
                      <dt>SHA-256 chính sách</dt>
                      <dd>{data.policy_sha256}</dd>
                    </div>
                    <div>
                      <dt>Bộ thực thi SHA-256</dt>
                      <dd>{data.executor_code_sha256}</dd>
                    </div>
                    <div>
                      <dt>Nguồn ngưỡng hiện có</dt>
                      <dd>
                        Bộ kiểm tra điều kiện cách ly hiện có
                        <br />
                        {data.policy.threshold_reference_sha256}
                      </dd>
                    </div>
                    <div>
                      <dt>Lần thử đọc / mã lỗi</dt>
                      <dd>
                        {time(data.source?.last_attempt)} /{" "}
                        {data.source?.last_error ||
                          "Không có lỗi được ghi nhận"}
                      </dd>
                    </div>
                  </dl>
                </details>
                <h3>Quyết định gần đây</h3>
              </>
            )}
            {latestRows.length ? (
              latestRows.map((row, index) => (
                <Decision key={row.request_id} row={row} open={index === 0}
                  currentPolicy={row.policy_sha256 && row.policy_sha256 === data.policy_sha256 ? data.policy : null} />
              ))
            ) : (
              <p>
                Chưa có quyết định trong phạm vi đang xem.
              </p>
            )}
            {previousRows.length > 0 && (
              <details>
                <summary>Các lần đánh giá trước ({previousRows.length})</summary>
                {previousRows.map((row) => (
                  <Decision key={row.request_id} row={row}
                    currentPolicy={row.policy_sha256 && row.policy_sha256 === data.policy_sha256 ? data.policy : null} />
                ))}
              </details>
            )}
            {!incidentId && (
              <small>
                Nhật ký hiển thị tối đa 50 quyết định gần nhất.
              </small>
            )}
          </>
        )
      )}
    </Panel>
    {extra}
    </>
  );
}
