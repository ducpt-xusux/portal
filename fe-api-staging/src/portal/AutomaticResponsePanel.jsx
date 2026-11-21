import { useEffect, useState } from "react";
import { ShieldCheck, CircleCheck, CircleX, Clock3 } from "lucide-react";
import usePortalResource from "../hooks/usePortalResource";
import { usePortal } from "./PortalContext";
import { Badge, Panel, ResourceNotice, useTime } from "./PortalUI";
import { incidentHref } from "../services/incidentLinks";
import "./AutomaticResponse.css";
import { uiLabel } from "../services/uiLanguage";

const checks = {
  incident_policy: "Sự cố thuộc chính sách phản ứng",
  evidence_integrity: "Bằng chứng trực tiếp, yêu cầu độc lập, mã băm khớp",
  source_verification: "Xác minh IP → cổng mạng → máy ảo trên Neutron",
  target_allowlist: "Máy ảo thuộc danh sách được phép tự động cách ly",
  policy_authorization: "Bộ đánh giá chính sách cấp phép phản ứng",
  recovery_ready: "Nhật ký nhóm bảo mật và bộ giám sát phục hồi sẵn sàng",
};
const reasonNames = {
  AUTO_RULE_NOT_APPROVED:
    "Loại sự cố chưa được chính sách cho phép tự phản ứng.",
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
    "Định danh máy ảo, cổng mạng, IP hoặc nhóm bảo mật gốc đã thay đổi.",
  AUTO_WATCHDOG_NOT_ACTIVE: "Bộ giám sát phục hồi chưa hoạt động.",
  AUTO_WATCHDOG_HEARTBEAT_MISSING_OR_STALE:
    "Không có nhịp hoạt động của bộ giám sát phục hồi còn hiệu lực.",
  AUTO_ALREADY_ISOLATED:
    "VM đã có lượt cách ly đang hoạt động; không xử lý lặp.",
  AUTO_SOURCE_OWNERSHIP_WINDOW_UNPROVEN:
    "Thiếu mẫu Neutron đủ mới trước hoặc sau cửa sổ sự kiện; chưa chứng minh quyền sở hữu nguồn.",
  AUTO_SOURCE_OWNERSHIP_CHANGED_DURING_EVIDENCE:
    "Định danh, phiên bản cấu hình hoặc nhóm bảo mật của cổng mạng thay đổi trong cửa sổ sự kiện; không tự cô lập.",
  CORR002_VERIFIED_DISTINCT_LIVE_INJECTION:
    "CORR-002 có chuỗi yêu cầu trực tiếp, độc lập đã đối chiếu.",
  DEDICATED_CLONE_MAPPING_VERIFIED:
    "Đã đối chiếu đúng máy ảo thử nghiệm và cổng mạng tại thời điểm phản ứng.",
  OWNER_POLICY_ALLOWLIST_MATCH:
    "Đúng phạm vi chính sách thử nghiệm đã được chủ hệ thống cho phép.",
  DURABLE_RECOVERY_AND_WATCHDOG_READY:
    "Có nhật ký bền vững, kiểm tra phiên bản cổng mạng và bộ giám sát phục hồi còn hiệu lực.",
};
function recent(value, maximum) {
  const age = (Date.now() - Date.parse(value)) / 1000;
  return Number.isFinite(age) && age >= -1 && age <= maximum;
}
function Decision({ row, open }) {
  const time = useTime();
  const proof = row.evidence;
  const incident = proof.incident;
  const mapping = proof.source_verification;
  return (
    <details className="auto-response-decision" open={open}>
      <summary>
        <span>
          <strong>{row.incident_id}</strong>
          <small>{time(row.decided_at)}</small>
        </span>
        <span
          className={`v4-badge ${proof.decision === "AUTHORIZED" ? "good" : "warn"}`}
        >
          {proof.decision === "AUTHORIZED" ? "Được cấp phép" : "Cần rà soát"}
        </span>
        <Badge value={row.state} />
      </summary>
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
      <div className="auto-response-links">
        <a href={incidentHref(row.incident_id, row.stream_id)}>
          Mở hồ sơ sự cố
        </a>
        <a href={`#/workloads/${"fa34f3e8-50ff-467e-a7db-a5cd92613682"}`}>
          Xem SG / Khôi phục VM
        </a>
      </div>
      <details>
        <summary>Định danh, chính sách và nguồn xác minh</summary>
        <dl className="auto-response-facts">
          <div>
            <dt>Mã luồng</dt>
            <dd>{row.stream_id}</dd>
          </div>
          <div>
            <dt>Mã yêu cầu phản ứng</dt>
            <dd>{row.request_id}</dd>
          </div>
          <div>
            <dt>Mã lượt xử lý</dt>
            <dd>{row.operation_id || "Không thực thi"}</dd>
          </div>
          <div>
            <dt>Chính sách / SHA-256</dt>
            <dd>
              {uiLabel(proof.policy_version)}
              <br />
              {row.policy_sha256}
            </dd>
          </div>
          <div>
            <dt>Bản chụp bằng chứng phát hiện</dt>
            <dd>{incident.snapshot_id || "Nguồn chưa lưu"}</dd>
          </div>
          <div>
            <dt>Bộ phát hiện / SHA-256</dt>
            <dd>
              {incident.detector_version ? uiLabel(incident.detector_version) : "Nguồn chưa lưu"}
              <br />
              {incident.detector_sha256}
            </dd>
          </div>
          <div>
            <dt>Mã bộ thực thi SHA-256</dt>
            <dd>{proof.executor_code_sha256}</dd>
          </div>
          <div>
            <dt>Xác minh Neutron lúc</dt>
            <dd>{mapping ? time(mapping.observed_at) : "Chưa xác minh"}</dd>
          </div>
          <div>
            <dt>Máy ảo / Dự án</dt>
            <dd>
              {mapping
                ? `${mapping.server_id} / ${mapping.project_id}`
                : "Chưa xác minh"}
            </dd>
          </div>
          <div>
            <dt>IP / Cổng mạng / Mạng</dt>
            <dd>
              {mapping
                ? `${mapping.source_ip} / ${mapping.port_id} / ${mapping.network_id}`
                : "Chưa xác minh"}
            </dd>
          </div>
          <div>
            <dt>Phiên bản cổng mạng / mã băm ánh xạ</dt>
            <dd>
              {mapping
                ? `${mapping.revision_number} / ${mapping.snapshot_sha256}`
                : "Chưa xác minh"}
            </dd>
          </div>
          <div>
            <dt>Bộ giám sát phục hồi tại lúc cấp phép</dt>
            <dd>
              {proof.recovery_readiness
                ? time(proof.recovery_readiness.watchdog_last_success)
                : "Chưa xác minh"}
            </dd>
          </div>
          {mapping?.ownership_window && (
            <>
              <div>
                <dt>Mẫu Neutron trước sự kiện</dt>
                <dd>
                  {time(mapping.ownership_window.before.observed_at)}
                  <br />
                  Phiên bản cổng {mapping.ownership_window.before.revision_number}
                  <br />
                  {mapping.ownership_window.before.snapshot_sha256}
                </dd>
              </div>
              <div>
                <dt>Mẫu Neutron sau sự kiện</dt>
                <dd>
                  {time(mapping.ownership_window.after.observed_at)}
                  <br />
                  Phiên bản cổng {mapping.ownership_window.after.revision_number}
                  <br />
                  {mapping.ownership_window.after.snapshot_sha256}
                </dd>
              </div>
              <div>
                <dt>Cửa sổ đã đối chiếu</dt>
                <dd>
                  {time(
                    new Date(
                      mapping.ownership_window.evidence_from_ms,
                    ).toISOString(),
                  )}{" "}
                  →{" "}
                  {time(
                    new Date(
                      mapping.ownership_window.evidence_to_ms,
                    ).toISOString(),
                  )}
                  <br />
                  {mapping.ownership_window.observations_checked} mẫu Neutron,
                  phiên bản cổng mạng ổn định
                </dd>
              </div>
            </>
          )}
        </dl>
      </details>
      <details>
        <summary>
          Sự kiện / yêu cầu / mã băm làm bằng chứng ({incident.evidence.length})
        </summary>
        <div className="table-scroll">
          <table className="v4-table">
            <thead>
              <tr>
                <th>SỰ KIỆN / YÊU CẦU</th>
                <th>THỨ TỰ / THỜI GIAN YÊU CẦU</th>
                <th>ĐIỂM RỦI RO / QUY TẮC</th>
                <th>SHA-256 NHẬT KÝ CHUẨN HÓA</th>
              </tr>
            </thead>
            <tbody>
              {incident.evidence.map((event) => (
                <tr key={event.event_id}>
                  <td>
                    {event.event_id}
                    <small>{event.request_id}</small>
                  </td>
                  <td>
                    {event.seq}
                    <small>{time(new Date(event.ms).toISOString())}</small>
                    <small>Mốc bộ phát hiện: lúc tiếp nhận yêu cầu</small>
                    {event.audit_occurred_at && <small>Nhật ký kiểm toán: {time(event.audit_occurred_at)}</small>}
                  </td>
                  <td>
                    {event.p15}
                    <small>
                      {(event.matched_rules || event.injection_rules).join(
                        ", ",
                      )}
                    </small>
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
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </details>
  );
}

export default function AutomaticResponsePanel({ incidentId, streamId }) {
  const { sessionAuthEnabled, sessionVersion } = usePortal();
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
  if (!sessionAuthEnabled || (incidentId && data?.configured === false))
    return null;
  const rows =
    data?.decisions?.filter(
      (row) =>
        !incidentId ||
        (row.incident_id === incidentId && row.stream_id === streamId),
    ) || [];
  const feedFresh =
    data?.armed &&
    !data.source?.last_error &&
    recent(data.source?.last_success, data.policy.max_feed_age_seconds);
  const watchdogFresh = recent(data?.watchdog_last_success, 20);
  return (
    <Panel
      title="Ứng phó tự động"
      subtitle={
        incidentId
          ? "Quyết định ứng phó tự động cho đúng sự cố và luồng dữ liệu này"
          : "Chính sách thử nghiệm chỉ cấp phép cho máy ảo thử nghiệm cách ly"
      }
      action={<ShieldCheck size={22} />}
    >
      <ResourceNotice resource={resource} />
      {data?.configured === false ? (
        <p>Chưa cấu hình kết nối bộ ứng phó tự động cho bản Portal này.</p>
      ) : (
        data && (
          <>
            {!incidentId && (
              <>
                <p>
                  DB Firewall xử lý từng truy vấn. Lớp phản ứng này hạn chế
                  nguồn trong môi trường thử nghiệm tiếp tục phát sinh lưu lượng trái chính sách trong
                  phạm vi nhóm bảo mật áp dụng.
                </p>
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
                    <small>Khôi phục thành công</small>
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
                <h3>Quyết định phản ứng gần đây</h3>
              </>
            )}
            {rows.length ? (
              rows.map((row, index) => (
                <Decision key={row.request_id} row={row} open={index === 0} />
              ))
            ) : (
              <p>
                Chưa có quyết định mới trong phạm vi này sau mốc kích hoạt. Một sự kiện
                bị chặn hoặc một sự cố mức cao riêng lẻ không tự cấp phép cô lập.
              </p>
            )}
            {!incidentId && (
              <small>
                Hiển thị tối đa 50 quyết định gần nhất. Bằng chứng và lịch sử SG
                được lưu bền vững trên bộ điều khiển.
              </small>
            )}
          </>
        )
      )}
    </Panel>
  );
}
