import { ArrowRight, ScanSearch } from "lucide-react";
import usePortalResource from "../hooks/usePortalResource";
import { analysisEventHref, incidentSectionHref, sameRequestEvent } from "../services/incidentLinks";
import { usePortal } from "./PortalContext";
import "./InvestigationFlow.css";

const steps = [
  ["event", "Sự kiện bảo mật", "Tường lửa ghi lại từng truy vấn được cho phép hoặc bị chặn.", "#/events?source=canonical"],
  ["incident", "Sự cố", "Bộ phát hiện liên kết các sự kiện theo mẫu hành vi và lưu căn cứ.", "#/incidents"],
  ["response", "Ứng phó tự động", "Bộ điều khiển đánh giá chính sách và ghi kết quả cách ly.", "#/system/automatic-response"],
];

export function InvestigationFlow({ current }) {
  return (
    <section className="investigation-flow" aria-label="Luồng điều tra và ứng phó">
      <h2>Luồng điều tra và ứng phó</h2>
      <ol>
        {steps.map(([key, label, description, url]) => (
          <li key={key}>
            <a href={url} aria-current={current === key ? "step" : undefined}>{label}</a>
            <p>{description}</p>
            {key !== "response" && <ArrowRight className="investigation-flow-arrow" size={16} aria-hidden="true" />}
          </li>
        ))}
      </ol>
      <p className="investigation-flow-branch">
        <ScanSearch size={16} aria-hidden="true" />
        <span>
          <a href="#/incidents?analysis=1">Phân tích hành vi</a> giúp xem sâu các mẫu và truy vấn
          liên quan.
        </span>
      </p>
    </section>
  );
}

export function EventInvestigationLinks({ event, analysis = false }) {
  const { sessionVersion, auth, mode } = usePortal();
  const analysisUrl = analysisEventHref(event);
  const { event_id, stream_id } = event;
  const resource = usePortalResource(analysisUrl ? `/events/${encodeURIComponent(event_id)}` : "", {
    params: { source: "p17", stream_id },
    enabled: Boolean(analysisUrl && event.request_id && mode === "v4" && auth?.status !== "checking"),
    interval: 0,
    scope: `${sessionVersion}:${auth?.status}:${auth?.user?.user_id || ""}`,
  });
  if (!analysisUrl) return null;

  const projection = resource.error ? null : resource.data;
  const matched = sameRequestEvent(event, projection);
  const refs = matched && Array.isArray(projection.incident_refs) ? [...new Set(projection.incident_refs)] : [];
  const savedLinks = refs.map((id) => ({
    id,
    href: incidentSectionHref(id, stream_id, "detection"),
  })).filter((link) => link.href);

  return (
    <section className="investigation-related" aria-label="Liên kết điều tra sự kiện">
      <strong>Tiếp tục điều tra sự kiện này</strong>
      {!analysis && <a href={analysisUrl}>Xem phân tích hành vi của truy vấn</a>}
      {resource.loading ? (
        <p>Đang đối chiếu mã luồng, sự kiện và yêu cầu…</p>
      ) : savedLinks.length ? (
        <>
          <p>{projection.incident_membership === "DIRECT_PERSISTED"
            ? "Liên kết sự cố đã lưu cho đúng yêu cầu:"
            : "Sự cố từ đối chiếu lịch sử. Danh sách có thể gồm liên kết được dựng lại:"}</p>
          <ul>
            {savedLinks.map((link) => <li key={link.id}><a href={link.href}>{link.id}</a></li>)}
          </ul>
        </>
      ) : (
        <p>{resource.error && resource.error.status !== 404
          ? "Chưa đọc được nguồn liên kết sự cố."
          : "Chưa tìm thấy liên kết sự cố cho đúng mã yêu cầu trong dữ liệu đã đọc."}</p>
      )}
    </section>
  );
}
