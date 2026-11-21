import { useV4Resource } from "./IncidentPages";
import { Badge, Panel, useTime } from "./PortalUI";
import { Check, LockKeyhole, ChevronDown, Clock3 } from "lucide-react";
import { uiLabel } from "../services/uiLanguage";

const groups = (values) =>
  Array.isArray(values)
    ? values.join(" · ") || "Không gán SG"
    : "Không có bản ghi SG";

export default function QuarantineJournal({ serverId }) {
  const time = useTime();
  const resource = useV4Resource(
    `/workloads/${encodeURIComponent(serverId)}/journal`,
    { interval: 15000 },
  );
  if (!resource.data?.operations?.length) return null;
  return (
    <Panel
      title="Nhật ký cách ly và khôi phục"
      subtitle="Các lượt xử lý và bằng chứng nhóm bảo mật đã lưu"
      className="vm-journal-panel"
      action={
        <span className="vm-journal-count">
          {resource.data.operations.length} lượt ghi nhận
        </span>
      }
    >
      <div className="vm-journal-list">
        {resource.data.operations.map((operation) => (
          <details className="vm-journal-entry" key={operation.operation_id}>
            <summary>
              <span className="vm-journal-icon">
                {operation.state === "RESTORED" ? (
                  <Check size={17} />
                ) : (
                  <LockKeyhole size={16} />
                )}
              </span>
              <span className="vm-journal-description">
                <strong>{time(operation.started_at)}</strong>
                <small>{operation.operation_id}</small>
              </span>
              <Badge value={operation.state} />
              <ChevronDown className="vm-journal-chevron" size={16} />
            </summary>
            <div className="table-scroll">
              <table className="v4-table">
                <thead>
                  <tr>
                    <th>GIAI ĐOẠN</th>
                    <th>CỔNG MẠNG</th>
                    <th>NHÓM BẢO MẬT ĐÃ GHI NHẬN</th>
                    <th>PHIÊN BẢN CỔNG</th>
                    <th>MỐC NHẬT KÝ</th>
                  </tr>
                </thead>
                <tbody>
                  {operation.ports.map((port) => (
                    <tr key={`baseline:${port.port_id}`}>
                      <td>Trước cách ly</td>
                      <td>{port.port_id}</td>
                      <td>{groups(port.security_group_ids)}</td>
                      <td>{port.revision_number}</td>
                      <td>{time(operation.started_at)}</td>
                    </tr>
                  ))}
                  {operation.events.flatMap((event, index) =>
                    ["before", "after"].flatMap((stage) =>
                      (event[stage] || []).map((port) => (
                        <tr key={`${index}:${stage}:${port.port_id}`}>
                          <td>
                            {event.action === "WORKLOAD_RESTORE"
                              ? "Khôi phục"
                              : "Cách ly"}{" "}
                            ·{" "}
                            {stage === "before"
                              ? "Trước thực thi"
                              : "Kết quả xác minh"}
                            <br />
                            {uiLabel(event.outcome)}
                          </td>
                          <td>{port.port_id}</td>
                          <td>{groups(port.security_group_ids)}</td>
                          <td>{port.revision_number}</td>
                          <td>{time(event.timestamp)}</td>
                        </tr>
                      )),
                    ),
                  )}
                </tbody>
              </table>
            </div>
          </details>
        ))}
      </div>
      <p className="vm-journal-footnote">
        <Clock3 size={15} />
        <span>
          Đọc nhật ký lúc {time(resource.data.collected_at)}. Trạng thái mạng
          hiện tại được xác minh riêng qua Neutron.
        </span>
      </p>
    </Panel>
  );
}
