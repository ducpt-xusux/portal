import { useV4Resource } from "./IncidentPages";
import { Panel, useTime } from "./PortalUI";
import { FileCheck2, ChevronDown } from "lucide-react";
import { uiLabel } from "../services/uiLanguage";

const valueText = (value) =>
  value === true
    ? "Có"
    : value === false
      ? "Không"
      : value === "NOT_MEASURED"
        ? "Không được đo trong lần thử này"
        : uiLabel(value);

export default function ReportEvidencePanel() {
  const time = useTime();
  const resource = useV4Resource("/system/report-evidence", { interval: 0 });
  return (
    <Panel
      title="Bằng chứng TLS, quyền SQL và khôi phục"
      resource={resource}
    >
      {resource.data?.artifacts.map((artifact, index) => (
        <details
          className="portal-report-artifact"
          key={artifact.evidence_id}
          open={index === 0}
        >
          <summary>
            <FileCheck2 size={20} />
            <div>
              <h3>{uiLabel(artifact.title)}</h3>
              <small>{time(artifact.observed_at)}</small>
            </div>
            <ChevronDown size={17} />
          </summary>
          <div className="portal-report-body">
            <p>{uiLabel(artifact.scope)}</p>
            <details>
              <summary>Mã băm nguồn</summary>
              <code>{artifact.source_sha256}</code>
            </details>
            <div className="table-scroll">
              <table className="v4-table">
                <thead>
                  <tr>
                    <th>Trường nguồn</th>
                    <th>Kết quả đã ghi nhận</th>
                  </tr>
                </thead>
                <tbody>
                  {artifact.facts.map((fact) => (
                    <tr key={fact.key}>
                      <td title={fact.key}>{uiLabel(fact.key)}</td>
                      <td>{valueText(fact.value)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </details>
      ))}
    </Panel>
  );
}
