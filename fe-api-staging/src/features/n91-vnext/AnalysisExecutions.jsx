import { Badge, Panel, useTime } from "../../portal/PortalUI";
import { useV4Resource } from "../../portal/IncidentPages";
import {
  analysisCaseHref,
  analysisEventHref,
  incidentSectionHref,
  sameRequestEvent,
  workloadJournalHref,
} from "../../services/incidentLinks";
import { signalName } from "../../services/uiLanguage";

const list = (value) => (Array.isArray(value) ? value : []);

export function useAnalysisExecutions(enabled) {
  const response = useV4Resource("/system/automatic-response", {
    enabled,
    interval: 20000,
  });
  const targetId = response.data?.target_id;
  const journal = useV4Resource(
    targetId ? `/workloads/${encodeURIComponent(targetId)}/journal` : "",
    { enabled: enabled && Boolean(targetId), interval: 20000 },
  );
  return { response, targetId, journal };
}

export function AnalysisExecutions({ response, targetId, journal, cases, events }) {
  const time = useTime();
  const decisions = new Map();
  for (const decision of list(response.data?.decisions)) {
    const id = decision.operation_id;
    if (id && decision.evidence?.decision === "AUTHORIZED" && !decisions.has(id))
      decisions.set(id, decision);
  }
  const completed = list(journal.data?.operations)
    .filter((operation) =>
      operation.server_id === targetId &&
      decisions.has(operation.operation_id) &&
      Number.isFinite(Date.parse(operation.quarantined_at)),
    )
    .sort((a, b) => Date.parse(b.quarantined_at) - Date.parse(a.quarantined_at));
  const available = response.data?.configured === true && journal.data && !response.error && !journal.error;
  return (
    <Panel
      title="Các lần cách ly tự động"
      action={available ? <span className="n91-analysis-count">{completed.length} lần đã thực thi</span> : null}
    >
      {response.error || journal.error ? (
        <p className="muted" role="status">Chưa đọc được nhật ký ứng phó. Bấm Làm mới để kiểm tra lại.</p>
      ) : response.data?.configured === false ? (
        <p className="muted">Nguồn ứng phó tự động chưa được cấu hình.</p>
      ) : !available ? (
        <p className="muted" role="status">Đang đối chiếu quyết định và nhật ký cách ly…</p>
      ) : completed.length ? (
        <ol className="n91-analysis-executions">
          {completed.map((operation) => {
            const row = decisions.get(operation.operation_id);
            const incident = row.evidence.incident;
            const incidentUrl = incidentSectionHref(row.incident_id, row.stream_id, "response");
            const journalUrl = workloadJournalHref(targetId, operation.operation_id);
            const members = list(incident?.evidence);
            const matched = events.filter((event) =>
              members.some((member) => sameRequestEvent(event, { ...member, stream_id: row.stream_id })),
            );
            const relatedCases = cases.filter((item) =>
              matched.some((event) => event.case_id === item.case_id && event.stream_id === item.stream_id),
            );
            return (
              <li key={operation.operation_id}>
                <div className="n91-analysis-execution-head">
                  <div>
                    <strong>Cách ly lúc {time(operation.quarantined_at)}</strong>
                    <p>
                      {signalName(incident?.correlation_rule) || "Tín hiệu cách ly theo chính sách"}
                      {operation.restored_at && <> · Khôi phục lúc {time(operation.restored_at)}</>}
                    </p>
                  </div>
                  <Badge value={operation.state} />
                </div>
                <div className="n91-analysis-links">
                  {incidentUrl && <a href={incidentUrl}>Mở quyết định của sự cố</a>}
                  {journalUrl && <a href={journalUrl}>Mở nhật ký cách ly và khôi phục</a>}
                  {relatedCases.map((item) => (
                    <a key={item.case_id} href={analysisCaseHref(item.case_id, item.stream_id)}>
                      Hồ sơ phân tích của IP {item.source_ip}
                    </a>
                  ))}
                </div>
                {members.length > 0 && (
                  <details className="n91-analysis-execution-evidence">
                    <summary>{members.length} truy vấn làm bằng chứng</summary>
                    {matched.length > 0 && (
                      <ul>
                        {matched.map((event) => (
                          <li key={event.event_id}><a href={analysisEventHref(event)}>
                            Truy vấn số {event.stream_sequence} · {time(event.event_time)}
                          </a></li>
                        ))}
                      </ul>
                    )}
                    {matched.length < members.length && (
                      <p>Bản xuất phân tích hiện có {matched.length}/{members.length} truy vấn. Mở quyết định để đối chiếu bằng chứng của lần cách ly.</p>
                    )}
                  </details>
                )}
              </li>
            );
          })}
        </ol>
      ) : (
        <p className="muted">Chưa thấy lần cách ly đã thực thi trong các quyết định gần nhất.</p>
      )}
    </Panel>
  );
}
