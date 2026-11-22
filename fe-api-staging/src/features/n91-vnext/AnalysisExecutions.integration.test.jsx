import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { AnalysisExecutions } from "./AnalysisExecutions";
import { PortalContext } from "../../portal/PortalContext";

afterEach(cleanup);

it("shows two verified operations in one analysis case and links only exact requests", () => {
  const targetId = "test-vm";
  const streamId = "test-stream";
  const date = "2026-11-21T15:52:00Z";
  const analysisCase = { case_id: "same-case", stream_id: streamId, source_ip: "192.0.2.10" };
  const newEvent = {
    stream_id: streamId, case_id: analysisCase.case_id, event_id: "test-new",
    request_id: "new-request", event_time: date, stream_sequence: 21,
  };
  const olderEvent = { ...newEvent, event_id: "test-old", request_id: "old-request", stream_sequence: 11 };
  const decisions = [
    ["test-current", "test-new-incident", "AUTHORIZED", [newEvent, { ...olderEvent, request_id: "wrong-request" }]],
    ["test-restored", "test-older-incident", "AUTHORIZED", [olderEvent]],
    ["test-not-verified", "test-unconfirmed-incident", "AUTHORIZED", [newEvent]],
    ["test-manual", "test-review-incident", "REVIEW_REQUIRED", []],
  ].map(([operation_id, incident_id, decision, evidence]) => ({
    operation_id, incident_id, stream_id: streamId,
    evidence: { decision, incident: { correlation_rule: "CORR-002", evidence } },
  }));
  const operations = [
    ["test-current", "QUARANTINED", "2026-11-21T16:50:00Z", null],
    ["test-restored", "RESTORED", date, "2026-11-21T15:56:00Z"],
    ["test-not-verified", "APPLYING", null, null],
    ["test-manual", "RESTORED", date, "2026-11-21T15:56:00Z"],
  ].map(([operation_id, state, quarantined_at, restored_at]) => ({
    operation_id, server_id: targetId, state, quarantined_at, restored_at,
  }));
  render(
    <PortalContext.Provider value={{ timezone: "UTC" }}>
      <AnalysisExecutions
        response={{ data: { configured: true, decisions } }}
        journal={{ data: { operations } }}
        targetId={targetId}
        cases={[analysisCase]}
        events={[newEvent, olderEvent]}
      />
    </PortalContext.Provider>,
  );

  expect(screen.getByText("2 lần đã thực thi")).toBeTruthy();
  const current = screen.getByText("Đang cách ly").closest("li");
  const restored = screen.getByText("Đã khôi phục").closest("li");
  expect(within(current).getByRole("link", { name: "Mở quyết định của sự cố" }).getAttribute("href"))
    .toBe("#/incidents/test-new-incident?stream_id=test-stream&wb_tab=response");
  expect(within(restored).getByRole("link", { name: "Mở nhật ký cách ly và khôi phục" }).getAttribute("href"))
    .toBe("#/workloads/test-vm?operation_id=test-restored");
  expect(screen.getAllByRole("link", { name: "Hồ sơ phân tích của IP 192.0.2.10" })).toHaveLength(2);
  fireEvent.click(within(current).getByText("2 truy vấn làm bằng chứng"));
  expect(within(current).getByRole("link", { name: /Truy vấn số 21/ }).getAttribute("href"))
    .toContain("request_id=new-request");
  expect(within(current).queryByText(/Truy vấn số 11/)).toBeNull();
});
