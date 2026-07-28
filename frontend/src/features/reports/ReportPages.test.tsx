import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it, vi } from "vitest";
import { renderRoute } from "../../test/render";

const { downloadReport } = vi.hoisted(() => ({ downloadReport: vi.fn() }));
vi.mock("./report-download", () => ({ downloadReport }));

it("renders each backend report Finding with its attack flow", async () => {
  renderRoute("/scans/scan-001/ai-report");
  expect(await screen.findByText("확인된 Finding을 우선순위에 따라 검토하세요.")).toBeVisible();
  expect(screen.getByRole("link", { name: "finding-001 →" })).toBeVisible();
  expect(screen.getAllByRole("listitem").map((item) => item.textContent)).toEqual(["대상 식별", "권한 검증"]);
});
it("navigates to print preview", async () => {
  const { router } = renderRoute("/scans/scan-001/ai-report");
  await screen.findByText("확인된 Finding을 우선순위에 따라 검토하세요.");
  await userEvent.click(screen.getByRole("link", { name: "미리보기" }));
  expect(router.state.location.pathname).toMatch(/preview$/);
  expect(await screen.findByText("VulnScope 보안 리포트")).toBeVisible();
  await userEvent.click(screen.getByRole("link", { name: /AI 리포트로 돌아가기/ }));
  expect(router.state.location.pathname).toBe("/scans/scan-001/ai-report");
});
it("starts a report download with the backend report id", async () => {
  renderRoute("/scans/scan-001/ai-report");
  await screen.findByText("확인된 Finding을 우선순위에 따라 검토하세요.");
  await userEvent.click(screen.getByRole("button", { name: "PDF 다운로드" }));
  expect(downloadReport).toHaveBeenCalledWith(expect.anything(), "report-001", "scan-001");
});
