import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it } from "vitest";
import { MockScannerService } from "../../services/mock/mock-scanner-service";
import { mockScanResult } from "../../services/mock/mock-data";
import { renderRoute } from "../../test/render";
it("renders summary metrics and real detail destinations", async () => {
  const { router } = renderRoute("/scans/scan-001/overview");
  expect(screen.getByRole("status", { name: "Loading content" })).toBeVisible();
  expect(await screen.findByText("Discovered APIs")).toBeVisible();
  for (const destination of ["progress", "apis", "findings", "ai-report"])
    expect(
      document.querySelector(`.metrics a[href$="${destination}"]`),
    ).toBeInTheDocument();
  await userEvent.click(screen.getByText("Scan pipeline"));
  expect(router.state.location.pathname).toBe("/scans/scan-001/progress");
});

it("renders query error and retry states", async () => {
  class FailingService extends MockScannerService {
    override async getOverview(): Promise<never> {
      throw new Error("overview unavailable");
    }
  }
  renderRoute("/scans/scan-001/overview", { service: new FailingService() });
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "overview unavailable",
  );
  expect(screen.getByRole("button", { name: "Retry" })).toBeVisible();
});

it("describes empty Findings without claiming safety", async () => {
  class EmptyService extends MockScannerService {
    override async getScanResult() {
      return { ...mockScanResult, findings: [] };
    }
  }
  renderRoute("/scans/scan-001/overview", { service: new EmptyService() });
  expect(await screen.findByText("확정된 Finding이 없습니다")).toBeVisible();
  expect(
    screen.getByText("현재 결과는 안전함의 증명이 아닙니다."),
  ).toBeVisible();
});
it("renders accessible distributions and no placeholder links", async () => {
  const { container } = renderRoute("/scans/scan-001/overview");
  expect(
    await screen.findByRole("img", { name: /API methods: GET 24, POST 4/ }),
  ).toBeVisible();
  expect(
    screen.getByRole("img", { name: /Finding types: BOLA 2, DATA 1, AUTH 1/ }),
  ).toBeVisible();
  expect(container.querySelector('a[href="#"]')).toBeNull();
  expect(screen.queryByText(/responseSummary/)).not.toBeInTheDocument();
});
