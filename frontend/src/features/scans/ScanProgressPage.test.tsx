import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it } from "vitest";
import { MockScannerService } from "../../services/mock/mock-scanner-service";
import { renderRoute } from "../../test/render";

it("renders the backend status and progress", async () => {
  const { router } = renderRoute("/scans/scan-001/progress");
  expect(await screen.findByText("72%")).toBeVisible();
  expect(screen.getAllByText("MODULE_EXECUTION").length).toBeGreaterThan(0);
  expect(screen.getByText("RUNNING")).toBeVisible();
  await userEvent.click(screen.getByRole("link", { name: /개요로 돌아가기/ }));
  expect(router.state.location.pathname).toBe("/scans/scan-001/overview");
});

it("renders a structured backend error without rendering an object", async () => {
  class FailedScanService extends MockScannerService {
    override async getScanStatus() {
      return {
        scanId: "scan-001",
        status: "FAILED" as const,
        stage: "MODULE_EXECUTION" as const,
        progress: 72,
        error: {
          code: "SCAN_FAILED",
          message: "Scanner callback failed",
          details: null,
          fieldErrors: [],
        },
      };
    }
  }

  renderRoute("/scans/scan-001/progress", { service: new FailedScanService() });
  expect(await screen.findByText(/SCAN_FAILED/)).toBeVisible();
  expect(screen.getByText(/Scanner callback failed/)).toBeVisible();
});
