import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it } from "vitest";
import { MockScannerService } from "../../services/mock/mock-scanner-service";
import { renderRoute } from "../../test/render";
it("renders summary metrics and real detail destinations", async () => {
  const { router } = renderRoute("/scans/scan-001/overview");
  expect(screen.getByRole("status", { name: "Loading content" })).toBeVisible();
  expect((await screen.findAllByText("API 발견 수"))[0]).toBeVisible();
  for (const destination of ["progress", "apis", "findings", "ai-report"])
    expect(
      document.querySelector(`.metrics a[href$="${destination}"]`),
    ).toBeInTheDocument();
  await userEvent.click(screen.getByText("스캔 진행률"));
  expect(router.state.location.pathname).toBe("/scans/scan-001/progress");
});

it("renders query error and retry states", async () => {
  class FailingService extends MockScannerService {
    override async getScanSummary(): Promise<never> {
      throw new Error("summary unavailable");
    }
  }
  renderRoute("/scans/scan-001/overview", { service: new FailingService() });
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "summary unavailable",
  );
  expect(screen.getByRole("button", { name: "다시 시도" })).toBeVisible();
});

it("keeps the overview available while the AI report is being generated", async () => {
  class ReportPendingService extends MockScannerService {
    override async getScanSummary() {
      return {
        ...(await super.getScanSummary("scan-001")),
        reportStatus: "PENDING",
      };
    }

    override async getAiReport(): Promise<never> {
      throw new Error("report must not be requested while pending");
    }
  }

  renderRoute("/scans/scan-001/overview", { service: new ReportPendingService() });
  expect(await screen.findByText("리포트 생성 중")).toBeVisible();
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
});

it("describes empty Findings without claiming safety", async () => {
  class EmptyService extends MockScannerService {
    override async getFindings() {
      return { items: [], page: 0, size: 20, totalElements: 0, totalPages: 0 };
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
    await screen.findByRole("img", { name: /API 메서드: GET 2, PATCH 1/ }),
  ).toBeVisible();
  expect(
    screen.getByRole("img", { name: /Finding 유형: BOLA-001 1/ }),
  ).toBeVisible();
  expect(container.querySelector('a[href="#"]')).toBeNull();
  expect(screen.queryByText(/responseSummary/)).not.toBeInTheDocument();
});
