import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it } from "vitest";
import { MockScannerService } from "../../services/mock/mock-scanner-service";
import { renderRoute } from "../../test/render";

it("combines module and text filtering with safety disclaimer", async () => {
  renderRoute("/scans/scan-001/findings");
  await screen.findByRole("img", { name: /Finding 유형/ });
  await userEvent.selectOptions(screen.getByLabelText("Finding 유형"), "BOLA-001");
  expect(screen.getByText("/users/{id}")).toBeVisible();
  await userEvent.type(screen.getByLabelText("Finding 검색"), "missing");
  expect(screen.getByText("검색 결과가 없다는 사실은 안전함의 증명이 아닙니다.")).toBeVisible();
});
it("shows confirmed Finding fields and the evidence availability state", async () => {
  renderRoute("/scans/scan-001/findings/finding-001");
  expect(await screen.findByText("BOLA-001")).toBeVisible();
  expect(screen.getByText("HIGH")).toBeVisible();
  expect(screen.getByText("Evidence")).toBeVisible();
  expect(screen.getByText("Evidence는 아직 제공되지 않았습니다.")).toBeVisible();
});
it("renders the backend error for an unknown Finding", async () => {
  renderRoute("/scans/scan-001/findings/missing");
  expect(await screen.findByRole("alert")).toHaveTextContent("Unknown mock Finding: missing");
});

it("loads a Finding detail through the dedicated detail service", async () => {
  class DetailOnlyService extends MockScannerService {
    override async getFindings() {
      return { items: [], page: 1, size: 20, totalElements: 21, totalPages: 2 };
    }
  }

  renderRoute("/scans/scan-001/findings/finding-001", {
    service: new DetailOnlyService(),
  });
  expect(await screen.findByText("객체 소유권 검증 필요")).toBeVisible();
});
