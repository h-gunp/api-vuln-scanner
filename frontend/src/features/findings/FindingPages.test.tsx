import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it } from "vitest";
import { renderRoute } from "../../test/render";

it("combines module and text filtering with safety disclaimer", async () => {
  renderRoute("/scans/scan-001/findings");
  await screen.findByRole("img", { name: /Finding 유형/ });
  await userEvent.selectOptions(screen.getByLabelText("Finding 유형"), "BOLA-001");
  expect(screen.getByText("/users/{id}")).toBeVisible();
  await userEvent.type(screen.getByLabelText("Finding 검색"), "missing");
  expect(screen.getByText("검색 결과가 없다는 사실은 안전함의 증명이 아닙니다.")).toBeVisible();
});
it("shows only confirmed Finding fields and marks evidence unavailable", async () => {
  renderRoute("/scans/scan-001/findings/finding-001");
  expect(await screen.findByText("BOLA-001")).toBeVisible();
  expect(screen.getByText("HIGH")).toBeVisible();
  expect(screen.getByText("Evidence")).toBeVisible();
  expect(screen.getByText(/Evidence 형식과 조회 API는 아직/)).toBeVisible();
});
it("renders an explicit unknown Finding state", async () => {
  renderRoute("/scans/scan-001/findings/missing");
  expect(await screen.findByText("현재 scan의 Finding 목록에 없는 항목입니다.")).toBeVisible();
});
