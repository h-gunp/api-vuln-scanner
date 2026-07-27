import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it } from "vitest";
import { renderRoute } from "../../test/render";
it("combines type and text filtering with safety disclaimer", async () => {
  renderRoute("/scans/scan-001/findings");
  await screen.findByRole("img", { name: /Finding types/ });
  await userEvent.selectOptions(screen.getByLabelText("Finding type"), "AUTH");
  expect(screen.getByText("GET:/api/profile")).toBeVisible();
  await userEvent.type(screen.getByLabelText("Search findings"), "missing");
  expect(
    screen.getByText("검색 결과가 없다는 사실은 안전함의 증명이 아닙니다."),
  ).toBeVisible();
});
it("shows verification, affected fields, and redacted evidence", async () => {
  renderRoute("/scans/scan-001/findings/finding-001");
  expect(await screen.findByText("BOLA-OBJECT-OWNER-MISMATCH")).toBeVisible();
  expect(screen.getByText("FOREIGN_OBJECT_RETURNED")).toBeVisible();
  expect(screen.getAllByText("account_id").length).toBeGreaterThan(0);
  expect(
    await screen.findByText(/GET \/api\/accounts\/\[REDACTED\]/),
  ).toBeVisible();
  expect(document.body.textContent).not.toMatch(/Bearer\s+[A-Za-z0-9._-]+/);
});
it("renders an explicit unknown Finding state", async () => {
  renderRoute("/scans/scan-001/findings/missing");
  expect(
    await screen.findByText("확정된 scan result에 없는 Finding입니다."),
  ).toBeVisible();
});
