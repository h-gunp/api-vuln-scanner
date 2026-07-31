import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it } from "vitest";
import { renderRoute } from "../../test/render";

it("searches endpoints and navigates to encoded operation detail", async () => {
  const { router } = renderRoute("/scans/scan-001/apis");
  await screen.findAllByText("/users/{id}");
  await userEvent.type(screen.getByLabelText("API 검색"), "update");
  expect(screen.getAllByText("/users/{id}")).toHaveLength(1);
  expect(screen.queryByText("/users")).not.toBeInTheDocument();
  await userEvent.click(screen.getByText("updateUser"));
  expect(router.state.location.pathname).toContain("updateUser");
});
it("shows only confirmed endpoint fields", async () => {
  renderRoute("/scans/scan-001/apis/getUser");
  expect(await screen.findByRole("heading", { name: "/users/{id}" })).toBeVisible();
  expect(screen.getByText("Operation ID")).toBeVisible();
  expect(screen.getByText("입출력 계약")).toBeVisible();
  expect(screen.getByText(/현재 백엔드 계약에 포함되지 않았습니다/)).toBeVisible();
});
it("renders an explicit unknown operation state", async () => {
  renderRoute("/scans/scan-001/apis/UNKNOWN");
  expect(await screen.findByText("백엔드가 반환한 endpoint에 없는 operation입니다.")).toBeVisible();
});
