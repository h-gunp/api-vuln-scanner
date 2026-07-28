import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it } from "vitest";
import { renderRoute } from "../../test/render";

it("renders the backend status and progress", async () => {
  const { router } = renderRoute("/scans/scan-001/progress");
  expect(await screen.findByText("72%")).toBeVisible();
  expect(screen.getAllByText("MODULE_EXECUTION").length).toBeGreaterThan(0);
  expect(screen.getByText("RUNNING")).toBeVisible();
  await userEvent.click(screen.getByRole("link", { name: /개요로 돌아가기/ }));
  expect(router.state.location.pathname).toBe("/scans/scan-001/overview");
});
