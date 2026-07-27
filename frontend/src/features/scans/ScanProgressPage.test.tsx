import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it } from "vitest";
import { renderRoute } from "../../test/render";
it("renders overall progress and all five textual stages", async () => {
  const { router } = renderRoute("/scans/scan-001/progress");
  expect(await screen.findByText("72%")).toBeVisible();
  const detail = document.querySelector<HTMLElement>(".detail-card")!;
  for (const label of [
    "Authentication",
    "API discovery",
    "Relationship analysis",
    "Module verification",
    "AI Report",
  ])
    expect(within(detail).getByText(label)).toBeVisible();
  for (const status of ["completed", "running", "waiting"])
    expect(screen.getAllByText(status).length).toBeGreaterThan(0);
  await userEvent.click(screen.getByRole("link", { name: /Back to overview/ }));
  expect(router.state.location.pathname).toBe("/scans/scan-001/overview");
});
