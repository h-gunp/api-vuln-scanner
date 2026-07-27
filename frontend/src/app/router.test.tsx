import { screen, waitFor } from "@testing-library/react";
import { expect, it } from "vitest";
import { renderRoute } from "../test/render";
it("redirects an unknown route to scan setup", async () => {
  const { router } = renderRoute("/unknown");
  await waitFor(() =>
    expect(router.state.location.pathname).toBe("/scans/new"),
  );
  expect(screen.getByRole("heading", { name: "새 스캔 시작" })).toBeVisible();
});
it("renders every deliberate route", async () => {
  for (const path of [
    "/scans/scan-001/overview",
    "/scans/scan-001/progress",
    "/scans/scan-001/apis",
    "/scans/scan-001/apis/GET%3A%2Fapi%2Faccounts",
    "/scans/scan-001/findings",
    "/scans/scan-001/findings/finding-001",
    "/scans/scan-001/ai-report",
    "/scans/scan-001/ai-report/preview",
  ]) {
    const view = renderRoute(path);
    await screen.findByRole("heading", { level: 1 });
    view.unmount();
  }
});
