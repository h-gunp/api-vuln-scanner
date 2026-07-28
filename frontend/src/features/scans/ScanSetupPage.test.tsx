import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it, vi } from "vitest";
import { MockScannerService } from "../../services/mock/mock-scanner-service";
import { renderRoute } from "../../test/render";
it("shows accessible inline validation and does not call the service", async () => {
  const service = new MockScannerService();
  const spy = vi.spyOn(service, "createScan");
  renderRoute("/scans/new", { service });
  await userEvent.click(
    screen.getByRole("button", { name: /스캔 시작/ }),
  );
  expect(screen.getByText(/http:\/\/ 또는 https:\/\//)).toBeVisible();
  expect(spy).not.toHaveBeenCalled();
});
it("submits only the confirmed scan contract and navigates", async () => {
  const service = new MockScannerService();
  const spy = vi.spyOn(service, "createScan");
  const { queryClient, router } = renderRoute("/scans/new", { service });
  await userEvent.type(
    screen.getByLabelText("Target URL"),
    "https://staging.example.test",
  );
  await userEvent.click(
    screen.getByRole("button", { name: /스캔 시작/ }),
  );
  await waitFor(() =>
    expect(router.state.location.pathname).toBe("/scans/scan-001/overview"),
  );
  expect(queryClient.getMutationCache().getAll()).toHaveLength(0);
  expect(spy).toHaveBeenCalledWith({
    targetUrl: "https://staging.example.test",
    scanConfig: null,
  });
});
it("does not render browser credential inputs", async () => {
  const view = renderRoute("/scans/new");
  expect(screen.queryByLabelText("User A username")).not.toBeInTheDocument();
  view.unmount();
});
