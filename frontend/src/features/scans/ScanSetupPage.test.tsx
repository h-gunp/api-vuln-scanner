import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it, vi } from "vitest";
import { MockScannerService } from "../../services/mock/mock-scanner-service";
import { renderRoute } from "../../test/render";
const labels = [
  "User A username",
  "User A password",
  "User B username",
  "User B password",
];
it("shows accessible inline validation and does not call the service", async () => {
  const service = new MockScannerService();
  const spy = vi.spyOn(service, "createScan");
  renderRoute("/scans/new", { service });
  await userEvent.click(
    screen.getByRole("button", { name: /Start mock scan/ }),
  );
  expect(screen.getByText(/http:\/\/ 또는 https:\/\//)).toBeVisible();
  expect(screen.getAllByText("필수 입력입니다.")).toHaveLength(4);
  expect(spy).not.toHaveBeenCalled();
});
it("uses safe password fields, clears credentials, leaves mutation cache empty, and navigates", async () => {
  const service = new MockScannerService();
  const { queryClient, router } = renderRoute("/scans/new", { service });
  await userEvent.type(
    screen.getByLabelText("Target URL"),
    "https://staging.example.test",
  );
  for (const label of labels)
    await userEvent.type(screen.getByLabelText(label), `temporary-${label}`);
  expect(screen.getByLabelText("User A password")).toHaveAttribute(
    "type",
    "password",
  );
  expect(screen.getByLabelText("User A password")).toHaveAttribute(
    "autocomplete",
    "new-password",
  );
  await userEvent.click(
    screen.getByRole("button", { name: /Start mock scan/ }),
  );
  await waitFor(() =>
    expect(router.state.location.pathname).toBe("/scans/scan-001/overview"),
  );
  expect(queryClient.getMutationCache().getAll()).toHaveLength(0);
  expect(JSON.stringify(service.getDebugSnapshot())).not.toContain("temporary");
});
it("discards controlled credentials on unmount", async () => {
  const view = renderRoute("/scans/new");
  await userEvent.type(screen.getByLabelText("User A username"), "ephemeral");
  view.unmount();
  expect(document.body).not.toHaveTextContent("ephemeral");
});
