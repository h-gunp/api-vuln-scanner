import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it } from "vitest";
import { renderRoute } from "../../test/render";
it("searches APIs and navigates to encoded operation detail", async () => {
  const { router } = renderRoute("/scans/scan-001/apis");
  await screen.findByText("/api/accounts/{account_id}");
<<<<<<< ours
  await userEvent.type(screen.getByLabelText("Search APIs"), "balance");
=======
  await userEvent.type(screen.getByLabelText("API 검색"), "balance");
>>>>>>> theirs
  expect(screen.getByText("/api/accounts/{account_id}")).toBeVisible();
  expect(screen.queryByText("/api/profile")).not.toBeInTheDocument();
  await userEvent.click(screen.getByText("/api/accounts/{account_id}"));
  expect(router.state.location.pathname).toContain(
    "GET%3A%2Fapi%2Faccounts%2F%7Baccount_id%7D",
  );
});
it("shows contract-limited inputs and outputs", async () => {
  renderRoute(
    "/scans/scan-001/apis/GET%3A%2Fapi%2Faccounts%2F%7Baccount_id%7D",
  );
  expect(
    await screen.findByRole("heading", { name: "/api/accounts/{account_id}" }),
  ).toBeVisible();
<<<<<<< ours
  expect(screen.getByText("Inputs")).toBeVisible();
  expect(screen.getByText("Outputs")).toBeVisible();
=======
  expect(screen.getByText("입력")).toBeVisible();
  expect(screen.getByText("출력")).toBeVisible();
>>>>>>> theirs
  expect(screen.getAllByText("account_id").length).toBeGreaterThan(0);
  expect(screen.queryByText(/token/i)).not.toBeInTheDocument();
});
it("renders an explicit unknown operation state", async () => {
  renderRoute("/scans/scan-001/apis/UNKNOWN");
  expect(
    await screen.findByText("정규화된 API graph에 없는 operation입니다."),
  ).toBeVisible();
});
