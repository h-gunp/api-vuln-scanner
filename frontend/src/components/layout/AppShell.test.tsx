import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it } from "vitest";
import { renderRoute } from "../../test/render";
it("shows approved sidebar destinations and mobile menu", async () => {
  renderRoute("/scans/scan-001/overview");
<<<<<<< ours
  for (const name of ["Overview", "APIs", "Findings", "AI Report"])
=======
  for (const name of ["개요", "APIs", "Finding", "AI 리포트"])
>>>>>>> theirs
    expect(screen.getByRole("link", { name })).toHaveAttribute(
      "href",
      expect.stringContaining("/scans/scan-001/"),
    );
  await userEvent.click(screen.getByRole("button", { name: "메뉴" }));
  expect(
<<<<<<< ours
    screen.getByRole("navigation", { name: "Main navigation" }),
=======
    screen.getByRole("navigation", { name: "주요 메뉴" }),
>>>>>>> theirs
  ).toBeInTheDocument();
});
