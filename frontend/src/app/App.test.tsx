import { screen } from "@testing-library/react";
import { expect, it } from "vitest";
import { renderRoute } from "../test/render";
it("renders the product name", () => {
  renderRoute("/scans/new");
  expect(screen.getByText("VulnScope")).toBeInTheDocument();
});
