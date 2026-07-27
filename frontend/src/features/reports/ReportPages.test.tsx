import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it, vi } from "vitest";
import { renderRoute } from "../../test/render";
it("renders every report Finding once with ordered attack flow", async () => {
  renderRoute("/scans/scan-001/ai-report");
  expect(await screen.findByText(/검증된 API 취약점 4건/)).toBeVisible();
  for (const id of ["finding-001", "finding-002", "finding-003", "finding-004"])
    expect(screen.getAllByRole("link", { name: `${id} →` })).toHaveLength(1);
  const items = screen
    .getAllByRole("listitem")
    .slice(0, 3)
    .map((item) => item.textContent);
  expect(items).toEqual([
    "인증된 사용자 요청",
    "다른 객체 참조",
    "허용되지 않은 응답 확인",
  ]);
});
it("navigates to print preview", async () => {
  const { router } = renderRoute("/scans/scan-001/ai-report");
  await screen.findByText(/검증된 API 취약점 4건/);
  await userEvent.click(screen.getByRole("link", { name: "Preview" }));
  expect(router.state.location.pathname).toMatch(/preview$/);
  expect(await screen.findByText("VulnScope Security Report")).toBeVisible();
});
it("downloads a valid named PDF without sensitive text", async () => {
  const create = vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:mock");
  const revoke = vi
    .spyOn(URL, "revokeObjectURL")
    .mockImplementation(() => undefined);
  const click = vi
    .spyOn(HTMLAnchorElement.prototype, "click")
    .mockImplementation(() => undefined);
  renderRoute("/scans/scan-001/ai-report");
  await screen.findByText(/검증된 API 취약점 4건/);
  await userEvent.click(screen.getByRole("button", { name: "Download PDF" }));
  await vi.waitFor(() => expect(click).toHaveBeenCalled());
  expect(create).toHaveBeenCalled();
  expect(revoke).toHaveBeenCalledWith("blob:mock");
  create.mockRestore();
  revoke.mockRestore();
  click.mockRestore();
});
