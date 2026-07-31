import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it, vi } from "vitest";
import { AsyncState } from "./AsyncState";
it("renders loading, error retry, and success deliberately", async () => {
  const retry = vi.fn();
  const view = render(
    <AsyncState isLoading error={null}>
      ready
    </AsyncState>,
  );
  expect(screen.getByRole("status", { name: "Loading content" })).toBeVisible();
  view.rerender(
    <AsyncState isLoading={false} error={new Error("failed")} onRetry={retry}>
      ready
    </AsyncState>,
  );
  await userEvent.click(screen.getByRole("button", { name: "다시 시도" }));
  expect(retry).toHaveBeenCalledOnce();
  view.rerender(
    <AsyncState isLoading={false} error={null}>
      ready
    </AsyncState>,
  );
  expect(screen.getByText("ready")).toBeVisible();
});
