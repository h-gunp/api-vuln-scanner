import { expect, test } from "@playwright/test";
async function overview(page: import("@playwright/test").Page) {
  await page.goto("/scans/scan-001/overview");
  await expect(
    page.getByRole("heading", { name: "Security overview" }),
  ).toBeVisible();
}
test("complete mock workspace flow", async ({ page }) => {
  await page.goto("/scans/new");
  await page.getByLabel("Target URL").fill("https://staging.example.test");
  for (const label of [
    "User A username",
    "User A password",
    "User B username",
    "User B password",
  ])
    await page.getByLabel(label).fill("temporary-value");
  await page.getByRole("button", { name: /Start mock scan/ }).click();
  await expect(page).toHaveURL(/overview/);
  await page.getByText("Scan progress", { exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Verification pipeline" }),
  ).toBeVisible();
  await overview(page);
  await page.getByText("Scan pipeline", { exact: true }).click();
  await expect(page).toHaveURL(/progress/);
  await overview(page);
  await page.getByText("Discovered APIs", { exact: true }).click();
  await page.getByLabel("Search APIs").fill("accounts");
  await page.getByText("/api/accounts/{account_id}").click();
  await expect(
    page.getByRole("heading", { name: "/api/accounts/{account_id}" }),
  ).toBeVisible();
  await overview(page);
  await page.getByText("API discovery", { exact: true }).click();
  await expect(page).toHaveURL(/apis$/);
  await overview(page);
  await page.getByText("Verified findings", { exact: true }).click();
  await page.getByLabel("Finding type", { exact: true }).selectOption("BOLA");
  await page.getByText("GET:/api/accounts/{account_id}").first().click();
  await expect(page.getByText(/\[REDACTED\]/).first()).toBeVisible();
  await overview(page);
  await page.getByText("Finding breakdown", { exact: true }).click();
  await expect(page).toHaveURL(/findings$/);
  await overview(page);
  await page.getByText("AI Report", { exact: true }).first().click();
  await page.getByRole("link", { name: "Preview" }).click();
  await expect(
    page.getByRole("heading", { name: "Security report preview" }),
  ).toBeVisible();
  await page.goto("/scans/scan-001/ai-report");
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download PDF" }).click();
  expect((await download).suggestedFilename()).toBe(
    "vulnscope-scan-001-report.pdf",
  );
});
test("every dashboard link has and renders a destination", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await overview(page);
  const links = await page
    .locator("main a")
    .evaluateAll((elements) =>
      elements.map((element) => element.getAttribute("href")),
    );
  for (const href of links) {
    expect(href).toBeTruthy();
    expect(href).not.toBe("#");
    await page.goto(href!);
    await expect(page.locator("main h1").first()).toBeVisible();
  }
  expect(errors).toEqual([]);
});
