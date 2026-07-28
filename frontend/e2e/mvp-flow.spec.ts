import { expect, test } from "@playwright/test";
async function overview(page: import("@playwright/test").Page) {
  await page.goto("/scans/scan-001/overview");
  await expect(
<<<<<<< ours
    page.getByRole("heading", { name: "Security overview" }),
=======
    page.getByRole("heading", { name: "보안 개요" }),
>>>>>>> theirs
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
<<<<<<< ours
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
=======
  await page.getByRole("button", { name: /Mock 스캔 시작/ }).click();
  await expect(page).toHaveURL(/overview/);
  await page.getByText("스캔 진행률", { exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "검증 진행 상태" }),
  ).toBeVisible();
  await overview(page);
  await page.getByText("스캔 진행률", { exact: true }).click();
  await expect(page).toHaveURL(/progress/);
  await overview(page);
  await page.getByText("API 발견 수", { exact: true }).first().click();
  await page.getByLabel("API 검색").fill("accounts");
>>>>>>> theirs
  await page.getByText("/api/accounts/{account_id}").click();
  await expect(
    page.getByRole("heading", { name: "/api/accounts/{account_id}" }),
  ).toBeVisible();
  await overview(page);
<<<<<<< ours
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
=======
  await page.getByText("API 발견 수", { exact: true }).last().click();
  await expect(page).toHaveURL(/apis$/);
  await overview(page);
  await page.getByText("검증된 Finding", { exact: true }).click();
  await page.getByLabel("Finding 유형", { exact: true }).selectOption("BOLA");
  await page.getByText("GET:/api/accounts/{account_id}").first().click();
  await expect(page.getByText(/\[REDACTED\]/).first()).toBeVisible();
  await overview(page);
  await page.getByText("Finding 유형별 현황", { exact: true }).click();
  await expect(page).toHaveURL(/findings$/);
  await overview(page);
  await page.getByText("AI 리포트", { exact: true }).first().click();
  await page.getByRole("link", { name: "미리보기" }).click();
  await expect(
    page.getByRole("heading", { name: "보안 리포트 미리보기" }),
  ).toBeVisible();
  await page.getByRole("link", { name: /AI 리포트로 돌아가기/ }).click();
  await expect(page).toHaveURL(/ai-report$/);
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "PDF 다운로드" }).click();
>>>>>>> theirs
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
