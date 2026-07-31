import { expect, test } from "@playwright/test";
async function overview(page: import("@playwright/test").Page) {
  await page.goto("/scans/scan-001/overview");
  await expect(
    page.getByRole("heading", { name: "보안 개요" }),
  ).toBeVisible();
}
test("complete backend-contract workspace flow", async ({ page }) => {
  await page.route("**/api/**", async (route) => {
    const url = new URL(route.request().url());
    const json = (body: unknown) => route.fulfill({ contentType: "application/json", body: JSON.stringify(body) });
    if (url.pathname === "/api/scans" && route.request().method() === "POST") {
      await json({ scan_id: "scan-001", status: "PENDING", stage: "TARGET_VALIDATION" });
    } else if (url.pathname === "/api/scans/scan-001/summary") {
      await json({ scan_id: "scan-001", target_url: "https://staging.example.test", status: "RUNNING", stage: "MODULE_EXECUTION", progress: 72, api_count: 2, finding_count: 1, planned_module_count: 4, completed_module_count: 3, overall_risk: "HIGH", report_status: "READY" });
    } else if (url.pathname === "/api/scans/scan-001") {
      await json({ scan_id: "scan-001", status: "RUNNING", stage: "MODULE_EXECUTION", progress: 72, error: null });
    } else if (url.pathname === "/api/scans/scan-001/endpoints") {
      await json({ items: [{ operation_id: "getUser", method: "GET", path: "/users/{id}" }, { operation_id: "updateUser", method: "PATCH", path: "/users/{id}" }] });
    } else if (url.pathname === "/api/scans/scan-001/findings") {
      await json({ items: [{ finding_id: "finding-001", module_id: "BOLA-001", severity: "HIGH", target_endpoint: { operation_id: "getUser", method: "GET", path: "/users/{id}" }, title: "객체 소유권 검증 필요", summary: "대상 객체에 대한 권한 검증 결과를 확인해야 합니다." }], page: 0, size: 20, total_elements: 1, total_pages: 1 });
    } else if (url.pathname === "/api/scans/scan-001/ai-report") {
      await json({ report_id: "report-001", scan_id: "scan-001", summary: "확인된 Finding을 우선순위에 따라 검토하세요.", overall_risk: "HIGH", findings: [{ finding_id: "finding-001", root_cause: "객체 소유권 검증 확인 필요", attack_flow: ["대상 식별", "권한 검증"], impact: "다른 사용자의 객체에 접근할 가능성이 있습니다.", recommendation: "서버에서 객체 소유권을 검증하세요." }] });
    } else if (url.pathname === "/api/reports/report-001/download") {
      await route.fulfill({ body: "%PDF-1.4\n%%EOF", headers: { "content-type": "application/pdf", "content-disposition": "attachment; filename=security-report.pdf" } });
    } else {
      await route.fulfill({ status: 404, contentType: "application/json", body: JSON.stringify({ error: { code: "SCAN_NOT_FOUND", message: "Not found", details: null } }) });
    }
  });
  await page.goto("/scans/new");
  await page.getByLabel("Target URL").fill("https://staging.example.test");
  await page.getByRole("button", { name: "스캔 시작" }).click();
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
  await page.getByLabel("API 검색").fill("getUser");
  await page.getByText("getUser").click();
  await expect(
    page.getByRole("heading", { name: "/users/{id}" }),
  ).toBeVisible();
  await overview(page);
  await page.getByText("API 발견 수", { exact: true }).last().click();
  await expect(page).toHaveURL(/apis$/);
  await overview(page);
  await page.getByText("검증된 Finding", { exact: true }).click();
  await page.getByLabel("Finding 유형", { exact: true }).selectOption("BOLA-001");
  await page.getByText("객체 소유권 검증 필요").click();
  await expect(page.getByText(/Evidence 형식과 조회 API는 아직/)).toBeVisible();
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
  const reportDownload = await download;
  expect(reportDownload.suggestedFilename()).toBe("vulnscope-scan-001-report.pdf");
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
