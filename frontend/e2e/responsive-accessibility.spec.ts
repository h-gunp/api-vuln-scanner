import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
const pages = ["overview", "apis", "findings", "ai-report"];
for (const viewport of [
  { name: "desktop", width: 1440, height: 900 },
  { name: "mobile", width: 390, height: 844 },
]) {
  for (const route of pages)
    test(`${route} is responsive and accessible on ${viewport.name}`, async ({
      page,
    }) => {
      await page.setViewportSize(viewport);
      await page.goto(`/scans/scan-001/${route}`);
      await expect(page.locator("main h1")).toBeVisible();
      expect(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= window.innerWidth,
        ),
      ).toBe(true);
      const results = await new AxeBuilder({ page }).analyze();
      expect(
        results.violations.filter(
          (item) => item.impact === "critical" || item.impact === "serious",
        ),
      ).toEqual([]);
      if (viewport.name === "mobile") {
        await expect(page.getByRole("button", { name: "메뉴" })).toBeVisible();
        await page.getByRole("button", { name: "메뉴" }).click();
        await expect(
          page.getByRole("link", { name: "개요" }),
        ).toBeVisible();
      }
    });
}
