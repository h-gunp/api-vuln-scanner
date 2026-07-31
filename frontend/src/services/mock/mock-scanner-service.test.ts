import { describe, expect, it } from "vitest";
import { MockNotFoundError } from "../scanner-service";
import { MockScannerService } from "./mock-scanner-service";

describe("MockScannerService", () => {
  it("returns scan-001 using the real scan-create input shape", async () => {
    const service = new MockScannerService();
    await expect(
      service.createScan({ targetUrl: "https://staging.example.test", scanConfig: null }),
    ).resolves.toMatchObject({ scanId: "scan-001", status: "PENDING" });
  });
  it("returns contract-shaped endpoint, finding, status and report fixtures", async () => {
    const service = new MockScannerService();
    await expect(service.getEndpoints("scan-001")).resolves.toHaveProperty(
      "items.0.operationId",
      "listUsers",
    );
    await expect(service.getFindings("scan-001")).resolves.toMatchObject({
      items: [{ findingId: "finding-001", moduleId: "BOLA-001" }],
    });
    await expect(service.getScanStatus("scan-001")).resolves.toMatchObject({ stage: "MODULE_EXECUTION" });
    await expect(service.getAiReport("scan-001")).resolves.toMatchObject({ reportId: "report-001" });
  });
  it("rejects an unknown scan id with MockNotFoundError", async () => {
    await expect(new MockScannerService().getScanSummary("missing")).rejects.toBeInstanceOf(MockNotFoundError);
  });
});
