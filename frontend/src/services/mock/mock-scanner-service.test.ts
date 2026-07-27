import { describe, expect, it } from "vitest";
import { MockNotFoundError } from "../scanner-service";
import { MockScannerService } from "./mock-scanner-service";
const input = {
  targetUrl: "https://staging.example.test",
  userA: { username: "temporary-a", password: "temporary-secret-a" },
  userB: { username: "temporary-b", password: "temporary-secret-b" },
};
describe("MockScannerService", () => {
  it("returns scan-001 without retaining submitted credentials", async () => {
    const service = new MockScannerService();
    await expect(service.createScan(input)).resolves.toEqual({
      scanId: "scan-001",
    });
    expect(JSON.stringify(service.getDebugSnapshot())).not.toMatch(/temporary/);
  });
  it("returns finalized-contract fixtures by scan id", async () => {
    const service = new MockScannerService();
    await expect(service.getApiGraph("scan-001")).resolves.toMatchObject({
      schema_version: "1.1",
    });
    await expect(service.getScanResult("scan-001")).resolves.toMatchObject({
      schema_version: "1.2",
    });
  });
  it("returns a complete five-stage mock scan progress view", async () => {
    const service = new MockScannerService();
    expect((await service.getScanProgress("scan-001")).stages).toHaveLength(5);
  });
  it("rejects an unknown scan id with MockNotFoundError", async () => {
    await expect(
      new MockScannerService().getOverview("missing"),
    ).rejects.toBeInstanceOf(MockNotFoundError);
  });
  it("returns only redacted evidence content", async () => {
    const evidence = await new MockScannerService().getEvidence(
      "evidence:redacted:001",
    );
    expect(JSON.stringify(evidence)).toContain("[REDACTED]");
  });
});
