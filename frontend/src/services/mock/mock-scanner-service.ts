import {
  MockNotFoundError,
  type CreateScanInput,
  type MockServiceDebugSnapshot,
  type ScannerService,
  type ScanProgressDetail,
} from "../scanner-service";
import { mockAiReport, mockApiGraph, mockScanResult } from "./mock-data";
import { mockEvidenceByRef } from "./mock-evidence";

const delay = () => new Promise((resolve) => setTimeout(resolve, 80));
const assertScan = (scanId: string) => {
  if (scanId !== "scan-001")
    throw new MockNotFoundError(`Unknown mock scan: ${scanId}`);
};

export class MockScannerService implements ScannerService {
  private readonly createdScanIds = new Set<string>();

  async createScan(input: CreateScanInput) {
    const protocol = new URL(input.targetUrl).protocol;
    if (protocol !== "http:" && protocol !== "https:")
      throw new TypeError("Target URL must use HTTP or HTTPS");
    await delay();
    this.createdScanIds.add("scan-001");
    return { scanId: "scan-001" };
  }
  async getOverview(scanId: string) {
    assertScan(scanId);
    await delay();
    return {
      scanId,
      targetUrl: "https://staging.example.test",
      progress: 72,
      stage: "Module verification",
      reportStatus: "ready" as const,
    };
  }
  async getScanProgress(scanId: string): Promise<ScanProgressDetail> {
    assertScan(scanId);
    await delay();
    return {
      scanId,
      progress: 72,
      currentStageId: "module-verification",
      stages: [
        {
          id: "authentication",
          label: "Authentication",
          description: "Validate isolated actors",
          status: "completed",
        },
        {
          id: "api-discovery",
          label: "API discovery",
          description: "Normalize API operations",
          status: "completed",
        },
        {
          id: "relationship-analysis",
          label: "Relationship analysis",
          description: "Map object data flows",
          status: "completed",
        },
        {
          id: "module-verification",
          label: "Module verification",
          description: "Validate evidence using approved modules",
          status: "running",
        },
        {
          id: "ai-report",
          label: "AI Report",
          description: "Summarize verified Findings",
          status: "waiting",
        },
      ],
    };
  }
  async getApiGraph(scanId: string) {
    assertScan(scanId);
    await delay();
    return mockApiGraph;
  }
  async getScanResult(scanId: string) {
    assertScan(scanId);
    await delay();
    return mockScanResult;
  }
  async getAiReport(scanId: string) {
    assertScan(scanId);
    await delay();
    return mockAiReport;
  }
  async getEvidence(ref: string) {
    await delay();
    const result = mockEvidenceByRef[ref];
    if (!result)
      throw new MockNotFoundError(`Unknown redacted evidence: ${ref}`);
    return result;
  }
  getDebugSnapshot(): MockServiceDebugSnapshot {
    return { createdScanIds: [...this.createdScanIds] };
  }
}
export const defaultScannerService = new MockScannerService();
