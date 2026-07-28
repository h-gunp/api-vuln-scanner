import type {
  AiReportResponse,
  EndpointList,
  FindingPage,
  ScanStatusSnapshot,
  ScanSummary,
} from "../../contracts";
import {
  MockNotFoundError,
  type CreateScanInput,
  type MockServiceDebugSnapshot,
  type ReportDownload,
  type ScannerService,
} from "../scanner-service";

const delay = () => new Promise((resolve) => setTimeout(resolve, 80));
const assertScan = (scanId: string) => {
  if (scanId !== "scan-001") {
    throw new MockNotFoundError(`Unknown mock scan: ${scanId}`);
  }
};

const endpoints: EndpointList = {
  items: [
    { operationId: "listUsers", method: "GET", path: "/users" },
    { operationId: "getUser", method: "GET", path: "/users/{id}" },
    { operationId: "updateUser", method: "PATCH", path: "/users/{id}" },
  ],
};
const findings: FindingPage = {
  items: [
    {
      findingId: "finding-001",
      moduleId: "BOLA-001",
      severity: "HIGH",
      targetEndpoint: endpoints.items[1],
      title: "객체 소유권 검증 필요",
      summary: "대상 객체에 대한 권한 검증 결과를 확인해야 합니다.",
    },
  ],
  page: 0,
  size: 20,
  totalElements: 1,
  totalPages: 1,
};

export class MockScannerService implements ScannerService {
  private readonly createdScanIds = new Set<string>();

  async createScan(input: CreateScanInput) {
    const protocol = new URL(input.targetUrl).protocol;
    if (protocol !== "http:" && protocol !== "https:") {
      throw new TypeError("Target URL must use HTTP or HTTPS");
    }
    await delay();
    this.createdScanIds.add("scan-001");
    return {
      scanId: "scan-001",
      status: "PENDING",
      stage: "TARGET_VALIDATION",
    };
  }

  async getScanSummary(scanId: string): Promise<ScanSummary> {
    assertScan(scanId);
    await delay();
    return {
      scanId,
      targetUrl: "https://staging.example.test",
      status: "RUNNING",
      stage: "MODULE_EXECUTION",
      progress: 72,
      apiCount: endpoints.items.length,
      findingCount: findings.totalElements,
      plannedModuleCount: 4,
      completedModuleCount: 3,
      overallRisk: "HIGH",
      reportStatus: "READY",
    };
  }

  async getScanStatus(scanId: string): Promise<ScanStatusSnapshot> {
    const summary = await this.getScanSummary(scanId);
    return {
      scanId: summary.scanId,
      status: summary.status,
      stage: summary.stage,
      progress: summary.progress,
      error: null,
    };
  }

  async getEndpoints(scanId: string): Promise<EndpointList> {
    assertScan(scanId);
    await delay();
    return endpoints;
  }

  async getFindings(scanId: string): Promise<FindingPage> {
    assertScan(scanId);
    await delay();
    return findings;
  }

  async getAiReport(scanId: string): Promise<AiReportResponse> {
    assertScan(scanId);
    await delay();
    return {
      reportId: "report-001",
      scanId,
      summary: "확인된 Finding을 우선순위에 따라 검토하세요.",
      overallRisk: "HIGH",
      findings: [
        {
          findingId: "finding-001",
          rootCause: "객체 소유권 검증 확인 필요",
          attackFlow: ["대상 식별", "권한 검증"],
          impact: "다른 사용자의 객체에 접근할 가능성이 있습니다.",
          recommendation: "서버에서 객체 소유권을 검증하세요.",
        },
      ],
    };
  }

  async downloadReport(reportId: string): Promise<ReportDownload> {
    if (reportId !== "report-001") {
      throw new MockNotFoundError(`Unknown mock report: ${reportId}`);
    }
    await delay();
    return {
      blob: new Blob(["%PDF-1.4\\nmock report\\n%%EOF"], {
        type: "application/pdf",
      }),
      filename: "vulnscope-report.pdf",
    };
  }

  getDebugSnapshot(): MockServiceDebugSnapshot {
    return { createdScanIds: [...this.createdScanIds] };
  }
}
