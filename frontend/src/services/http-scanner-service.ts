import type {
  AiReportResponse,
  EndpointList,
  FindingPage,
  ScanStatusSnapshot,
  ScanSummary,
} from "../contracts";
import type { CreateScanInput, ReportDownload, ScannerService } from "./scanner-service";

export interface ApiFieldError {
  field: string;
  reason: string;
}

export class ApiError extends Error {
  readonly name = "ApiError";
  readonly status: number;
  readonly code: string;
  readonly details: unknown;
  readonly fieldErrors: ApiFieldError[];

  constructor(
    status: number,
    code: string,
    message: string,
    details: unknown,
    fieldErrors: ApiFieldError[] = [],
  ) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
    this.fieldErrors = fieldErrors;
  }
}

type ApiErrorBody = {
  error?: {
    code?: string;
    message?: string;
    details?: unknown;
    field_errors?: ApiFieldError[];
  };
};

const defaultBaseUrl = "http://localhost:8080";

function getBaseUrl() {
  return (import.meta.env.VITE_API_BASE_URL ?? defaultBaseUrl).replace(/\/$/, "");
}

async function toApiError(response: Response) {
  const body = (await response.json().catch(() => null)) as ApiErrorBody | null;
  const error = body?.error;
  return new ApiError(
    response.status,
    error?.code ?? "INTERNAL_SERVER_ERROR",
    error?.message ?? `요청 처리에 실패했습니다. (${response.status})`,
    error?.details ?? null,
    error?.field_errors ?? [],
  );
}

function getFilename(header: string | null) {
  const match = /filename="?([^";]+)"?/i.exec(header ?? "");
  return match?.[1] ?? null;
}

export class HttpScannerService implements ScannerService {
  private readonly baseUrl: string;

  constructor(baseUrl = getBaseUrl()) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
  }

  private async request(path: string, init?: RequestInit) {
    const response = await fetch(`${this.baseUrl}${path}`, init);
    if (!response.ok) throw await toApiError(response);
    return response;
  }

  async createScan(input: CreateScanInput) {
    const response = await this.request("/api/scans", {
      body: JSON.stringify({
        target_url: input.targetUrl,
        scan_config: input.scanConfig,
      }),
      headers: { "Content-Type": "application/json" },
      method: "POST",
    });
    const result = (await response.json()) as {
      scan_id: string;
      status: ScanStatusSnapshot["status"];
      stage: ScanStatusSnapshot["stage"];
    };
    return {
      scanId: result.scan_id,
      stage: result.stage,
      status: result.status,
    };
  }

  async getScanSummary(scanId: string) {
    const response = await this.request(`/api/scans/${encodeURIComponent(scanId)}/summary`);
    const result = (await response.json()) as {
      scan_id: string;
      target_url: string;
      status: ScanSummary["status"];
      stage: ScanSummary["stage"];
      progress: number;
      api_count: number;
      finding_count: number;
      planned_module_count: number;
      completed_module_count: number;
      overall_risk: string | null;
      report_status: string;
    };
    return {
      apiCount: result.api_count,
      completedModuleCount: result.completed_module_count,
      findingCount: result.finding_count,
      overallRisk: result.overall_risk,
      plannedModuleCount: result.planned_module_count,
      progress: result.progress,
      reportStatus: result.report_status,
      scanId: result.scan_id,
      stage: result.stage,
      status: result.status,
      targetUrl: result.target_url,
    } satisfies ScanSummary;
  }

  async getScanStatus(scanId: string) {
    const response = await this.request(`/api/scans/${encodeURIComponent(scanId)}`);
    const result = (await response.json()) as {
      scan_id: string;
      status: ScanStatusSnapshot["status"];
      stage: ScanStatusSnapshot["stage"];
      progress: number;
      error: string | null;
    };
    return {
      error: result.error,
      progress: result.progress,
      scanId: result.scan_id,
      stage: result.stage,
      status: result.status,
    } satisfies ScanStatusSnapshot;
  }

  async getEndpoints(scanId: string) {
    const response = await this.request(
      `/api/scans/${encodeURIComponent(scanId)}/endpoints`,
    );
    const result = (await response.json()) as {
      items: Array<{ operation_id: string; method: string; path: string }>;
    };
    return {
      items: result.items.map((item) => ({
        method: item.method,
        operationId: item.operation_id,
        path: item.path,
      })),
    } satisfies EndpointList;
  }

  async getFindings(scanId: string) {
    const response = await this.request(
      `/api/scans/${encodeURIComponent(scanId)}/findings`,
    );
    const result = (await response.json()) as {
      items: Array<{
        finding_id: string;
        module_id: string;
        severity: FindingPage["items"][number]["severity"];
        target_endpoint: { operation_id: string; method: string; path: string };
        title: string;
        summary: string;
      }>;
      page: number;
      size: number;
      total_elements: number;
      total_pages: number;
    };
    return {
      items: result.items.map((item) => ({
        findingId: item.finding_id,
        moduleId: item.module_id,
        severity: item.severity,
        summary: item.summary,
        targetEndpoint: {
          method: item.target_endpoint.method,
          operationId: item.target_endpoint.operation_id,
          path: item.target_endpoint.path,
        },
        title: item.title,
      })),
      page: result.page,
      size: result.size,
      totalElements: result.total_elements,
      totalPages: result.total_pages,
    } satisfies FindingPage;
  }

  async getAiReport(scanId: string) {
    const response = await this.request(
      `/api/scans/${encodeURIComponent(scanId)}/ai-report`,
    );
    const result = (await response.json()) as {
      report_id: string;
      scan_id: string;
      summary: string;
      overall_risk: string;
      findings: Array<{
        finding_id: string;
        root_cause: string;
        attack_flow: string[];
        impact: string;
        recommendation: string;
      }>;
    };
    return {
      findings: result.findings.map((finding) => ({
        attackFlow: finding.attack_flow,
        findingId: finding.finding_id,
        impact: finding.impact,
        recommendation: finding.recommendation,
        rootCause: finding.root_cause,
      })),
      overallRisk: result.overall_risk,
      reportId: result.report_id,
      scanId: result.scan_id,
      summary: result.summary,
    } satisfies AiReportResponse;
  }

  async downloadReport(reportId: string): Promise<ReportDownload> {
    const response = await this.request(
      `/api/reports/${encodeURIComponent(reportId)}/download`,
    );
    return {
      blob: await response.blob(),
      filename: getFilename(response.headers.get("Content-Disposition")),
    };
  }
}
