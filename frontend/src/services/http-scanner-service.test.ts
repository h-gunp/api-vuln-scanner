import { afterEach, expect, it, vi } from "vitest";
import { HttpScannerService } from "./http-scanner-service";

const response = (body: unknown, status = 200, headers?: HeadersInit) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });

afterEach(() => vi.unstubAllGlobals());

it("creates a scan with only the confirmed target_url and scan_config fields", async () => {
  const fetchMock = vi.fn().mockResolvedValue(
    response({
      scan_id: "scan_123",
      status: "PENDING",
      stage: "TARGET_VALIDATION",
    }),
  );
  vi.stubGlobal("fetch", fetchMock);

  const service = new HttpScannerService();
  await expect(
    service.createScan({ targetUrl: "https://example.com", scanConfig: null }),
  ).resolves.toEqual({
    scanId: "scan_123",
    status: "PENDING",
    stage: "TARGET_VALIDATION",
  });
  expect(fetchMock).toHaveBeenCalledWith("http://localhost:8080/api/scans", {
    body: JSON.stringify({ target_url: "https://example.com", scan_config: null }),
    headers: { "Content-Type": "application/json" },
    method: "POST",
  });
});

it("maps the common API error response to ApiError", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue(
      response(
        {
          error: {
            code: "SCAN_NOT_FOUND",
            message: "해당 스캔을 찾을 수 없습니다.",
            details: null,
          },
        },
        404,
      ),
    ),
  );

  const service = new HttpScannerService();
  await expect(service.getScanSummary("missing")).rejects.toMatchObject({
    code: "SCAN_NOT_FOUND",
    message: "해당 스캔을 찾을 수 없습니다.",
    status: 404,
  });
});

it("maps confirmed scan, endpoint, Finding, and report payloads without inventing fields", async () => {
  const fetchMock = vi
    .fn()
    .mockResolvedValueOnce(
      response({
        scan_id: "scan_123",
        status: "RUNNING",
        stage: "MODULE_EXECUTION",
        progress: 78,
        error: null,
      }),
    )
    .mockResolvedValueOnce(
      response({
        items: [
          {
            operation_id: "GET:/api/users/{user_id}",
            method: "GET",
            path: "/api/users/{user_id}",
          },
        ],
      }),
    )
    .mockResolvedValueOnce(
      response({
        items: [
          {
            finding_id: "finding_001",
            module_id: "BOLA-001",
            severity: "HIGH",
            target_endpoint: {
              operation_id: "GET:/api/users/{user_id}",
              method: "GET",
              path: "/api/users/{user_id}",
            },
            title: "객체 수준 인가 검증 실패",
            summary: "다른 사용자의 객체 정보에 접근할 수 있습니다.",
          },
        ],
        page: 1,
        size: 20,
        total_elements: 1,
        total_pages: 1,
      }),
    )
    .mockResolvedValueOnce(
      response({
        report_id: "report_123",
        scan_id: "scan_123",
        summary: "총 1개의 취약점이 확인되었습니다.",
        overall_risk: "HIGH",
        findings: [
          {
            finding_id: "finding_001",
            root_cause: "객체 소유권 검증이 누락되었습니다.",
            attack_flow: ["User A로 로그인"],
            impact: "다른 사용자의 정보가 노출될 수 있습니다.",
            recommendation: "객체 소유자를 비교해야 합니다.",
          },
        ],
      }),
    );
  vi.stubGlobal("fetch", fetchMock);

  const service = new HttpScannerService();
  await expect(service.getScanStatus("scan_123")).resolves.toMatchObject({
    scanId: "scan_123",
    stage: "MODULE_EXECUTION",
    status: "RUNNING",
  });
  await expect(service.getEndpoints("scan_123")).resolves.toEqual({
    items: [
      {
        method: "GET",
        operationId: "GET:/api/users/{user_id}",
        path: "/api/users/{user_id}",
      },
    ],
  });
  await expect(service.getFindings("scan_123")).resolves.toMatchObject({
    items: [
      {
        findingId: "finding_001",
        moduleId: "BOLA-001",
        severity: "HIGH",
        targetEndpoint: { method: "GET", path: "/api/users/{user_id}" },
      },
    ],
    totalElements: 1,
  });
  await expect(service.getAiReport("scan_123")).resolves.toMatchObject({
    reportId: "report_123",
    scanId: "scan_123",
    findings: [{ findingId: "finding_001", attackFlow: ["User A로 로그인"] }],
  });
});

it("downloads the backend-generated report PDF by report_id", async () => {
  const pdf = new Blob(["%PDF-"], { type: "application/pdf" });
  const fetchMock = vi.fn().mockResolvedValue(
    new Response(pdf, {
      headers: {
        "Content-Disposition": 'attachment; filename="security-report-scan_123.pdf"',
        "Content-Type": "application/pdf",
      },
    }),
  );
  vi.stubGlobal("fetch", fetchMock);

  const service = new HttpScannerService();
  await expect(service.downloadReport("report_123")).resolves.toEqual({
    blob: pdf,
    filename: "security-report-scan_123.pdf",
  });
  expect(fetchMock).toHaveBeenCalledWith(
    "http://localhost:8080/api/reports/report_123/download",
    undefined,
  );
});
