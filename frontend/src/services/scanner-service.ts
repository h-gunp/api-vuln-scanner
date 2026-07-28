import type {
  AiReportResponse,
  EndpointList,
  FindingDetail,
  FindingPage,
  ScanStatusSnapshot,
  ScanSummary,
} from "../contracts";

export interface CreateScanInput {
  targetUrl: string;
  scanConfig: unknown | null;
}

export interface ReportDownload {
  blob: Blob;
  filename: string | null;
}

/** Legacy fixture type retained only for security-redaction unit tests. */
export interface RedactedEvidence {
  ref: string;
  requestSummary: string;
  responseSummary: string;
}

export interface ScannerService {
  createScan(input: CreateScanInput): Promise<{
    scanId: string;
    status: string;
    stage: string;
  }>;
  getScanSummary(scanId: string): Promise<ScanSummary>;
  getScanStatus(scanId: string): Promise<ScanStatusSnapshot>;
  getEndpoints(scanId: string): Promise<EndpointList>;
  getFindings(scanId: string): Promise<FindingPage>;
  getFinding(findingId: string): Promise<FindingDetail>;
  getAiReport(scanId: string): Promise<AiReportResponse>;
  downloadReport(reportId: string): Promise<ReportDownload>;
}

export class MockNotFoundError extends Error {
  readonly name = "MockNotFoundError";
}

export interface MockServiceDebugSnapshot {
  createdScanIds: string[];
}
