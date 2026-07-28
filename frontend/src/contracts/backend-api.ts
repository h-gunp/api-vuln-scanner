export type ScanStatus =
  | "PENDING"
  | "RUNNING"
  | "COMPLETED"
  | "FAILED"
  | "CANCELLED"
  | "TIMED_OUT";

export type ScanStage =
  | "TARGET_VALIDATION"
  | "HEALTH_CHECK"
  | "API_DISCOVERY"
  | "API_NORMALIZATION"
  | "RELATIONSHIP_ANALYSIS"
  | "PLAN_GENERATION"
  | "PLAN_VALIDATION"
  | "MODULE_EXECUTION"
  | "RESULT_VALIDATION"
  | "REPORT_GENERATION"
  | "COMPLETED";

export interface ScanStatusSnapshot {
  scanId: string;
  status: ScanStatus;
  stage: ScanStage;
  progress: number;
  error: string | null;
}

export interface ScanSummary {
  scanId: string;
  targetUrl: string;
  status: ScanStatus;
  stage: ScanStage;
  progress: number;
  apiCount: number;
  findingCount: number;
  plannedModuleCount: number;
  completedModuleCount: number;
  overallRisk: string | null;
  reportStatus: string;
}

export interface Endpoint {
  operationId: string;
  method: string;
  path: string;
}

export interface EndpointList {
  items: Endpoint[];
}

export interface Finding {
  findingId: string;
  moduleId: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  targetEndpoint: Endpoint;
  title: string;
  summary: string;
}

export interface FindingPage {
  items: Finding[];
  page: number;
  size: number;
  totalElements: number;
  totalPages: number;
}

export interface AiReportResponse {
  reportId: string;
  scanId: string;
  summary: string;
  overallRisk: string;
  findings: Array<{
    findingId: string;
    rootCause: string;
    attackFlow: string[];
    impact: string;
    recommendation: string;
  }>;
}
