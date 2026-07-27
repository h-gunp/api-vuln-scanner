import type { AiReport, NormalizedApiGraph, ScanResult } from "../contracts";

export interface CreateScanInput {
  targetUrl: string;
  userA: { username: string; password: string };
  userB: { username: string; password: string };
}
export interface ScanOverview {
  scanId: string;
  targetUrl: string;
  progress: number;
  stage: string;
  reportStatus: "waiting" | "generating" | "ready";
}
export type ScanStageStatus = "completed" | "running" | "waiting" | "failed";
export interface ScanProgressStage {
  id:
    | "authentication"
    | "api-discovery"
    | "relationship-analysis"
    | "module-verification"
    | "ai-report";
  label: string;
  description: string;
  status: ScanStageStatus;
}
export interface ScanProgressDetail {
  scanId: string;
  progress: number;
  currentStageId: ScanProgressStage["id"];
  stages: ScanProgressStage[];
}
export interface RedactedEvidence {
  ref: string;
  requestSummary: string;
  responseSummary: string;
}
export class MockNotFoundError extends Error {
  readonly name = "MockNotFoundError";
}
export interface ScannerService {
  createScan(input: CreateScanInput): Promise<{ scanId: string }>;
  getOverview(scanId: string): Promise<ScanOverview>;
  getScanProgress(scanId: string): Promise<ScanProgressDetail>;
  getApiGraph(scanId: string): Promise<NormalizedApiGraph>;
  getScanResult(scanId: string): Promise<ScanResult>;
  getEvidence(ref: string): Promise<RedactedEvidence>;
  getAiReport(scanId: string): Promise<AiReport>;
}
export interface MockServiceDebugSnapshot {
  createdScanIds: string[];
}
