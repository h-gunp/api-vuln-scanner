import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import type { CreateScanInput } from "../../services/scanner-service";
import { useScannerService } from "../../services/service-context";

const terminalStatuses = new Set(["COMPLETED", "FAILED", "CANCELLED", "TIMED_OUT"]);
const pollInterval = (status?: string) =>
  status && !terminalStatuses.has(status) ? 2_000 : false;

export const scanKeys = {
  summary: (id: string) => ["scan", id, "summary"] as const,
  status: (id: string) => ["scan", id, "status"] as const,
  endpoints: (id: string) => ["scan", id, "endpoints"] as const,
  findings: (id: string) => ["scan", id, "findings"] as const,
  report: (id: string) => ["scan", id, "ai-report"] as const,
};

export function useScanSummary(id: string) {
  const service = useScannerService();
  return useQuery({
    queryKey: scanKeys.summary(id),
    queryFn: () => service.getScanSummary(id),
    refetchInterval: (query) => pollInterval(query.state.data?.status),
  });
}
export function useScanStatus(id: string) {
  const service = useScannerService();
  return useQuery({
    queryKey: scanKeys.status(id),
    queryFn: () => service.getScanStatus(id),
    refetchInterval: (query) => pollInterval(query.state.data?.status),
  });
}
export function useEndpoints(id: string) {
  const service = useScannerService();
  return useQuery({ queryKey: scanKeys.endpoints(id), queryFn: () => service.getEndpoints(id) });
}
export function useFindings(id: string) {
  const service = useScannerService();
  return useQuery({ queryKey: scanKeys.findings(id), queryFn: () => service.getFindings(id) });
}
export function useAiReport(id: string, enabled = true) {
  const service = useScannerService();
  return useQuery({ queryKey: scanKeys.report(id), queryFn: () => service.getAiReport(id), enabled });
}
export function useCreateScan() {
  const service = useScannerService();
  const [isPending, setIsPending] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const createScan = async (input: CreateScanInput) => {
    setIsPending(true);
    setError(null);
    try {
      return await service.createScan(input);
    } catch (cause) {
      const nextError = cause instanceof Error ? cause : new Error("스캔 생성에 실패했습니다.");
      setError(nextError);
      throw nextError;
    } finally {
      setIsPending(false);
    }
  };
  return { createScan, isPending, error };
}
