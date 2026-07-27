import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import type { CreateScanInput } from "../../services/scanner-service";
import { useScannerService } from "../../services/service-context";

export const scanKeys = {
  overview: (id: string) => ["scan", id, "overview"] as const,
  progress: (id: string) => ["scan", id, "progress"] as const,
  apis: (id: string) => ["scan", id, "apis"] as const,
  findings: (id: string) => ["scan", id, "findings"] as const,
  report: (id: string) => ["scan", id, "ai-report"] as const,
  evidence: (ref: string) => ["evidence", ref] as const,
};
export function useScanOverview(id: string) {
  const service = useScannerService();
  return useQuery({
    queryKey: scanKeys.overview(id),
    queryFn: () => service.getOverview(id),
  });
}
export function useScanProgress(id: string) {
  const service = useScannerService();
  return useQuery({
    queryKey: scanKeys.progress(id),
    queryFn: () => service.getScanProgress(id),
  });
}
export function useApiGraph(id: string) {
  const service = useScannerService();
  return useQuery({
    queryKey: scanKeys.apis(id),
    queryFn: () => service.getApiGraph(id),
  });
}
export function useScanResult(id: string) {
  const service = useScannerService();
  return useQuery({
    queryKey: scanKeys.findings(id),
    queryFn: () => service.getScanResult(id),
  });
}
export function useAiReport(id: string) {
  const service = useScannerService();
  return useQuery({
    queryKey: scanKeys.report(id),
    queryFn: () => service.getAiReport(id),
  });
}
export function useEvidence(ref: string) {
  const service = useScannerService();
  return useQuery({
    queryKey: scanKeys.evidence(ref),
    queryFn: () => service.getEvidence(ref),
  });
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
      const nextError =
        cause instanceof Error ? cause : new Error("Mock scan creation failed");
      setError(nextError);
      throw nextError;
    } finally {
      setIsPending(false);
    }
  };
  return { createScan, isPending, error };
}
