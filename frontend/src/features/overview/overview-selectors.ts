import type { NormalizedApiGraph, ScanResult } from "../../contracts";
export function countOperationsByMethod(graph: NormalizedApiGraph) {
  return graph.operations.reduce<Record<string, number>>(
    (counts, operation) => ({
      ...counts,
      [operation.method]: (counts[operation.method] ?? 0) + 1,
    }),
    {},
  );
}
export function countFindingsByType(result: ScanResult) {
  return result.findings.reduce<Record<string, number>>(
    (counts, finding) => ({
      ...counts,
      [finding.vulnerability_type]:
        (counts[finding.vulnerability_type] ?? 0) + 1,
    }),
    {},
  );
}
export function selectRecentFindings(result: ScanResult, limit: number) {
  return result.findings.slice(0, limit);
}
