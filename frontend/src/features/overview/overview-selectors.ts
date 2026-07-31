import type { Endpoint, Finding } from "../../contracts";

export function countOperationsByMethod(endpoints: Endpoint[]) {
  return endpoints.reduce<Record<string, number>>(
    (counts, endpoint) => ({
      ...counts,
      [endpoint.method]: (counts[endpoint.method] ?? 0) + 1,
    }),
    {},
  );
}
export function countFindingsByType(findings: Finding[]) {
  return findings.reduce<Record<string, number>>(
    (counts, finding) => ({
      ...counts,
      [finding.moduleId]: (counts[finding.moduleId] ?? 0) + 1,
    }),
    {},
  );
}
export function selectRecentFindings(findings: Finding[], limit: number) {
  return findings.slice(0, limit);
}
