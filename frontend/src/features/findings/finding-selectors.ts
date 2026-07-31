import type { Finding } from "../../contracts";

export function filterFindings(
  findings: Finding[],
  filters: { query: string; moduleId: string },
) {
  const query = filters.query.trim().toLowerCase();
  return findings.filter(
    (finding) =>
      (filters.moduleId === "ALL" || finding.moduleId === filters.moduleId) &&
      (!query ||
        [
          finding.findingId,
          finding.moduleId,
          finding.title,
          finding.summary,
          finding.targetEndpoint.operationId,
          finding.targetEndpoint.path,
        ].some((value) => value.toLowerCase().includes(query))),
  );
}
