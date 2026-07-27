import type { ScanResult } from "../../contracts";
type Finding = ScanResult["findings"][number];
export function filterFindings(
  findings: Finding[],
  filters: { query: string; vulnerabilityType: string },
) {
  const query = filters.query.trim().toLowerCase();
  return findings.filter(
    (finding) =>
      (filters.vulnerabilityType === "ALL" ||
        finding.vulnerability_type === filters.vulnerabilityType) &&
      (!query ||
        [
          finding.finding_id,
          finding.operation_id,
          finding.vulnerability_type,
          ...finding.affected_fields.map((field) => field.field_path),
        ].some((value) => value.toLowerCase().includes(query))),
  );
}
