import { describe, expect, it } from "vitest";
import { allMockFixtures, mockScanResult } from "../services/mock/mock-data";
import { mockEvidenceByRef } from "../services/mock/mock-evidence";
const forbiddenPatterns = [
  /Bearer\s+[A-Za-z0-9._-]+/i,
  /"password"\s*:\s*"(?!<|env:)/i,
  /sk-[A-Za-z0-9]{12,}/,
  /eyJ[A-Za-z0-9_-]{10,}\./,
];
describe("safe mock fixtures", () => {
  it("contains no credential or token shaped values", () => {
    const serialized = JSON.stringify(allMockFixtures);
    forbiddenPatterns.forEach((pattern) =>
      expect(serialized).not.toMatch(pattern),
    );
  });
  it("uses only redacted evidence references", () => {
    mockScanResult.findings
      .flatMap((finding) => finding.evidence_refs)
      .forEach((ref) => expect(ref).toMatch(/^evidence:redacted:/));
  });
  it("keeps all evidence redacted", () => {
    Object.values(mockEvidenceByRef).forEach((item) =>
      expect(`${item.requestSummary}${item.responseSummary}`).toContain(
        "[REDACTED]",
      ),
    );
  });
});
