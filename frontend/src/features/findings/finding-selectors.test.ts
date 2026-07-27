import { expect, it } from "vitest";
import { mockScanResult } from "../../services/mock/mock-data";
import { filterFindings } from "./finding-selectors";
it("combines search and vulnerability type filters", () => {
  expect(
    filterFindings(mockScanResult.findings, {
      query: "balance",
      vulnerabilityType: "BOLA",
    }),
  ).toHaveLength(1);
  expect(
    filterFindings(mockScanResult.findings, {
      query: "finding-003",
      vulnerabilityType: "ALL",
    }),
  ).toHaveLength(1);
  expect(
    filterFindings(mockScanResult.findings, {
      query: "profile",
      vulnerabilityType: "AUTH",
    }),
  ).toHaveLength(1);
});
