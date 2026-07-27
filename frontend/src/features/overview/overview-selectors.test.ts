import { expect, it } from "vitest";
import { mockApiGraph, mockScanResult } from "../../services/mock/mock-data";
import {
  countFindingsByType,
  countOperationsByMethod,
  selectRecentFindings,
} from "./overview-selectors";
it("summarizes overview data", () => {
  expect(countOperationsByMethod(mockApiGraph)).toEqual({ GET: 24, POST: 4 });
  expect(countFindingsByType(mockScanResult)).toEqual({
    BOLA: 2,
    DATA: 1,
    AUTH: 1,
  });
  expect(selectRecentFindings(mockScanResult, 3)).toHaveLength(3);
});
