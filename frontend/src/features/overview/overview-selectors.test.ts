import { expect, it } from "vitest";
import type { Endpoint, Finding } from "../../contracts";
import { countFindingsByType, countOperationsByMethod, selectRecentFindings } from "./overview-selectors";

const endpoints: Endpoint[] = [
  { operationId: "one", method: "GET", path: "/one" },
  { operationId: "two", method: "GET", path: "/two" },
  { operationId: "three", method: "POST", path: "/three" },
];
const findings: Finding[] = [
  { findingId: "one", moduleId: "BOLA-001", severity: "HIGH", targetEndpoint: endpoints[0], title: "One", summary: "One" },
  { findingId: "two", moduleId: "BOLA-001", severity: "HIGH", targetEndpoint: endpoints[1], title: "Two", summary: "Two" },
  { findingId: "three", moduleId: "AUTHN-001", severity: "LOW", targetEndpoint: endpoints[2], title: "Three", summary: "Three" },
];
it("summarizes confirmed overview response fields", () => {
  expect(countOperationsByMethod(endpoints)).toEqual({ GET: 2, POST: 1 });
  expect(countFindingsByType(findings)).toEqual({ "BOLA-001": 2, "AUTHN-001": 1 });
  expect(selectRecentFindings(findings, 2)).toHaveLength(2);
});
