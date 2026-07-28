import { expect, it } from "vitest";
import type { Finding } from "../../contracts";
import { filterFindings } from "./finding-selectors";

const findings: Finding[] = [
  { findingId: "finding-001", moduleId: "BOLA-001", severity: "HIGH", targetEndpoint: { operationId: "getBalance", method: "GET", path: "/accounts/{id}/balance" }, title: "권한 검증", summary: "계정 잔액 검증" },
  { findingId: "finding-002", moduleId: "AUTHN-001", severity: "MEDIUM", targetEndpoint: { operationId: "getProfile", method: "GET", path: "/profile" }, title: "인증 확인", summary: "프로필 접근 검증" },
];
it("combines search and module filters", () => {
  expect(filterFindings(findings, { query: "balance", moduleId: "BOLA-001" })).toHaveLength(1);
  expect(filterFindings(findings, { query: "finding-002", moduleId: "ALL" })).toHaveLength(1);
  expect(filterFindings(findings, { query: "profile", moduleId: "AUTHN-001" })).toHaveLength(1);
});
