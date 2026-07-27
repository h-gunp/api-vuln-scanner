import type { RedactedEvidence } from "../scanner-service";

export const mockEvidenceByRef: Readonly<Record<string, RedactedEvidence>> = {
  "evidence:redacted:001": {
    ref: "evidence:redacted:001",
    requestSummary: "GET /api/accounts/[REDACTED] as User A",
    responseSummary: "200 account_id=[REDACTED], balance=[REDACTED]",
  },
  "evidence:redacted:002": {
    ref: "evidence:redacted:002",
    requestSummary: "GET /api/accounts/[REDACTED] as User B",
    responseSummary: "200 owner_id=[REDACTED]",
  },
  "evidence:redacted:003": {
    ref: "evidence:redacted:003",
    requestSummary: "GET /api/customers/[REDACTED]",
    responseSummary: "200 email=[REDACTED]",
  },
  "evidence:redacted:004": {
    ref: "evidence:redacted:004",
    requestSummary: "GET /api/profile with session=[REDACTED]",
    responseSummary: "200 profile_id=[REDACTED]",
  },
};
