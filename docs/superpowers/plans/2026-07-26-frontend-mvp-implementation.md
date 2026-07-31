# API Vulnerability Scanner Frontend MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Execute inline in the current session; do not dispatch subagents.

**Goal:** Build a complete, responsive React frontend for the first MVP using the finalized JSON contracts and replaceable mock services, with no dependency on unfinished backend APIs.

**Architecture:** Create an isolated `frontend/` Vite application. Contract types mirror the finalized JSON files, UI code consumes feature-level query hooks, and query hooks depend on a `ScannerService` interface backed by an in-memory mock implementation. The approved left-sidebar UI provides an overview page and navigable API, Finding, and AI Report detail pages.

**Tech Stack:** React, TypeScript, Vite, Tailwind CSS, React Router, TanStack Query, Vitest, Testing Library, Playwright, axe-core, jsPDF

## Global Constraints

- Treat `origin/docs:docs/최종 JSON 데이터 계약.md` as the only finalized data-contract source.
- Do not treat the other GitHub documents or the earlier architecture documents as implementation authority.
- Use the approved left sidebar (`왼쪽 사이드바`) with `Overview`, `APIs`, `Findings`, and `AI Report`.
- Use neutral white and gray surfaces, purple emphasis, Cloudflare-style summary visualizations, and Sentry-style Finding exploration.
- Say and write `mock 데이터`, never the Korean transliteration of “mock”.
- Keep all frontend code inside `frontend/`.
- Do not add real backend calls or invent production API request and error contracts.
- Do not store User A/B credentials in mock fixtures, URLs, logs, module state, `localStorage`, `sessionStorage`, IndexedDB, or generated reports.
- Keep credentials only in controlled component state and clear them after mock submission and component unmount.
- Do not put actual tokens, credentials, object IDs, or unredacted evidence in source files.
- Do not modify the user’s existing `.gitignore` change or unrelated untracked `docs/` files.
- Do not create branches, commit, push, rebase, or open a PR without a separate explicit user request.
- Run each task’s focused checks before advancing. After the final task, run every required quality gate from a clean frontend install.
- Run this plan in a Codex Cloud Linux container using Bash. Unless a task says otherwise, start commands from the repository root and use `cd`, not PowerShell-specific navigation commands.
- Before implementation, confirm the Cloud checkout includes `AGENTS.md`, this plan, and the approved UI design document. Cloud cannot read local uncommitted files.
- Keep Cloud agent internet access limited to dependency installation. Use the configured common-dependency allowlist; do not add secrets or enable unrestricted access.

## Execution Autonomy

- Continue from one task to the next without waiting for user confirmation.
- Make only implementation choices already bounded by this plan and the approved UI design.
- When a test fails, diagnose and fix it before advancing.
- When a dependency command is blocked by the sandbox or network, request the required approval and retry.
- Do not weaken tests, remove required functionality, or replace a failing required gate with a less strict command.
- Do not declare completion while any dashboard card, chart summary, panel, row, or action lacks an implemented destination.
- Do not leave placeholder click handlers, empty navigation callbacks, `href="#"`, or detail routes that render a blank page.
- Declare completion only when every item in **Final Success Criteria** passes.
- If an external condition makes a required gate impossible after safe retries, stop with the task incomplete and report the exact blocker and remaining command. Do not claim completion.

## Planned File Structure

```text
frontend/
├─ index.html
├─ package.json
├─ package-lock.json
├─ vite.config.ts
├─ playwright.config.ts
├─ eslint.config.js
├─ tsconfig.json
├─ tsconfig.app.json
├─ tsconfig.node.json
├─ src/
│  ├─ main.tsx
│  ├─ app/
│  │  ├─ App.tsx
│  │  ├─ router.tsx
│  │  └─ providers.tsx
│  ├─ styles/
│  │  └─ index.css
│  ├─ contracts/
│  │  ├─ common.ts
│  │  ├─ target-profile.ts
│  │  ├─ normalized-api-graph.ts
│  │  ├─ relationship-analysis.ts
│  │  ├─ scan-plan.ts
│  │  ├─ scan-result.ts
│  │  ├─ ai-report.ts
│  │  └─ index.ts
│  ├─ services/
│  │  ├─ scanner-service.ts
│  │  ├─ service-context.tsx
│  │  └─ mock/
│  │     ├─ mock-data.ts
│  │     ├─ mock-evidence.ts
│  │     ├─ mock-pdf.ts
│  │     └─ mock-scanner-service.ts
│  ├─ components/
│  │  ├─ layout/
│  │  │  ├─ AppShell.tsx
│  │  │  ├─ Sidebar.tsx
│  │  │  └─ ContentHeader.tsx
│  │  └─ ui/
│  │     ├─ AsyncState.tsx
│  │     ├─ Badge.tsx
│  │     ├─ DonutChart.tsx
│  │     ├─ EmptyState.tsx
│  │     ├─ MetricCard.tsx
│  │     ├─ SearchField.tsx
│  │     └─ Skeleton.tsx
│  ├─ features/
│  │  ├─ scans/
│  │  │  ├─ scan-types.ts
│  │  │  ├─ scan-queries.ts
│  │  │  ├─ ScanSetupPage.tsx
│  │  │  ├─ ScanSetupPage.test.tsx
│  │  │  ├─ ScanProgressPage.tsx
│  │  │  └─ ScanProgressPage.test.tsx
│  │  ├─ overview/
│  │  │  ├─ overview-selectors.ts
│  │  │  ├─ OverviewPage.tsx
│  │  │  ├─ overview-selectors.test.ts
│  │  │  └─ OverviewPage.test.tsx
│  │  ├─ apis/
│  │  │  ├─ api-selectors.ts
│  │  │  ├─ ApiListPage.tsx
│  │  │  ├─ ApiDetailPage.tsx
│  │  │  ├─ api-selectors.test.ts
│  │  │  └─ ApiPages.test.tsx
│  │  ├─ findings/
│  │  │  ├─ finding-selectors.ts
│  │  │  ├─ FindingsPage.tsx
│  │  │  ├─ FindingDetailPage.tsx
│  │  │  ├─ finding-selectors.test.ts
│  │  │  └─ FindingPages.test.tsx
│  │  └─ reports/
│  │     ├─ report-download.ts
│  │     ├─ AiReportPage.tsx
│  │     ├─ ReportPreviewPage.tsx
│  │     └─ ReportPages.test.tsx
│  └─ test/
│     ├─ render.tsx
│     ├─ setup.ts
│     └─ security.test.ts
└─ e2e/
   ├─ mvp-flow.spec.ts
   └─ responsive-accessibility.spec.ts
```

---

### Task 1: Frontend foundation and executable test harness

**Files:**
- Create: `frontend/package.json`
- Create: `frontend/vite.config.ts`
- Create: `frontend/playwright.config.ts`
- Create: `frontend/eslint.config.js`
- Create: `frontend/tsconfig*.json`
- Create: `frontend/index.html`
- Create: `frontend/src/main.tsx`
- Create: `frontend/src/app/App.tsx`
- Create: `frontend/src/app/providers.tsx`
- Create: `frontend/src/styles/index.css`
- Create: `frontend/src/test/setup.ts`

**Interfaces:**
- Produces: `AppProviders({ children }: PropsWithChildren)` and an executable React application.
- Produces scripts: `dev`, `build`, `typecheck`, `lint`, `test`, `test:coverage`, `test:e2e`.

- [ ] **Step 1: Scaffold the isolated React application**

Run from the repository root:

```bash
npm create vite@latest frontend -- --template react-ts
cd frontend
npm install
npm install react-router-dom @tanstack/react-query lucide-react jspdf
npm install -D tailwindcss @tailwindcss/vite vitest @vitest/coverage-v8 jsdom @testing-library/react @testing-library/jest-dom @testing-library/user-event @playwright/test @axe-core/playwright
npx playwright install chromium
```

Expected: `frontend/package.json` and `frontend/package-lock.json` exist and Chromium installation succeeds.

- [ ] **Step 2: Configure scripts and quality thresholds**

Add these scripts to `frontend/package.json`:

```json
{
  "scripts": {
    "dev": "vite",
    "build": "tsc -b && vite build",
    "typecheck": "tsc -b --pretty false",
    "lint": "eslint . --max-warnings 0",
    "test": "vitest run",
    "test:coverage": "vitest run --coverage",
    "test:e2e": "playwright test"
  }
}
```

Configure `vite.config.ts` with React, Tailwind, jsdom, `src/test/setup.ts`, and coverage thresholds:

```ts
coverage: {
  provider: "v8",
  thresholds: {
    lines: 80,
    functions: 80,
    statements: 80,
    branches: 70,
  },
}
```

- [ ] **Step 3: Write the failing application smoke test**

Create `frontend/src/app/App.test.tsx`:

```tsx
import { render, screen } from "@testing-library/react";
import { App } from "./App";

it("renders the product name", () => {
  render(<App />);
  expect(screen.getByText("VulnScope")).toBeInTheDocument();
});
```

- [ ] **Step 4: Verify the smoke test fails**

Run:

```bash
npm test -- src/app/App.test.tsx
```

Expected: FAIL because the product shell has not been implemented.

- [ ] **Step 5: Add the minimal provider and application entry**

Implement `AppProviders` with `QueryClientProvider`, configure Tailwind through `@tailwindcss/vite`, import `src/styles/index.css`, and render a minimal `VulnScope` heading.

- [ ] **Step 6: Verify the foundation**

Run:

```bash
npm test -- src/app/App.test.tsx
npm run typecheck
npm run lint
npm run build
```

Expected: all commands exit `0`.

---

### Task 2: Finalized JSON contract types and safe mock fixtures

**Files:**
- Create: `frontend/src/contracts/*.ts`
- Create: `frontend/src/contracts/index.ts`
- Create: `frontend/src/services/mock/mock-data.ts`
- Create: `frontend/src/services/mock/mock-evidence.ts`
- Create: `frontend/src/test/security.test.ts`

**Interfaces:**
- Produces: `TargetProfile`, `NormalizedApiGraph`, `RelationshipAnalysis`, `ScanPlan`, `ScanResult`, `AiReport`.
- Produces constants: `mockTargetProfile`, `mockApiGraph`, `mockRelationshipAnalysis`, `mockScanPlan`, `mockScanResult`, `mockAiReport`.

- [ ] **Step 1: Define shared contract primitives**

Create `common.ts`:

```ts
export type JsonFieldType =
  | "string"
  | "integer"
  | "number"
  | "boolean"
  | "object"
  | "array"
  | "unknown";

export type InputLocation = "path" | "query" | "header" | "body";
export type AffectedLocation = "request" | "response";
export type DataClass =
  | "identity"
  | "account"
  | "financial"
  | "authentication"
  | "transaction"
  | "other";
```

- [ ] **Step 2: Implement all six contract types**

Use literal schema versions from the finalized contract:

```ts
export interface TargetProfile {
  schema_version: "1.1";
  scan_id: string;
  target: {
    base_url: string;
    allowed_paths: string[];
    allowed_methods: string[];
  };
  discovery: {
    sources: Array<"openapi" | "crawl">;
    max_depth: number;
  };
  authentication: {
    login: {
      method: string;
      path: string;
      content_type: string;
      username_field: string;
      password_field: string;
      session: { type: string; token_field: string };
    };
    actors: Array<{
      actor_id: "user_a" | "user_b";
      username_env: string;
      password_env: string;
    }>;
  };
  safety_policy: {
    max_requests: number;
    requests_per_second: number;
    state_change_policy: string;
    approved_modules: string[];
  };
}
```

Define the other five interfaces exactly as follows:

```ts
export interface NormalizedApiGraph {
  schema_version: "1.1";
  scan_id: string;
  operations: Array<{
    operation_id: string;
    method: string;
    path_template: string;
    inputs: Array<{
      location: InputLocation;
      field_path: string;
      type: JsonFieldType;
    }>;
    outputs: Array<{
      field_path: string;
      type: JsonFieldType;
    }>;
  }>;
}

export interface RelationshipAnalysis {
  schema_version: "1.2";
  scan_id: string;
  model_name: string;
  prompt_version: string;
  prompt_sha256: string;
  approved_module_ids: string[];
  relationships: Array<{
    relationship_id: string;
    source_operation_id: string;
    target_operation_id: string;
    source_field: string | null;
    target_parameter: string | null;
    target_parameter_location: InputLocation | null;
    relationship_type: string;
    confidence: number;
  }>;
  test_candidates: Array<{
    candidate_id: string;
    module_id: string;
    target_operation_id: string;
    required_object_types: string[];
    rationale: string;
    priority: number;
    executable: boolean;
    missing_requirements: string[];
    binding_hints: Array<{
      parameter: string;
      location: InputLocation;
      binding_type: "object_binding" | "parameter_binding";
      object_type: string | null;
    }>;
  }>;
}

export interface ScanPlan {
  schema_version: "1.2";
  plan_id: string;
  scan_id: string;
  model_name: string;
  prompt_version: string;
  prompt_sha256: string;
  status: "PENDING_APPROVAL";
  budget: {
    requests_already_used: number;
    estimated_execution_requests: number;
    max_requests: number;
    within_budget: boolean;
  };
  steps: Array<{
    order: number;
    candidate_id: string;
    module_id: string;
    target_operation_id: string;
    target_endpoint: {
      method: string;
      path_template: string;
    };
    input_bindings: Array<{
      parameter: string;
      location: InputLocation;
      binding_type: "object_binding" | "parameter_binding";
      object_type: string | null;
      owner: "user_a" | "user_b" | null;
    }>;
  }>;
}

export interface ScanResult {
  schema_version: "1.2";
  scan_id: string;
  findings: Array<{
    finding_id: string;
    operation_id: string;
    vulnerability_type: string;
    verification: {
      rule_id: string;
      verified_conditions: string[];
    };
    affected_fields: Array<{
      location: AffectedLocation;
      field_path: string;
      data_class: DataClass;
    }>;
    evidence_refs: string[];
  }>;
}

export interface AiReport {
  schema_version: "1.2";
  scan_id: string;
  model_name: string;
  prompt_version: string;
  prompt_sha256: string;
  overall_risk: string;
  overall_risk_basis: "rule:max_verified_severity";
  summary: string;
  findings: Array<{
    finding_id: string;
    analysis_id: string;
    root_cause: string;
    attack_flow: string[];
    impact: string;
    recommendation: string;
    severity: string;
    evidence_refs: string[];
  }>;
}
```

Do not add `security`, raw response bodies, tokens, actual object IDs, `verdict`, or top-level `severity` to `ScanResult`.

- [ ] **Step 3: Write compile-time fixture assertions**

Each fixture must use `satisfies`, for example:

```ts
export const mockScanResult = {
  schema_version: "1.2",
  scan_id: "scan-001",
  findings: [
    {
      finding_id: "finding-001",
      operation_id: "GET:/api/accounts/{account_id}",
      vulnerability_type: "BOLA",
      verification: {
        rule_id: "BOLA-OBJECT-OWNER-MISMATCH",
        verified_conditions: ["FOREIGN_OBJECT_RETURNED"],
      },
      affected_fields: [
        {
          location: "response",
          field_path: "account_id",
          data_class: "account",
        },
      ],
      evidence_refs: ["evidence:redacted:001"],
    },
  ],
} satisfies ScanResult;
```

- [ ] **Step 4: Write security tests for fixtures**

Create assertions that recursively serialize all mock fixtures and reject:

```ts
const forbiddenPatterns = [
  /Bearer\s+[A-Za-z0-9._-]+/i,
  /"password"\s*:\s*"(?!<|env:)/i,
  /sk-[A-Za-z0-9]{12,}/,
  /eyJ[A-Za-z0-9_-]{10,}\./,
];
```

Also assert every `evidence_ref` starts with `evidence:redacted:`.

- [ ] **Step 5: Verify contract and fixture tests**

Run:

```bash
npm test -- src/test/security.test.ts
npm run typecheck
```

Expected: all fixtures typecheck and all security assertions pass.

---

### Task 3: Replaceable service boundary and TanStack Query hooks

**Files:**
- Create: `frontend/src/services/scanner-service.ts`
- Create: `frontend/src/services/service-context.tsx`
- Create: `frontend/src/services/mock/mock-scanner-service.ts`
- Create: `frontend/src/features/scans/scan-types.ts`
- Create: `frontend/src/features/scans/scan-queries.ts`
- Create: `frontend/src/services/mock/mock-scanner-service.test.ts`

**Interfaces:**
- Produces: `ScannerService`.
- Produces: cache-free `useCreateScan`, plus query-backed `useScanOverview`, `useScanProgress`, `useApiGraph`, `useScanResult`, `useEvidence`, `useAiReport`.

- [ ] **Step 1: Write service behavior tests**

Test these exact behaviors:

```ts
it("returns scan-001 without retaining submitted credentials");
it("returns finalized-contract fixtures by scan id");
it("returns a complete five-stage mock scan progress view");
it("rejects an unknown scan id with MockNotFoundError");
it("returns only redacted evidence content");
```

After `createScan(input)`, inspect the mock service’s public debug snapshot and assert neither usernames nor passwords are present.

- [ ] **Step 2: Verify the service tests fail**

Run:

```bash
npm test -- src/services/mock/mock-scanner-service.test.ts
```

Expected: FAIL because `ScannerService` is not implemented.

- [ ] **Step 3: Define the service interface**

```ts
export interface CreateScanInput {
  targetUrl: string;
  userA: { username: string; password: string };
  userB: { username: string; password: string };
}

export interface ScanOverview {
  scanId: string;
  targetUrl: string;
  progress: number;
  stage: string;
  reportStatus: "waiting" | "generating" | "ready";
}

export type ScanStageStatus = "completed" | "running" | "waiting" | "failed";

export interface ScanProgressStage {
  id:
    | "authentication"
    | "api-discovery"
    | "relationship-analysis"
    | "module-verification"
    | "ai-report";
  label: string;
  description: string;
  status: ScanStageStatus;
}

export interface ScanProgressDetail {
  scanId: string;
  progress: number;
  currentStageId: ScanProgressStage["id"];
  stages: ScanProgressStage[];
}

export interface RedactedEvidence {
  ref: string;
  requestSummary: string;
  responseSummary: string;
}

export class MockNotFoundError extends Error {
  readonly name = "MockNotFoundError";
}

export interface ScannerService {
  createScan(input: CreateScanInput): Promise<{ scanId: string }>;
  getOverview(scanId: string): Promise<ScanOverview>;
  getScanProgress(scanId: string): Promise<ScanProgressDetail>;
  getApiGraph(scanId: string): Promise<NormalizedApiGraph>;
  getScanResult(scanId: string): Promise<ScanResult>;
  getEvidence(ref: string): Promise<RedactedEvidence>;
  getAiReport(scanId: string): Promise<AiReport>;
}

export interface MockServiceDebugSnapshot {
  createdScanIds: string[];
}
```

- [ ] **Step 4: Implement the in-memory mock service**

Use a fixed delay of `80ms`. Validate that URL protocol is `http:` or `https:`. Never assign `CreateScanInput`, actor usernames, or passwords to an object or closure after `createScan` returns. The concrete `MockScannerService` exposes:

```ts
getDebugSnapshot(): MockServiceDebugSnapshot {
  return { createdScanIds: [...this.createdScanIds] };
}
```

The snapshot contains scan IDs only.

- [ ] **Step 5: Add service context and query hooks**

`ServiceProvider` receives a `ScannerService`. Query keys must be:

```ts
["scan", scanId, "overview"]
["scan", scanId, "progress"]
["scan", scanId, "apis"]
["scan", scanId, "findings"]
["scan", scanId, "ai-report"]
["evidence", evidenceRef]
```

Implement the read hooks with `useQuery`. Implement `useCreateScan` without `useMutation` so credentials never enter TanStack Query’s mutation cache:

```ts
export function useCreateScan() {
  const service = useScannerService();
  const [isPending, setIsPending] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const createScan = async (input: CreateScanInput) => {
    setIsPending(true);
    setError(null);
    try {
      return await service.createScan(input);
    } catch (cause) {
      const nextError =
        cause instanceof Error ? cause : new Error("Mock scan creation failed");
      setError(nextError);
      throw nextError;
    } finally {
      setIsPending(false);
    }
  };

  return { createScan, isPending, error };
}
```

- [ ] **Step 6: Verify service and hook boundaries**

Run:

```bash
npm test -- src/services/mock/mock-scanner-service.test.ts
npm run typecheck
npm run lint
```

Expected: all commands pass.

---

### Task 4: Router, left sidebar, and shared UI primitives

**Files:**
- Create: `frontend/src/app/router.tsx`
- Create: `frontend/src/components/layout/*.tsx`
- Create: `frontend/src/components/ui/*.tsx`
- Modify: `frontend/src/app/App.tsx`
- Test: `frontend/src/app/router.test.tsx`
- Test: `frontend/src/components/layout/AppShell.test.tsx`

**Interfaces:**
- Produces routes under `/scans`.
- Produces: `AppShell`, `Sidebar`, `ContentHeader`, `MetricCard`, `DonutChart`, `AsyncState`.

- [ ] **Step 1: Write routing and sidebar tests**

Assert:

```tsx
expect(screen.getByRole("link", { name: "Overview" })).toHaveAttribute(
  "href",
  "/scans/scan-001/overview",
);
expect(screen.getByRole("link", { name: "APIs" })).toBeVisible();
expect(screen.getByRole("link", { name: "Findings" })).toBeVisible();
expect(screen.getByRole("link", { name: "AI Report" })).toBeVisible();
```

Also test active-route indication uses `aria-current="page"`.

- [ ] **Step 2: Verify layout tests fail**

Run:

```bash
npm test -- src/app/router.test.tsx src/components/layout/AppShell.test.tsx
```

- [ ] **Step 3: Implement the route tree**

```text
/
└─ redirect to /scans/new
/scans/new
/scans/:scanId
├─ redirect to overview
├─ overview
├─ progress
├─ apis
├─ apis/:operationId
├─ findings
├─ findings/:findingId
├─ ai-report
└─ ai-report/preview
```

Use `encodeURIComponent(operationId)` when creating API-detail links and `decodeURIComponent` when reading the parameter.

- [ ] **Step 4: Implement approved layout primitives**

Sidebar requirements:

- Product identity at the top.
- Workspace and current scan summary.
- Four navigation links.
- Request budget summary at the bottom.
- Width collapses to an icon rail below `850px`.

Content header requirements:

- Breadcrumb on the left.
- `New scan` action on the right.

- [ ] **Step 5: Implement accessible shared components**

`DonutChart` must expose an accessible label:

```tsx
<div
  role="img"
  aria-label={`${label}: ${segments.map(({ name, value }) => `${name} ${value}`).join(", ")}`}
/>
```

Every visual status must include text, not color alone.

- [ ] **Step 6: Verify navigation and shared UI**

Run:

```bash
npm test -- src/app/router.test.tsx src/components/layout/AppShell.test.tsx
npm run typecheck
npm run lint
```

Expected: all commands pass.

---

### Task 5: Secure mock scan setup flow

**Files:**
- Create: `frontend/src/features/scans/ScanSetupPage.tsx`
- Create: `frontend/src/features/scans/ScanSetupPage.test.tsx`
- Modify: `frontend/src/app/router.tsx`

**Interfaces:**
- Consumes: `useCreateScan`.
- Produces navigation to `/scans/{scanId}/overview`.

- [ ] **Step 1: Write scan-form behavior tests**

Cover:

```text
invalid URL -> inline URL error and no service call
empty actor field -> inline required error
valid URL and four credential fields -> one service call
successful submit -> fields cleared and navigation to overview
unmount -> no credential value survives outside component state
password inputs -> type=password and autocomplete=new-password
successful submit -> QueryClient mutation cache remains empty
```

- [ ] **Step 2: Verify the tests fail**

Run:

```bash
npm test -- src/features/scans/ScanSetupPage.test.tsx
```

- [ ] **Step 3: Implement the form**

Use a single `credentials` state value and clear it after the cache-free `createScan` call succeeds:

```tsx
const emptyCredentials = {
  userA: { username: "", password: "" },
  userB: { username: "", password: "" },
};

const handleSuccess = ({ scanId }: { scanId: string }) => {
  setCredentials(emptyCredentials);
  navigate(`/scans/${scanId}/overview`);
};
```

React discards the remaining component state on unmount. Do not copy credentials into context, query cache, service state, a form library, or a persistence plugin.

- [ ] **Step 4: Verify credential safety**

Run:

```bash
npm test -- src/features/scans/ScanSetupPage.test.tsx src/test/security.test.ts
rg -n "localStorage|sessionStorage|indexedDB|console\\.(log|debug).*password" src
```

Expected: tests pass; `rg` returns no credential persistence or logging usage.

---

### Task 6: Summary-first main dashboard and scan-progress detail

**Files:**
- Create: `frontend/src/features/overview/overview-selectors.ts`
- Create: `frontend/src/features/overview/OverviewPage.tsx`
- Create: `frontend/src/features/overview/overview-selectors.test.ts`
- Create: `frontend/src/features/overview/OverviewPage.test.tsx`
- Create: `frontend/src/features/scans/ScanProgressPage.tsx`
- Create: `frontend/src/features/scans/ScanProgressPage.test.tsx`

**Interfaces:**
- Produces: `countOperationsByMethod`, `countFindingsByType`, `selectRecentFindings`.
- Consumes: overview, scan progress, API graph, scan result, and AI Report queries.

- [ ] **Step 1: Write selector tests**

Assert:

```ts
expect(countOperationsByMethod(mockApiGraph)).toEqual({ GET: 24, POST: 4 });
expect(countFindingsByType(mockScanResult)).toEqual({
  BOLA: 2,
  DATA: 1,
  AUTH: 1,
});
expect(selectRecentFindings(mockScanResult, 3)).toHaveLength(3);
```

Adjust the fixture counts so the fixture and expectations agree exactly.

- [ ] **Step 2: Verify selector tests fail, then implement selectors**

Run before and after implementation:

```bash
npm test -- src/features/overview/overview-selectors.test.ts
```

- [ ] **Step 3: Write dashboard interaction tests**

Assert cards and rows navigate:

```text
Scan progress card -> /scans/scan-001/progress
Scan pipeline panel -> /scans/scan-001/progress
Discovered APIs card -> /scans/scan-001/apis
API discovery panel -> /scans/scan-001/apis
Verified findings card -> /scans/scan-001/findings
Finding breakdown panel -> /scans/scan-001/findings
AI Report card -> /scans/scan-001/ai-report
AI Report summary panel -> /scans/scan-001/ai-report
recent Finding row -> /scans/scan-001/findings/{findingId}
```

Also assert the main dashboard contains no raw Evidence response block, every interactive card or panel has a non-empty destination, and no link uses `href="#"`.

- [ ] **Step 4: Implement the approved dashboard**

Include:

- Four metric cards.
- API Method distribution donut.
- Compact scan pipeline.
- Finding-type donut.
- Three recent Finding rows.
- AI Report status summary.

- [ ] **Step 5: Write and implement scan-progress detail tests**

Assert:

```text
page displays overall percentage and current stage
all five stages render in order
each stage renders label, description, and text status
completed, running, waiting, and failed states are not conveyed by color alone
loading, error, and success states render deliberately
breadcrumb and Back to overview actions return to /scans/{scanId}/overview
```

Implement `ScanProgressPage` at `/scans/:scanId/progress`. This page presents mock-only operational status and must not be described as a finalized backend response contract.

- [ ] **Step 6: Test async states**

Render with deferred and rejecting service promises and assert:

```text
loading -> skeletons with accessible labels
error -> retry action
empty findings -> “확정된 Finding이 없습니다”
success -> metrics and navigation links
```

- [ ] **Step 7: Verify the dashboard and progress detail**

Run:

```bash
npm test -- src/features/overview src/features/scans/ScanProgressPage.test.tsx
npm run typecheck
npm run lint
```

---

### Task 7: API list, search, and contract-limited detail

**Files:**
- Create: `frontend/src/features/apis/api-selectors.ts`
- Create: `frontend/src/features/apis/ApiListPage.tsx`
- Create: `frontend/src/features/apis/ApiDetailPage.tsx`
- Create: `frontend/src/features/apis/api-selectors.test.ts`
- Create: `frontend/src/features/apis/ApiPages.test.tsx`

**Interfaces:**
- Produces: `filterOperations(operations, query)`.
- Consumes only `NormalizedApiGraph.operations`.

- [ ] **Step 1: Write API search tests**

Search must be case-insensitive across:

- HTTP method
- `path_template`
- input `field_path`
- output `field_path`

An empty query returns all operations without mutating the original array.

- [ ] **Step 2: Verify failure, implement selector, verify pass**

Run:

```bash
npm test -- src/features/apis/api-selectors.test.ts
```

- [ ] **Step 3: Write page tests**

Assert:

```text
list shows method and path
search narrows visible rows
row navigates with encoded operation_id
detail shows inputs and outputs
unknown operation shows a not-found state
detail does not show authentication, tokens, or raw responses
```

- [ ] **Step 4: Implement API pages**

Use a table on wide screens and stacked rows on narrow screens. Use plain contract fields only.

- [ ] **Step 5: Verify API pages**

Run:

```bash
npm test -- src/features/apis
npm run typecheck
npm run lint
```

---

### Task 8: Finding exploration and redacted Evidence detail

**Files:**
- Create: `frontend/src/features/findings/finding-selectors.ts`
- Create: `frontend/src/features/findings/FindingsPage.tsx`
- Create: `frontend/src/features/findings/FindingDetailPage.tsx`
- Create: `frontend/src/features/findings/finding-selectors.test.ts`
- Create: `frontend/src/features/findings/FindingPages.test.tsx`

**Interfaces:**
- Produces: `filterFindings(findings, { query, vulnerabilityType })`.
- Consumes: `ScanResult`, `RedactedEvidence`.

- [ ] **Step 1: Write Finding selector tests**

Test independent and combined filtering by:

- `vulnerability_type`
- `operation_id`
- `finding_id`
- affected `field_path`

- [ ] **Step 2: Verify failure, implement selector, verify pass**

Run:

```bash
npm test -- src/features/findings/finding-selectors.test.ts
```

- [ ] **Step 3: Write Finding page tests**

Assert:

```text
type donut contains an accessible textual breakdown
type filter and search can be combined
empty results retain the “not proof of safety” disclaimer
detail shows verification rule and verified conditions
detail shows affected fields
detail loads every evidence_ref through useEvidence
evidence text contains [REDACTED]
detail never renders a Bearer token
```

- [ ] **Step 4: Implement Finding pages**

Keep `verified` as informational text only. Do not add controls that alter verdict, severity, or evidence references.

- [ ] **Step 5: Verify Finding pages and security**

Run:

```bash
npm test -- src/features/findings src/test/security.test.ts
npm run typecheck
npm run lint
```

---

### Task 9: AI Report, mock preview, and valid mock PDF download

**Files:**
- Create: `frontend/src/features/reports/report-download.ts`
- Create: `frontend/src/features/reports/AiReportPage.tsx`
- Create: `frontend/src/features/reports/ReportPreviewPage.tsx`
- Create: `frontend/src/features/reports/ReportPages.test.tsx`
- Create: `frontend/src/services/mock/mock-pdf.ts`

**Interfaces:**
- Produces: `createMockReportPdf(report: AiReport): Blob`.
- Consumes: `AiReport`.

- [ ] **Step 1: Write report tests**

Assert:

```text
overall summary renders
each report Finding renders exactly once
attack_flow renders as ordered steps
preview route renders a print-friendly report
download Blob has type application/pdf
download bytes begin with %PDF
report never includes raw credentials, tokens, or unredacted object IDs
```

- [ ] **Step 2: Verify report tests fail**

Run:

```bash
npm test -- src/features/reports/ReportPages.test.tsx
```

- [ ] **Step 3: Implement report and preview pages**

Use only fields from `AiReport`. Join by `finding_id` only when displaying links back to Finding details.

- [ ] **Step 4: Implement valid client-side mock PDF generation**

Use jsPDF:

```ts
const document = new jsPDF();
document.text("VulnScope Security Report", 16, 20);
document.text(report.summary, 16, 32, { maxWidth: 175 });
return document.output("blob");
```

Normalize control characters before writing:

```ts
export function sanitizeReportText(value: string): string {
  return value.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, " ");
}
```

The download filename must be:

```text
vulnscope-{scan_id}-report.pdf
```

- [ ] **Step 5: Verify report behavior**

Run:

```bash
npm test -- src/features/reports
npm run typecheck
npm run lint
```

---

### Task 10: End-to-end flow, responsive layout, and accessibility

**Files:**
- Create: `frontend/e2e/mvp-flow.spec.ts`
- Create: `frontend/e2e/responsive-accessibility.spec.ts`
- Modify: `frontend/playwright.config.ts`
- Modify: UI files only when tests expose a defect.

**Interfaces:**
- Validates the complete application through the browser.

- [ ] **Step 1: Configure Playwright web server**

```ts
webServer: {
  command: "npm run dev -- --host 127.0.0.1",
  url: "http://127.0.0.1:4173",
  reuseExistingServer: false,
},
use: {
  baseURL: "http://127.0.0.1:4173",
  trace: "retain-on-failure",
  screenshot: "only-on-failure",
},
```

Configure Vite with:

```ts
server: {
  host: "127.0.0.1",
  port: 4173,
  strictPort: true,
},
```

- [ ] **Step 2: Write the full MVP flow**

The test must:

```text
open /scans/new
fill URL and four actor fields
start mock scan
arrive at overview
click Scan progress card and verify scan-progress detail
return to overview and click Scan pipeline panel
verify the same scan-progress detail destination
return to overview and click Discovered APIs metric
verify the API list destination
search for accounts
open API detail
return to overview and click API discovery panel
verify the API list destination
return to overview and click Verified findings metric
open Findings from the sidebar
filter BOLA
open a Finding detail
verify redacted Evidence
return to overview and click Finding breakdown panel
verify the Finding list destination
return to overview and click the AI Report metric
open AI Report from the sidebar
open report preview
trigger PDF download and verify .pdf filename
```

Add a separate dashboard-link audit:

```ts
const links = page.locator("main a");
for (let index = 0; index < await links.count(); index += 1) {
  const href = await links.nth(index).getAttribute("href");
  expect(href).toBeTruthy();
  expect(href).not.toBe("#");
}
```

Visit each dashboard link and assert it renders a page heading and does not produce a blank page or uncaught console error.

- [ ] **Step 3: Write responsive and accessibility checks**

Run the overview, API list, Finding list, and AI Report at:

```text
Desktop: 1440 × 900
Mobile: 390 × 844
```

For each page:

- Assert `document.documentElement.scrollWidth <= window.innerWidth`.
- Run `new AxeBuilder({ page }).analyze()`.
- Assert zero `critical` or `serious` violations.
- Assert sidebar labels collapse on mobile while links remain accessible by name.

- [ ] **Step 4: Run E2E tests and fix failures**

Run:

```bash
npm run test:e2e
```

Expected: all flows pass in Chromium with no console errors.

---

### Task 11: Final clean-install verification and completion audit

**Files:**
- Modify only files required to fix a failing gate.
- Do not modify unrelated repository files.

**Interfaces:**
- Produces the final verified frontend artifact in `frontend/dist/`.

- [ ] **Step 1: Record the pre-verification repository state**

Run from repository root:

```bash
git status --short --branch
git diff -- .gitignore
```

Expected: preserve the pre-existing `.gitignore` modification and unrelated untracked documents.

- [ ] **Step 2: Perform a clean dependency install**

From `frontend/`:

```bash
repo_root="$(git rev-parse --show-toplevel)"
test "$(realpath "$PWD")" = "$repo_root/frontend"
node_modules_dir="$(realpath -m "$PWD/node_modules")"
test "$node_modules_dir" = "$repo_root/frontend/node_modules"
if [ -e "$node_modules_dir" ]; then
  rm -rf -- "$node_modules_dir"
fi
npm ci
```

Before removal, resolve and compare the absolute path to exactly `$repo_root/frontend/node_modules`. Do not remove any other directory.

- [ ] **Step 3: Run all mandatory quality gates**

```bash
npm run typecheck
npm run lint
npm test
npm run test:coverage
npm run test:e2e
npm run build
```

Expected: every command exits `0`; coverage meets the configured thresholds; `frontend/dist/index.html` exists.

- [ ] **Step 4: Run static security and contract scans**

From `frontend/`:

```bash
rg -n -i "Bearer [A-Za-z0-9._-]+|sk-[A-Za-z0-9]{12,}|eyJ[A-Za-z0-9_-]{10,}\\." src e2e
rg -n "localStorage|sessionStorage|indexedDB" src
rg -n "security|raw_response|access_token|refresh_token" src/contracts
```

Expected:

- No secret-shaped values.
- No credential persistence.
- No contract fields invented beyond the finalized JSON contract.

- [ ] **Step 5: Audit route and feature coverage**

Manually verify these URLs return a deliberate page rather than a blank screen:

```text
/scans/new
/scans/scan-001/overview
/scans/scan-001/progress
/scans/scan-001/apis
/scans/scan-001/apis/{encodedOperationId}
/scans/scan-001/findings
/scans/scan-001/findings/finding-001
/scans/scan-001/ai-report
/scans/scan-001/ai-report/preview
```

- [ ] **Step 6: Review the final diff**

Run:

```bash
git status --short
git diff --stat
git diff --check
```

Confirm:

- All implementation files are under `frontend/`.
- Only the approved design and plan files were added under `docs/superpowers/`.
- `.gitignore` remains the user’s change.
- No generated `node_modules/`, `dist/`, Playwright reports, coverage reports, or secrets are included in the intended source set.

- [ ] **Step 7: Fix any finding and rerun affected gates**

Completion is forbidden while any test, lint, typecheck, build, E2E, coverage, security, or responsive-accessibility check is failing.

## Final Success Criteria

Development is complete only when all criteria below are true:

### Functional completion

- [ ] A user can enter a target URL and User A/B credentials in the mock scan form.
- [ ] Invalid or incomplete input produces accessible inline errors.
- [ ] Successful mock submission clears credentials and navigates to the scan overview.
- [ ] The approved left sidebar works on every major page.
- [ ] The overview summarizes progress, API counts, Finding counts, Finding types, and AI Report state.
- [ ] The scan-progress card and Scan Pipeline panel both navigate to the scan-progress detail page.
- [ ] The scan-progress detail page shows the overall percentage and all five stages with label, description, and text status.
- [ ] API metric and discovery summary navigate to the API list, where every API row navigates to API detail.
- [ ] Finding metric and breakdown summary navigate to the Finding list, where every Finding row navigates to Finding detail.
- [ ] AI Report metric and summary navigate to the AI Report detail and report preview.
- [ ] Every clickable overview card, chart summary, panel, and row has a real destination; no empty handler or `href="#"` remains.
- [ ] API search and API detail work using finalized graph fields only.
- [ ] Finding search, type filtering, detail, and redacted Evidence display work.
- [ ] AI Report, print-friendly preview, and valid `.pdf` mock download work.
- [ ] Loading, Empty, Error, and Success states are implemented for all query-backed pages.

### Contract and security completion

- [ ] All six finalized JSON structures have exact TypeScript representations.
- [ ] Contract fixtures use `satisfies` and pass TypeScript validation.
- [ ] No production API shape is invented.
- [ ] No actual credentials, tokens, object IDs, or raw Evidence are present.
- [ ] Submitted credentials are not retained after mock scan creation.
- [ ] An empty `findings` array is described as no confirmed Finding, not proof of safety.
- [ ] AI Report UI cannot change Finding verification or classification.

### Visual and interaction completion

- [ ] UI matches the approved sidebar dashboard direction.
- [ ] API and Finding distributions use circular summaries with textual equivalents.
- [ ] Main dashboard contains summaries and navigation only; detailed analysis lives on detail pages.
- [ ] Scan progress, API, Finding, and AI Report each have a deliberate detailed destination reachable from the dashboard.
- [ ] Dashboard-link E2E audit visits every clickable summary and confirms a rendered destination with no uncaught console error.
- [ ] Desktop `1440×900` and mobile `390×844` layouts have no horizontal overflow.
- [ ] Keyboard navigation exposes every link, form control, filter, row action, preview action, and download action.
- [ ] axe-core reports zero critical or serious violations on the four major page types.

### Required verification completion

- [ ] `npm ci` succeeds from a clean `frontend/node_modules` state.
- [ ] `npm run typecheck` passes.
- [ ] `npm run lint` passes with zero warnings.
- [ ] `npm test` passes.
- [ ] `npm run test:coverage` passes with lines/functions/statements ≥80% and branches ≥70%.
- [ ] `npm run test:e2e` passes in Chromium.
- [ ] `npm run build` passes and produces `frontend/dist/index.html`.
- [ ] Static secret, persistence, and contract-drift scans pass.
- [ ] Final diff review shows no unrelated edits or generated artifacts intended for source control.

### Handoff completion

- [ ] Final report lists implemented features, changed files, and exact verification results.
- [ ] Mock-only boundaries and future backend replacement points are listed.
- [ ] Any environment limitation is reported as an incomplete gate, not hidden or described as success.
- [ ] No commit, push, branch, or PR action is performed without a separate explicit request.
