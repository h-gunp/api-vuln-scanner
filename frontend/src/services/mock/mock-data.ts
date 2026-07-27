import type {
  AiReport,
  NormalizedApiGraph,
  RelationshipAnalysis,
  ScanPlan,
  ScanResult,
  TargetProfile,
} from "../../contracts";

export const mockTargetProfile = {
  schema_version: "1.1",
  scan_id: "scan-001",
  target: {
    base_url: "https://staging.example.test",
    allowed_paths: ["/api/**"],
    allowed_methods: ["GET"],
  },
  discovery: { sources: ["openapi", "crawl"], max_depth: 3 },
  authentication: {
    login: {
      method: "POST",
      path: "/api/login",
      content_type: "application/json",
      username_field: "username",
      password_field: "password",
      session: { type: "bearer", token_field: "token" },
    },
    actors: [
      {
        actor_id: "user_a",
        username_env: "<USER_A_USERNAME_ENV>",
        password_env: "<USER_A_PASSWORD_ENV>",
      },
      {
        actor_id: "user_b",
        username_env: "<USER_B_USERNAME_ENV>",
        password_env: "<USER_B_PASSWORD_ENV>",
      },
    ],
  },
  safety_policy: {
    max_requests: 300,
    requests_per_second: 3,
    state_change_policy: "deny",
    approved_modules: ["authz", "input_validation", "data_exposure"],
  },
} satisfies TargetProfile;

const namedOperations = [
  {
    operation_id: "GET:/api/accounts",
    method: "GET",
    path_template: "/api/accounts",
    inputs: [],
    outputs: [{ field_path: "items[].account_id", type: "string" as const }],
  },
  {
    operation_id: "GET:/api/accounts/{account_id}",
    method: "GET",
    path_template: "/api/accounts/{account_id}",
    inputs: [
      {
        location: "path" as const,
        field_path: "account_id",
        type: "string" as const,
      },
    ],
    outputs: [
      { field_path: "account_id", type: "string" as const },
      { field_path: "balance", type: "number" as const },
    ],
  },
  {
    operation_id: "GET:/api/customers/{customer_id}",
    method: "GET",
    path_template: "/api/customers/{customer_id}",
    inputs: [
      {
        location: "path" as const,
        field_path: "customer_id",
        type: "string" as const,
      },
    ],
    outputs: [{ field_path: "email", type: "string" as const }],
  },
  {
    operation_id: "GET:/api/profile",
    method: "GET",
    path_template: "/api/profile",
    inputs: [
      {
        location: "header" as const,
        field_path: "session",
        type: "string" as const,
      },
    ],
    outputs: [{ field_path: "profile_id", type: "string" as const }],
  },
];
const generatedGetOperations = Array.from({ length: 20 }, (_, index) => ({
  operation_id: `GET:/api/resources/${index + 1}`,
  method: "GET",
  path_template: `/api/resources/${index + 1}`,
  inputs: [],
  outputs: [{ field_path: "data", type: "object" as const }],
}));
const generatedPostOperations = Array.from({ length: 4 }, (_, index) => ({
  operation_id: `POST:/api/search/${index + 1}`,
  method: "POST",
  path_template: `/api/search/${index + 1}`,
  inputs: [
    { location: "body" as const, field_path: "query", type: "string" as const },
  ],
  outputs: [{ field_path: "items", type: "array" as const }],
}));

export const mockApiGraph = {
  schema_version: "1.1",
  scan_id: "scan-001",
  operations: [
    ...namedOperations,
    ...generatedGetOperations,
    ...generatedPostOperations,
  ],
} satisfies NormalizedApiGraph;

export const mockRelationshipAnalysis = {
  schema_version: "1.2",
  scan_id: "scan-001",
  model_name: "mock-model",
  prompt_version: "rel-v2",
  prompt_sha256:
    "0758c15af1d9643432543c725ccdc2fab30e75adc1a420d04ac78cc40a0b28a5",
  approved_module_ids: ["BOLA-001", "AUTHN-001", "DATA-001"],
  relationships: [
    {
      relationship_id: "rel-001",
      source_operation_id: "GET:/api/accounts",
      target_operation_id: "GET:/api/accounts/{account_id}",
      source_field: "items[].account_id",
      target_parameter: "account_id",
      target_parameter_location: "path",
      relationship_type: "id_flow",
      confidence: 0.96,
    },
  ],
  test_candidates: [
    {
      candidate_id: "candidate-001",
      module_id: "BOLA-001",
      target_operation_id: "GET:/api/accounts/{account_id}",
      required_object_types: ["account"],
      rationale: "객체 식별자와 소유 관계가 확인됨",
      priority: 1,
      executable: true,
      missing_requirements: [],
      binding_hints: [
        {
          parameter: "account_id",
          location: "path",
          binding_type: "object_binding",
          object_type: "account",
        },
      ],
    },
  ],
} satisfies RelationshipAnalysis;

export const mockScanPlan = {
  schema_version: "1.2",
  plan_id: "plan-redacted-001",
  scan_id: "scan-001",
  model_name: "mock-model",
  prompt_version: "plan-v2",
  prompt_sha256:
    "5a3b33a80b61ca39363917775882aa969ae6c348669c9b094cf7600bd4545b72",
  status: "PENDING_APPROVAL",
  budget: {
    requests_already_used: 12,
    estimated_execution_requests: 4,
    max_requests: 300,
    within_budget: true,
  },
  steps: [
    {
      order: 1,
      candidate_id: "candidate-001",
      module_id: "BOLA-001",
      target_operation_id: "GET:/api/accounts/{account_id}",
      target_endpoint: {
        method: "GET",
        path_template: "/api/accounts/{account_id}",
      },
      input_bindings: [
        {
          parameter: "account_id",
          location: "path",
          binding_type: "object_binding",
          object_type: "account",
          owner: "user_b",
        },
      ],
    },
  ],
} satisfies ScanPlan;

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
        {
          location: "response",
          field_path: "balance",
          data_class: "financial",
        },
      ],
      evidence_refs: ["evidence:redacted:001"],
    },
    {
      finding_id: "finding-002",
      operation_id: "GET:/api/accounts/{account_id}",
      vulnerability_type: "BOLA",
      verification: {
        rule_id: "BOLA-OWNER-CHECK-MISSING",
        verified_conditions: ["OWNER_MISMATCH_ACCEPTED"],
      },
      affected_fields: [
        {
          location: "response",
          field_path: "owner_id",
          data_class: "identity",
        },
      ],
      evidence_refs: ["evidence:redacted:002"],
    },
    {
      finding_id: "finding-003",
      operation_id: "GET:/api/customers/{customer_id}",
      vulnerability_type: "DATA",
      verification: {
        rule_id: "DATA-SENSITIVE-FIELD",
        verified_conditions: ["SENSITIVE_FIELD_EXPOSED"],
      },
      affected_fields: [
        { location: "response", field_path: "email", data_class: "identity" },
      ],
      evidence_refs: ["evidence:redacted:003"],
    },
    {
      finding_id: "finding-004",
      operation_id: "GET:/api/profile",
      vulnerability_type: "AUTH",
      verification: {
        rule_id: "AUTHN-SESSION-CHECK",
        verified_conditions: ["SESSION_CHECK_MISSING"],
      },
      affected_fields: [
        {
          location: "request",
          field_path: "session",
          data_class: "authentication",
        },
      ],
      evidence_refs: ["evidence:redacted:004"],
    },
  ],
} satisfies ScanResult;

export const mockAiReport = {
  schema_version: "1.2",
  scan_id: "scan-001",
  model_name: "mock-model",
  prompt_version: "report-v2",
  prompt_sha256:
    "81e976544eaac9bd46e4169c13d4dfad6494a67c09b9d5102063a1086503854e",
  overall_risk: "high",
  overall_risk_basis: "rule:max_verified_severity",
  summary:
    "검증된 API 취약점 4건이 확인되었습니다. 우선순위에 따라 대응하세요.",
  findings: mockScanResult.findings.map((finding, index) => ({
    finding_id: finding.finding_id,
    analysis_id: `analysis-redacted-${index + 1}`,
    root_cause: "서버 측 접근 통제 및 입력 검증이 충분하지 않습니다.",
    attack_flow: [
      "인증된 사용자 요청",
      "다른 객체 참조",
      "허용되지 않은 응답 확인",
    ],
    impact: "민감한 업무 데이터에 접근할 수 있습니다.",
    recommendation: "서버에서 객체 소유권과 권한을 매 요청마다 검증하세요.",
    severity: index < 2 ? "high" : "medium",
    evidence_refs: finding.evidence_refs,
  })),
} satisfies AiReport;

export const allMockFixtures = [
  mockTargetProfile,
  mockApiGraph,
  mockRelationshipAnalysis,
  mockScanPlan,
  mockScanResult,
  mockAiReport,
] as const;
