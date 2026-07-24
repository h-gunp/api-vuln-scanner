# 최종 JSON 데이터 계약

| JSON 계약 | 생산 → 소비 | 담당 | 핵심 내용 |
| --- | --- | --- | --- |
| `target_profile.json` | 백엔드 → 스캐너 | 백엔드 | 대상 URL, 허용 범위, 인증 계정 참조, Rate Limit, 스캔 정책 |
| `normalized_api_graph.json` | 스캐너 → LLM | 스캐너 | 크롤링 한거 정규화해서 json 형태로 LLM에 보내기 |
| `relationship_analysis.json` | LLM → 백엔드·스캐너 | LLM | API 간 객체 관계, 사용자·계좌·거래 데이터 흐름, 공격 후보 |
| `scan_plan.json` | LLM → 실행기 | LLM | 승인된 모듈로 만든 선언형 검사 계획, 모듈 실행 순서 |
| `scan_result.json` | 검증기 → 백엔드·LLM·프론트 | 스캐너 | 규칙 기반으로 확정된 finding |
| `ai_report.json` | LLM → 백엔드·프론트 | LLM | 확정 finding의 설명, 영향도, 대응책, 규제 매핑 |

## `target_profile.json`

```json
{
  "schema_version": "1.1",
  "scan_id": "<scan_id>",

  "target": {
    "base_url": "<base_url>",
    "allowed_paths": ["<path_pattern>"],
    "allowed_methods": ["GET"]
  },

  "discovery": {
    "sources": ["openapi", "crawl"],
    "max_depth": 3
  },

  "authentication": {
    "login": {
      "method": "POST",
      "path": "/api/login",
      "content_type": "application/json",
      "username_field": "username",
      "password_field": "password",
      "session": {
        "type": "bearer",
        "token_field": "token"
      }
    },

    "actors": [
      {
        "actor_id": "user_a",
        "username_env": "<USER_A_USERNAME_ENV>",
        "password_env": "<USER_A_PASSWORD_ENV>"
      },
      {
        "actor_id": "user_b",
        "username_env": "<USER_B_USERNAME_ENV>",
        "password_env": "<USER_B_PASSWORD_ENV>"
      }
    ]
  },

  "safety_policy": {
    "max_requests": 300,
    "requests_per_second": 3,
    "state_change_policy": "deny",
    "approved_modules": [
      "authz",
      "input_validation",
      "data_exposure"
    ]
  }
}
```

| 필드 | 의미 |
| --- | --- |
| `schema_version` | 이 설정 파일 형식의 버전 |
| `scan_id` | 이번 스캔을 식별하는 ID. 후속 결과 파일들과 연결 |
| `target.base_url` | 검사 대상의 기준 URL |
| `allowed_paths` | 정규화·모듈 검사 대상으로 허용할 API 경로 범위 |
| `allowed_methods` | 로그인 외에 능동 검사에 사용할 HTTP 메서드. 현재는 `GET`만 허용 |
| `discovery.sources` | API 구조를 찾는 방법. OpenAPI 명세와 크롤링 결과를 함께 사용 |
| `discovery.max_depth` | 크롤링 링크를 따라갈 최대 깊이 |
| `authentication.login` | A/B 계정으로 로그인하기 위한 요청 형식 |
| `login.method`, `login.path` | 로그인 요청의 HTTP 메서드와 경로 |
| `username_field`, `password_field` | 로그인 JSON 본문에서 아이디·비밀번호를 담는 키 이름 |
| `session.type` | 로그인 후 얻는 인증 세션 유형. `bearer`면 JWT Bearer 토큰 |
| `session.token_field` | 로그인 응답 JSON에서 토큰을 꺼낼 필드 |
| `actors` | BOLA 등 권한 비교에 사용할 두 독립 사용자 |
| `actor_id` | 코드에서 사용하는 사용자 식별자 |
| `username_env`, `password_env` | 실제 자격증명이 들어 있는 런타임 환경변수 이름. JSON에 비밀번호를 저장하지 않음 |
| `max_requests` | 로그인·크롤링·모듈 실행을 모두 합친 전체 요청 상한 |
| `requests_per_second` | 모든 요청을 합친 초당 요청 상한 |
| `state_change_policy: "deny"` | 로그인 외에 송금·수정·삭제처럼 상태를 바꾸는 요청은 실행 금지 |
| `approved_modules` | 실행을 허용한 검사 모듈 목록 |

## `normalized_api_graph.json`

```json
{
  "schema_version": "1.1",
  "scan_id": "<scan_id>",
  "operations": [
    {
      "operation_id": "<HTTP_METHOD>:<path_template>",
      "method": "<HTTP_METHOD>",
      "path_template": "<path_template>",

      "inputs": [
        {
          "location": "<path|query|header|body>",
          "field_path": "<input_field_path>",
          "type": "<string|integer|number|boolean|object|array|unknown>"
        }
      ],

      "outputs": [
        {
          "field_path": "<response_json_path>",
          "type": "<string|integer|number|boolean|object|array|unknown>"
        }
      ]
    }
  ]
}
```

## `relationship_analysis.json`

```json
{
  "schema_version": "1.2",
  "scan_id": "scan-001",
  "model_name": "gpt-4o-mini-2024-07-18",
  "prompt_version": "rel-v2",
  "prompt_sha256": "0758c15af1d9643432543c725ccdc2fab30e75adc1a420d04ac78cc40a0b28a5",
  "approved_module_ids": ["BOLA-001", "AUTHN-001", "INPUT-001", "DATA-001"],
  "relationships": [
    {
      "relationship_id": "rel-001",
      "source_operation_id": "GET:/api/accounts",
      "target_operation_id": "GET:/api/accounts/{account_id}",
      "source_field": "items[].account_id",
      "target_parameter": "account_id",
      "target_parameter_location": "path",
      "relationship_type": "id_flow",
      "confidence": 0.96
    }
  ],
  "test_candidates": [
    {
      "candidate_id": "candidate-001",
      "module_id": "BOLA-001",
      "target_operation_id": "GET:/api/accounts/{account_id}",
      "required_object_types": ["account"],
      "rationale": "인증된 객체 식별자 입력과 상위 응답의 ID/소유 관계가 확인됨",
      "priority": 1,
      "executable": true,
      "missing_requirements": [],
      "binding_hints": [
        {
          "parameter": "account_id",
          "location": "path",
          "binding_type": "object_binding",
          "object_type": "account"
        }
      ]
    }
  ]
}
```

## `scan_plan.json`

```json
{
  "schema_version": "1.2",
  "plan_id": "d4904c98-0092-5002-9d01-c2031404ce92",
  "scan_id": "scan-001",
  "model_name": "gpt-4o-mini-2024-07-18",
  "prompt_version": "plan-v2",
  "prompt_sha256": "5a3b33a80b61ca39363917775882aa969ae6c348669c9b094cf7600bd4545b72",
  "status": "PENDING_APPROVAL",
  "budget": {
    "requests_already_used": 12,
    "estimated_execution_requests": 4,
    "max_requests": 300,
    "within_budget": true
  },
  "steps": [
    {
      "order": 1,
      "candidate_id": "candidate-001",
      "module_id": "BOLA-001",
      "target_operation_id": "GET:/api/accounts/{account_id}",
      "target_endpoint": {
        "method": "GET",
        "path_template": "/api/accounts/{account_id}"
      },
      "input_bindings": [
        {
          "parameter": "account_id",
          "location": "path",
          "binding_type": "object_binding",
          "object_type": "account",
          "owner": "user_b"
        }
      ]
    }
  ]
}
```

요청 예산은 다음 조건을 만족해야 한다.

```
requests_used + estimated_execution_requests <= max_requests
```

## `scan_result.json`

```json
{
  "schema_version": "1.2",
  "scan_id": "<scan_id>",

  "findings": [
    {
      "finding_id": "<finding_id>",
      "operation_id": "<operation_id>",
      "vulnerability_type": "<vulnerability_type>",

      "verification": {
        "rule_id": "<rule_id>",
        "verified_conditions": [
          "<rule_condition_code>"
        ]
      },

      "affected_fields": [
        {
          "location": "<request|response>",
          "field_path": "<field_path>",
          "data_class": "<identity|account|financial|authentication|transaction|other>"
        }
      ],

      "evidence_refs": [
        "<redacted_evidence_artifact_reference>"
      ]
    }
  ]
}
```

| 필드 | 의미 |
| --- | --- |
| `schema_version` | `scan_result.json` 형식 버전 |
| `scan_id` | 이번 결과를 그래프, 스캔 작업, AI 보고서와 연결하는 식별자 |
| `findings` | 검증 완료된 취약점 목록. 없으면 빈 배열 `[]` |
| `finding_id` | 취약점 한 건의 고유 ID. 대시보드 상세 화면과 `ai_report.json` 조인 기준 |
| `operation_id` | 취약점이 확인된 API 작업 ID. `normalized_api_graph.json.operations[].operation_id`와 정확히 일치해야 함 |
| `vulnerability_type` | 확정된 취약점 유형. 프로젝트에서 정한 고정 enum만 사용 |
| `verification` | 취약점이 확정된 규칙 근거 |
| `verification.rule_id` | 적용되어 통과한 검증 규칙의 전역 고유 ID |
| `verification.verified_conditions` | 해당 규칙에서 실제로 충족된 조건 코드 목록. 자유 문장이 아니라 규칙 명세에 정의된 고정 코드여야 함 |
| `affected_fields` | 실제로 노출·변조·접근 우회가 확인된 필드 목록 |
| `affected_fields.location` | 영향받은 필드의 위치. 요청값이면 `request`, 서버 응답에서 노출된 값이면 `response` |
| `affected_fields.field_path` | 해당 위치 내부의 필드 경로 |
| `affected_fields.data_class` | 필드의 업무상 데이터 분류. LLM이 영향도·심각도를 판단하는 직접 근거 |
| `evidence_refs` | 마스킹된 요청·응답 비교, 실행 결과 등 검증 증거 artifact의 참조값 |

## `ai_report.json`

```json
{
  "schema_version": "1.2",
  "scan_id": "scan-001",
  "model_name": "gpt-4o-mini-2024-07-18",
  "prompt_version": "report-v2",
  "prompt_sha256": "81e976544eaac9bd46e4169c13d4dfad6494a67c09b9d5102063a1086503854e",
  "overall_risk": "high",
  "overall_risk_basis": "rule:max_verified_severity",
  "summary": "검증된 객체 수준 인가 실패 1건이 확인되었습니다.",
  "findings": [
    {
      "finding_id": "finding-001",
      "analysis_id": "5f6ce4d9-4a43-5635-9b5e-8289716b190a",
      "root_cause": "객체 조회에서 인증 주체와 객체 소유자의 일치 검증이 작동하지 않았습니다.",
      "attack_flow": ["사용자 A 로그인", "사용자 B 소유 객체 참조", "민감 응답 확인"],
      "impact": "다른 사용자의 계좌 식별자와 잔액 정보에 접근할 수 있습니다.",
      "recommendation": "모든 객체 조회에서 서버 측 소유권 검증을 적용합니다.",
      "severity": "high",
      "evidence_refs": ["evidence:redacted:001", "evidence:redacted:002"]
    }
  ]
}
```