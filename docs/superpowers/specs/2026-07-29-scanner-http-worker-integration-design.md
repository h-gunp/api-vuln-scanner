# Scanner HTTP Worker Integration Design

- 작성일: 2026-07-29
- 대상 브랜치: `feature/scanner`
- 상태: 사용자 승인
- 기준 문서: `docs/최종 JSON 데이터 계약.md` (수정 금지)

## 1. 목표

기존 Scanner를 API 수집과 모듈 실행·룰 검증을 모두 담당하는 단일 워커로
고정한다. 별도 Executor 서비스를 만들지 않고, 백엔드가 생성한 작업을
FastAPI 내부 HTTP 진입점으로 받아 기존 `Scanner.run_discovery()` 또는
`Scanner.run_execution()`을 Background task에서 실행한다.

이 변경은 Scanner와 백엔드 사이의 HTTP 경계, 감사 가능한 Evidence,
계약 검증과 루트 패키징만 다룬다. 백엔드·LLM·프론트엔드·DB·큐·보고서
기능은 구현하지 않는다.

## 2. 확정된 책임

- Scanner는 Discovery와 Executor/Verifier를 하나의 프로세스에서 수행한다.
- `scan_plan.status`는 `PENDING_APPROVAL` 상태 그대로 입력받는다.
- Scanner 내부 Executor가 정책을 검증하고 승인 또는 거부를 결정한다.
- 실행 가능한 Module ID는 `BOLA-001`, `INPUT-001`, `DATA-001`뿐이다.
- `AUTHN-001`은 분석 후보나 계획 단계에서부터 허용하지 않는다.
- 실제 자격증명, 토큰, 쿠키, 객체 ID와 응답 값은 런타임 메모리에만 둔다.

## 3. HTTP 작업 진입점

`scanner/api.py`는 주입 가능한 `create_app()`과 Uvicorn이 읽을 기본 `app`을
제공한다.

### `POST /jobs/discovery`

- 상태 코드: `202 Accepted`
- 입력: `DiscoveryJobRequest`
- `target_profile`은 현재 `ContractSource` 형식을 사용한다.
- Background task에서 `Scanner.run_discovery(request)`를 실행한다.
- 응답:

```json
{
  "job_id": "backend-generated-job-id",
  "accepted": true
}
```

### `POST /jobs/execution`

- 상태 코드: `202 Accepted`
- 입력: `ExecutionJobRequest`
- `target_profile`, `normalized_api_graph`, `relationship_analysis`,
  `scan_plan`은 모두 현재 `ContractSource` 형식을 사용한다.
- Background task에서 `Scanner.run_execution(request)`을 실행한다.
- 응답은 Discovery와 동일하다.

### 멱등성과 동시성

- 백엔드가 보낸 `job_id`는 수정하거나 다시 생성하지 않는다.
- 프로세스 수명 동안 처리한 모든 `job_id`를 원자적 인메모리 레지스트리에
  보존한다.
- 같은 `job_id`가 다시 들어오면 `202`를 반환하되 Background task를 다시
  등록하지 않는다.
- 같은 `scan_id`의 작업은 scan별 잠금으로 직렬화한다.
- 다른 `scan_id` 작업은 서로 병렬 실행할 수 있다.
- 예상하지 못한 Background task 예외는 비밀값 없는 고정 오류 callback으로
  보고한다. Scanner가 이미 보고한 도메인 실패는 중복 보고하지 않는다.

## 4. BackendClient 설계

`BackendClient`의 작업 관련 메서드는 숨은 전역 상태를 사용하지 않고
`job_id`, `scan_id`, 작업 종류를 명시적으로 전달한다. 이 방식은 여러
Background task가 동시에 실행되어도 callback 대상이 섞이지 않게 한다.

`HttpBackendClient` 설정:

- `BACKEND_BASE_URL`
- `INTERNAL_AUTH_ENABLED`
- `INTERNAL_SERVICE_TOKEN`
- `BACKEND_TIMEOUT_SECONDS`

내부 인증이 활성화되면 모든 요청에
`Authorization: Bearer <INTERNAL_SERVICE_TOKEN>`을 추가한다. 활성화됐지만
토큰이 없으면 시작 시 설정 오류로 거부한다.

HTTP 오류, 잘못된 응답과 연결 실패는 응답 본문이나 URL query를 예외에
포함하지 않는 고정형 통합 오류로 변환한다.

### Callback 경로와 본문

| 이벤트 | 경로 | 본문 |
| --- | --- | --- |
| Discovery progress | `/internal/scans/{scan_id}/progress` | `stage`, `progress`, `message`, `metrics` |
| Execution progress | `/internal/scans/{scan_id}/execution-progress` | `stage`, `progress`, `message`, `metrics` |
| Normalized graph | `/internal/scans/{scan_id}/normalized-api-graph` | `normalized_api_graph.json` 본문 |
| Scan result | `/internal/scans/{scan_id}/scan-result` | `scan_result.json` 본문 |
| Evidence | `/internal/scans/{scan_id}/evidence` | `EvidenceArtifact` 본문 |
| Plan decision | `/internal/scans/{scan_id}/plan-approval` | `job_id`, `plan_id`, `status`, `reason_codes` |
| Failure | `/internal/scans/{scan_id}/failed` | `source`, 변환된 `stage`, 안전한 `error` |

Graph, result와 Evidence callback 응답의 `details.artifact_id`를
`artifact:<artifact_id>` 형태의 불투명 참조로 정규화한다. Evidence에서 얻은
참조는 해당 Finding의 `evidence_refs`에 넣는다.

`ContractSource.artifact_ref`를 읽을 때는 백엔드가 전달한 동일 출처의
상대 경로만 허용한다. 절대 외부 URL이나 다른 origin은 거부한다.

## 5. Stage 변환

Scanner 내부 단계는 작업 종류에 따라 백엔드 단계로 변환한다.

### Discovery

| Scanner | Backend |
| --- | --- |
| `PROFILE_LOADING` | `API_DISCOVERY` |
| `AUTHENTICATING` | `API_DISCOVERY` |
| `DISCOVERING` | `API_DISCOVERY` |
| `OBJECT_DISCOVERY` | `API_DISCOVERY` |
| `NORMALIZING` | `API_NORMALIZATION` |
| `COMPLETED` | `API_NORMALIZATION` |

### Execution

| Scanner | Backend |
| --- | --- |
| `PROFILE_LOADING` | `PLAN_VALIDATION` |
| `AUTHENTICATING` | `PLAN_VALIDATION` |
| `POLICY_VALIDATION` | `PLAN_VALIDATION` |
| `EXECUTING` | `MODULE_EXECUTION` |
| `VERIFYING` | `RESULT_VALIDATION` |
| `COMPLETED` | `RESULT_VALIDATION` |

백엔드의 현재 progress 계약은 최대 99이므로 Scanner의 완료 진행률 100은
callback 경계에서 99로 제한한다. 실제 단계 완료는 Graph 또는 Scan Result
산출물 callback이 확정한다.

## 6. 감사 가능한 Evidence

비정형 Evidence를 일반 Redactor에 통과시킨 뒤 모든 문자열 키와 값을 지우는
기존 방식은 사용하지 않는다. 외부 저장 형태를 allowlist Pydantic 모델로
고정한다.

```text
EvidenceArtifact
├─ scan_id
├─ operation_id
├─ module_id
├─ rule_id
├─ verified_conditions[]
├─ affected_fields[]
├─ baseline
│  ├─ actor_id
│  ├─ status_code
│  ├─ response_structure_sha256?
│  └─ observed_field_paths[]
└─ variant
   ├─ actor_id
   ├─ status_code
   ├─ response_structure_sha256?
   └─ observed_field_paths[]
```

- `actor_id`는 `user_a` 또는 `user_b`만 허용한다.
- 관측값에는 구조 해시 또는 관측 필드 경로가 최소 하나 있어야 한다.
- status code는 HTTP 범위만 허용한다.
- field path는 구조 이름만 허용하며 concrete 값과 URL query를 거부한다.
- 토큰, 쿠키, 비밀번호, 실제 객체 ID, 실제 응답 값과 concrete URL을 담는
  필드는 모델에 존재하지 않는다.
- 직렬화 전에 런타임 민감값과 정확 일치 또는 부분 포함 여부를 다시 검사한다.
- Finding의 rule, verified condition, affected field와 status를 Evidence
  참조 하나만으로 재검증할 수 있어야 한다.

## 7. 계약 검증

- `Operation.operation_id`는 정규화된
  `f"{method}:{path_template}"`와 정확히 같아야 한다.
- `NormalizedApiGraph.operations` 안의 operation ID는 중복될 수 없다.
- `Relationship.relationship_type`은
  `id_flow|ownership|call_order|data_flow`만 허용한다.
- `object_binding`에는 `object_type`과 `owner`가 모두 필수다.
- `parameter_binding`에서는 `object_type`과 `owner`가 모두 `null`이어야 한다.
- Relationship Analysis 후보와 Scan Plan step의 module ID는
  `BOLA-001|INPUT-001|DATA-001`만 허용한다.
- 기존 `scan_plan.status=PENDING_APPROVAL` 계약은 변경하지 않는다.
- `docs/최종 JSON 데이터 계약.md`의 예시는 Scanner 모델 계약 테스트로
  읽어 검증하되 원본 문서는 수정하지 않는다.

## 8. 패키징

루트 `pyproject.toml`은 고정 패키지 목록 대신 setuptools package discovery를
사용한다.

```toml
[tool.setuptools.packages.find]
include = ["scanner*"]
```

런타임 의존성은 `fastapi`, `uvicorn`, `httpx`, `pydantic`을 선언하고 개발
extra에는 `pytest`를 둔다. 이후 #2가 rebase하여 discovery include에
`llm*`를 추가하고 `openai`를 의존성에 더할 수 있는 구조를 유지한다.

## 9. 테스트 전략

모든 동작 변경은 Red-Green-Refactor 순서로 구현한다.

- 두 job endpoint의 `202`, 입력 검증, `job_id` 보존과 멱등 테스트
- Background task 성공과 예상·예상 밖 실패 callback 테스트
- `httpx.MockTransport` 기반 모든 callback 경로·본문·Bearer 인증 테스트
- Discovery/Execution stage 변환과 progress 상한 테스트
- 최종 JSON 계약 예시 파싱 테스트
- operation ID, 중복, relationship와 binding 교차 검증 테스트
- `AUTHN-001` 후보·계획 거부 테스트
- Evidence 의미 보존과 비밀값·응답값·query 미저장 테스트
- 기존 전체 회귀 테스트
- `python -m compileall -q scanner tests`

완료 시 전체 테스트와 compileall의 실제 출력으로만 완료를 판정한다.
