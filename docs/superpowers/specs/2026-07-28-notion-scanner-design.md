# Notion 정본 기반 API 취약점 스캐너 설계

- 작성일: 2026-07-28
- 대상 브랜치: `feature/scanner`
- 상태: 사용자 승인
- 대체 대상: `docs/superpowers/specs/2026-07-25-scanner-design.md`

## 1. 목표

백엔드가 전달한 `target_profile.json` v1.1을 기준으로 `vuln-bank`의 API를
수집·정규화하고, LLM이 생성한 관계 분석과 검사 계획을 Scanner Executor가
직접 정책 승인 또는 거부한 뒤 승인된 검사만 실행한다.

스캐너가 능동 실행하는 모듈은 다음 세 개뿐이다.

| 정책 승인값 | 실행 계획 Module ID | 구현 |
| --- | --- | --- |
| `authz` | `BOLA-001` | 실행 |
| `input_validation` | `INPUT-001` | 실행 |
| `data_exposure` | `DATA-001` | 실행 |
| 매핑 없음 | `AUTHN-001` | 실행 차단 |

거래 모듈은 현재 Target Profile과 JSON 계약에 없으므로 구현하지 않는다.

## 2. 정본과 책임 우선순위

이 설계는 Notion의 `명세서 모음` 아래 여섯 문서를 정본으로 사용한다.

1. 스캐너
2. JSON 계약
3. 백엔드
4. LLM 모듈
5. 전체 흐름
6. 프론트엔드

충돌이 발생하면 고정 JSON 필드 구조와 버전을 먼저 지키고, 그다음 최신의
구체적인 스캐너 책임 설명을 적용한다.

## 3. 범위

### 포함

- 백엔드 내부 Scanner Job 입력 처리
- Target Profile 또는 Artifact 참조 로드
- 계약 버전, `scan_id`, Scope와 안전 정책 검증
- 환경변수 기반 A/B 로그인과 독립 세션
- OpenAPI 우선, 인증 Katana 보완 수집
- `normalized_api_graph.json` v1.1 생성
- A/B 객체 ID와 관찰 입력 예시의 메모리 전용 관리
- 관계 분석과 검사 계획의 참조 무결성 검증
- Executor의 정책 승인·거부 결정
- BOLA, 비상태변경 입력 검증, 민감정보 노출 검사
- Executor 내부 고정 룰 판정
- Evidence 마스킹과 Artifact 메타데이터 생성
- `scan_result.json` v1.2 생성
- 진행률·통계·승인 결과·오류·취소의 백엔드 연동 포트

### 제외

- 백엔드 REST API, DB, 작업 큐와 Artifact 저장소
- LLM 호출, 프롬프트, 관계 분석과 계획 생성
- 프론트엔드와 공개 Scanner REST API
- AI·PDF 보고서
- `severity` 판정
- 별도 `verifier.py`
- 외부 `runtime_scan_context.json`
- 외부 `execution_evidence.json`
- `AUTHN-001` 능동 검사
- Transaction 검사

## 4. 패키지 구조

```text
scanner/
├─ auth/
│  └─ session_manager.py
├─ crawler/
│  ├─ katana_runner.py
│  └─ normalizer.py
├─ modules/
│  ├─ base.py
│  ├─ bola.py
│  ├─ input_validation.py
│  ├─ data_exposure.py
│  └─ auth.py
├─ integration/
│  └─ backend_client.py
├─ artifacts.py
├─ audit.py
├─ contracts.py
├─ http_client.py
├─ policy.py
├─ executor.py
└─ scanner.py
```

### 구성요소 책임

- `scanner.py`: Discovery Job과 Execution Job의 단계·진행률·취소 조정
- `executor.py`: 계획 전체 검증, 승인 결정, 모듈 실행, 고정 룰 판정, 결과 조립
- `policy.py`: origin, 경로, 메서드, 모듈, 요청 수, 속도와 상태 변경 검증
- `session_manager.py`: A/B 자격증명 해석, 로그인, 세션·객체·입력 예시 관리
- `katana_runner.py`: 인증 헤더를 파일로 주입한 범위 제한 Katana 실행
- `normalizer.py`: OpenAPI와 Katana 결과 병합 및 v1.1 그래프 생성
- `modules/*.py`: 모듈별 기준·변형 요청과 고정 판정 규칙
- `artifacts.py`: Evidence 마스킹, 직렬화, SHA-256과 크기 계산
- `backend_client.py`: 백엔드가 구현할 Scanner 연동 Protocol과 테스트용 Fake
- `contracts.py`: 외부 JSON과 내부 승인·Job 객체의 엄격한 Pydantic 모델
- `http_client.py`: 공통 정책을 통과한 HTTP 요청만 실행
- `audit.py`: `not_found`, `inconclusive`, 경고와 실패의 구조화 이벤트

`auth.py`는 `AUTHN-001`이 현재 정책에 매핑되지 않았음을 명시하고 네트워크 실행을
항상 차단한다. 인증 우회 공격 기능은 구현하지 않는다.

## 5. 계약

### 외부 JSON

| 계약 | 버전 | 스캐너 역할 |
| --- | --- | --- |
| `target_profile.json` | 1.1 | 소비 |
| `normalized_api_graph.json` | 1.1 | 생산 |
| `relationship_analysis.json` | 1.2 | 소비 |
| `scan_plan.json` | 1.2 | 소비 |
| `scan_result.json` | 1.2 | 생산 |
| `ai_report.json` | 1.2 | 사용하지 않음 |

모든 외부 계약 모델은 정의되지 않은 필드를 거부한다.

### Normalized API Graph

operation에는 다음 필드만 포함한다.

- `operation_id`
- `method`
- `path_template`
- `inputs[].location`
- `inputs[].field_path`
- `inputs[].type`
- `outputs[].field_path`
- `outputs[].type`

인증 메타데이터, required 여부, source, edge, confidence, 민감도, 실제 값은
그래프에 넣지 않는다. 실행에 필요한 required 여부와 관찰 예시는 직렬화하지
않는 Runtime Discovery Metadata로만 유지한다.

### Scan Result

`scan_result.json`에는 고정 룰로 확정된 Finding만 넣는다.

- `finding_id`
- `operation_id`
- `vulnerability_type`
- `verification.rule_id`
- `verification.verified_conditions`
- `affected_fields`
- `evidence_refs`

`verdict`와 `severity`를 추가하지 않는다. `findings: []`는 정상 결과다.

## 6. 공개 Python 경계

스캐너는 REST 서버를 제공하지 않는다. 상위 Worker가 호출할 Python 경계만
제공한다.

```python
discovery = scanner.run_discovery(job_request)

execution = scanner.run_execution(
    job_request=execution_request,
    relationship_analysis=relationship_analysis,
    scan_plan=scan_plan,
)
```

Discovery와 Execution 사이의 LLM 호출과 Artifact 전달은 백엔드가 조정한다.
스캐너는 LLM 구현을 직접 import하거나 호출하지 않는다.

## 7. BackendClient 경계

`BackendClient`는 다음 기능을 제공하는 Protocol이다.

- Target Profile Artifact 읽기
- Job의 기존 요청 사용량 읽기
- 진행 Stage·진행률·수집 통계 보고
- Executor 승인·거부 결과 보고
- Artifact 내용과 메타데이터 등록
- 고정 오류 코드와 `retryable` 보고
- 취소 요청 여부 확인

스캐너 저장소에는 Protocol과 Fake 구현만 둔다. 실제 URL, DB, 서비스 토큰 발급,
서명 검증, 재시도 스케줄링은 백엔드 담당이다.

## 8. Runtime Context

다음 값은 메모리에만 존재하며 Pydantic 외부 계약으로 직렬화하지 않는다.

- A/B 사용자명과 비밀번호
- Bearer 토큰과 쿠키
- actor별 계좌·거래·카드 객체 ID
- OpenAPI example/default
- Katana에서 관찰한 path/query 입력 예시
- 실제 요청 수

비밀 필드는 dataclass `repr=False`를 사용하고 로그·오류 변환 전에 공통
Redactor를 적용한다.

Execution 전에 프로세스가 재시작되어 Runtime Context가 없으면 백엔드의 누적
요청 수를 이어받아 다시 로그인하고 객체를 수집한다. 이 재수집으로 요청 수가
변하므로 기존 Plan은 `PLAN_REQUEST_COUNT_STALE`로 거부하고, 갱신된 요청 수로
새 Plan을 받아야 한다. 요청 예산을 0부터 다시 시작하지 않는다.

## 9. Discovery Job

1. 취소 여부를 확인한다.
2. inline Target Profile 또는 Artifact 참조를 로드한다.
3. v1.1, `scan_id`, origin, 경로, 인증 설정과 안전 정책을 검증한다.
4. `user_a`, `user_b` 환경변수를 읽고 로그인한다.
5. 허용된 표준 OpenAPI 경로를 우선 조회한다.
6. A/B 세션별 Katana를 실행한다.
7. OpenAPI와 Katana operation을 병합·중복 제거한다.
8. 허용 GET을 actor별로 호출해 출력 구조, 객체 ID와 입력 예시를 수집한다.
9. API 구조만 포함한 v1.1 그래프를 생성한다.
10. Artifact 체크섬·크기와 수집 통계를 백엔드 포트에 등록한다.
11. 다음 단계를 위한 Runtime Context를 메모리에 유지한다.

OpenAPI가 성공하고 Katana만 실패하면 경고 후 계속한다. 두 소스가 모두
실패하면 Discovery Job을 실패 처리한다.

## 10. Katana 안전 실행

Katana는 shell 없이 argv 배열로 실행한다.

- 동일 origin과 `allowed_paths`에서 생성한 crawl scope
- `-c 1`, `-p 1`
- Profile의 초당 요청 수를 `-rl`로 전달
- Katana에 할당한 남은 요청 수를 `-rlm`으로 전달
- 한 분 미만의 `-ct` 제한
- `-retry 0`
- `-jsonl`, `-omit-raw`, `-omit-body`

인증 헤더는 프로세스 argv에 직접 넣지 않고 임시 Header 파일로 전달한다.
파일은 실행 성공·실패·취소와 관계없이 삭제한다.

Katana 할당량은 실행 전에 전체 예산에서 예약하고, JSONL 요청 기록을 실제
요청 카운터에 반영한다. 안전하게 할당할 예산이 없으면 Katana를 실행하지 않고
OpenAPI 결과만 사용한다.

취소 요청이 들어오면 프로세스를 종료하고 새 HTTP 요청을 시작하지 않는다.

## 11. Executor 승인 결정

원본 `scan_plan.json.status=PENDING_APPROVAL`은 수정하지 않는다. Executor가
별도의 내부 결과를 만든다.

```text
PENDING_APPROVAL
      ↓
Executor Policy Validation
      ├─ APPROVED
      └─ REJECTED + reason_codes
```

`PlanApprovalDecision`은 다음 필드를 가진다.

- `scan_id`
- `plan_id`
- `status`: `APPROVED | REJECTED`
- `reason_codes`

Executor가 승인·거부의 최종 주체다. 결정은 BackendClient로 보고한다.

### 원자적 승인

한 Step이라도 참조 또는 정책을 위반하면 계획 전체를 거부하고 HTTP 요청을
하나도 보내지 않는다. 부분 승인·부분 실행은 하지 않는다.

`steps: []`는 승인 가능한 정상 계획이며 빈 Finding 결과를 만든다.

### 승인 조건

- Profile과 Graph는 v1.1
- Relationship과 Plan은 v1.2
- 모든 문서의 `scan_id` 일치
- Plan의 Step 순서가 1부터 연속되고 중복 없음
- Candidate가 관계 분석에 존재하고 `executable=true`
- Operation이 Graph에 존재
- Endpoint method/path가 Operation과 정확히 일치
- Binding이 Candidate hint 및 Operation input과 일치
- Profile 승인값과 Module ID 매핑이 정확함
- 모든 능동 요청이 허용된 GET
- 상태 변경 요청 없음
- Runtime 요청 수와 `requests_already_used` 일치
- `max_requests`가 Profile 값과 일치
- 예상 요청 수를 Executor가 다시 계산한 값과 일치
- `within_budget`가 계산식과 일치하고 true

요청 추정치는 다음과 같다.

| Module ID | Step당 요청 |
| --- | --- |
| `BOLA-001` | 2 |
| `INPUT-001` | 2 |
| `DATA-001` | 1 |

`AUTHN-001`, Transaction, 알 수 없는 Module ID는 계획 전체 거부 사유다.

## 12. 공통 요청 정책

모든 직접 HTTP 요청과 리다이렉트는 전송 직전에 다음을 확인한다.

- Target Profile과 동일한 scheme, host, port
- 정규화된 경로가 `allowed_paths`에 포함
- 로그인 외에는 `allowed_methods`에 포함
- 승인된 Module
- 전체 요청 상한 미초과
- 초당 요청 수 준수
- 상태 변경 정책 준수
- Job 취소 상태가 아님

리다이렉트는 자동 추적하지 않는다. Location을 해석한 뒤 전체 정책을 다시
통과한 경우에만 제한된 횟수로 따른다.

## 13. 모듈 판정

### BOLA-001

- 기준 요청: A 세션과 A 소유 객체 ID
- 변형 요청: A 세션과 B 소유 객체 ID
- verified: 변형 응답에서 B 객체의 런타임 식별 정보 또는 B 전용 필드가 확인됨
- not_found: 거부 응답 또는 B 객체임을 확인할 수 없는 응답
- inconclusive: 기준 요청 실패, 객체·Binding 부족, 비 JSON 비교 불가
- Rule: `VERIFY-BOLA-001`
- Condition: `BOLA_FOREIGN_OBJECT_RETURNED`
- vulnerability type: `BOLA`

단순 2xx만으로 확정하지 않는다.

### INPUT-001

GET path/query 입력만 검사한다.

- 기준값: OpenAPI example/default 또는 Katana에서 관찰한 실제 입력 예시
- 숫자 변형: 타입에 맞는 `-1`, `0` 또는 경계 초과값 중 하나
- 문자열 변형: 형식 규칙을 위반하는 결정적 문자열 하나
- 기준 요청 1회와 변형 요청 1회
- verified: 잘못된 입력 수용과 함께 기준 응답에 없던 타 사용자 객체 또는 민감
  필드가 추가되는 범위 확장 영향이 확인됨
- not_found: 입력 거부 또는 보안 영향이 없는 수용
- inconclusive: 유효 기준값, Binding 또는 영향 비교 근거 부족
- Rule: `VERIFY-INPUT-001`
- Condition: `INPUT_INVALID_VALUE_EXPANDED_SCOPE`
- vulnerability type: `INPUT_VALIDATION`

단순 2xx, 4xx, 5xx 또는 오류 메시지만으로 확정하지 않는다.

### DATA-001

인증된 성공 응답을 검사한다.

고정 금지 범주는 다음과 같다.

- 평문 비밀번호와 비밀번호 해시
- 인증 토큰, API Key와 Secret
- PIN과 CVV
- 주민식별번호
- 마스킹되지 않은 전체 카드번호와 계좌번호

필드명과 값 형식을 함께 확인하여 일반 ID를 오탐하지 않는다.

- Rule: `VERIFY-DATA-001`
- Condition: `DATA_SENSITIVE_FIELD_UNMASKED`
- vulnerability type: `DATA_EXPOSURE`

## 14. Finding과 Evidence

모듈 내부 결과는 `verified`, `not_found`, `inconclusive`다.

- `verified`: Evidence 등록 성공 후 Finding 생성
- `not_found`: 감사 이벤트만 보고
- `inconclusive`: 고정 사유 코드와 함께 감사 이벤트만 보고

Finding ID는 scan, operation, rule, 조건과 영향 필드로 결정적으로 생성한다.

Evidence는 등록 전에 다음을 마스킹한다.

- Authorization와 Cookie
- 사용자명·비밀번호
- 토큰과 세션
- actor 객체 ID
- 원시 민감 응답값

백엔드가 반환한 불투명 Artifact 참조만 `evidence_refs`에 저장한다. Evidence
등록이 실패하면 증거 없는 Finding을 만들지 않고 해당 검사를 inconclusive로
처리한다.

## 15. Job 진행·취소·오류

Scanner Stage는 Profile 로드, 인증, Discovery, 정규화, 객체 수집, 계획 검증,
실행, 판정과 결과 등록을 구분한다.

모든 Stage 진입과 HTTP 요청 직전에 취소 상태를 확인한다. 취소 후에는 새 요청을
보내지 않고 Katana를 종료한 뒤 실제 종료 상태를 보고한다.

| 오류 | 처리 |
| --- | --- |
| 계약·버전·scan ID 오류 | 재시도 불가 |
| 참조·정책·승인 오류 | 계획 거부, 재시도 불가 |
| 일시적 네트워크·대상 timeout | 재시도 가능으로 보고 |
| OpenAPI 성공·Katana 실패 | 경고 후 계속 |
| 모든 Discovery 소스 실패 | Job 실패 |
| Evidence 등록 실패 | 해당 검사 inconclusive |
| Graph·Result Artifact 등록 실패 | Job 실패 |
| 취소 | 새 요청 중단, canceled 보고 |

스캐너는 Job 전체를 자동 재실행하지 않는다. `retryable` 정보만 보고하고 실제
재시도 스케줄링은 백엔드가 담당한다.

오류에는 고정 코드, Stage와 `retryable`만 포함한다. 비밀값, 응답 원문과
Katana argv/stderr를 넣지 않는다.

## 16. 테스트 전략

모든 테스트는 로컬 Mock과 Fake를 사용하며 외부 대상에 요청하지 않는다.

### 계약

- 정확한 v1.1/v1.2 수용
- extra field 거부
- Scan ID 불일치
- Graph와 Result에 금지 필드가 없음

### 정책과 승인

- origin·경로·메서드·리다이렉트 거부
- RPS와 전체 요청 상한
- 모듈 매핑과 미승인 모듈
- Candidate·Operation·Binding 참조
- 요청 수·예상치·within_budget 불일치
- 거부 계획의 네트워크 호출 0회
- 빈 계획 승인과 빈 결과

### 세션과 Discovery

- A/B 자격증명·토큰·객체 분리
- OpenAPI 우선 및 Katana 병합
- A/B 인증 Header 파일
- Katana scope·속도·예산·취소
- 실제 값이 Graph에 포함되지 않음

### 모듈

- 세 모듈의 verified/not_found/inconclusive 경계
- 2xx만으로 BOLA·Input Finding이 생성되지 않음
- `AUTHN-001`·Transaction 요청 0회
- Data Exposure 마스킹·형식 오탐 방지

### 통합

- Fake BackendClient를 이용한 Discovery Job
- APPROVED Execution Job
- REJECTED Execution Job
- 실행 중 취소 후 추가 요청 0회
- 안전 대상 Finding 0건
- 취약 대상에서 해당 Rule Finding만 생성
- JSON·로그·오류·Evidence 비밀값 누출 0건
- 변경 경로가 scanner, tests, package metadata와 설계·계획 문서에만 한정

## 17. 완료 조건

- Notion 고정 JSON 구조와 버전을 변경하지 않는다.
- Executor가 계획 승인·거부의 최종 주체다.
- 승인된 세 모듈만 능동 실행한다.
- Executor가 실행 직후 고정 룰로 판정한다.
- verified Finding만 Scan Result에 포함한다.
- Severity를 생성하지 않는다.
- Runtime 비밀값을 외부 JSON·로그·오류·Artifact에 남기지 않는다.
- 백엔드·LLM·프론트엔드·DB·보고서 기능을 구현하지 않는다.
- 전체 테스트와 Scope 감사가 통과한다.

## Sources

- [명세서 모음](https://app.notion.com/p/3a9c9b03596c807ebb52c1ae6be28e91)
- [스캐너](https://app.notion.com/p/3a9c9b03596c80b4a6aaf48da8feeed3)
- [JSON 계약](https://app.notion.com/p/3a9c9b03596c807db6d7e4bae1416efe)
- [백엔드](https://app.notion.com/p/3a9c9b03596c80329576f2ba4301e31c)
- [LLM 모듈](https://app.notion.com/p/3aac9b03596c80ecbd75c4e7e5a02b37)
- [전체 흐름](https://app.notion.com/p/3aac9b03596c809c8f9dc224c5d7fc78)
- [프론트엔드](https://app.notion.com/p/3a9c9b03596c8065aac7ce2da3d2427b)
- [ProjectDiscovery Katana 공식 실행 문서](https://docs.projectdiscovery.io/opensource/katana/running)
