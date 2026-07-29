# API Vulnerability Scanner 설계

- 작성일: 2026-07-25
- 대상 브랜치: `feature/scanner`
- 상태: 승인됨
- 기준 문서: `docs/스캐너 명세서.md` 및 `main`의 나머지 데이터 계약·연동 문서

## 1. 목표

`vuln-bank`의 API 구조를 수집·정규화하고 `user_a`, `user_b`의 독립 세션을
사용하여 BOLA, 인증 우회, 비정상 거래, 민감정보 노출을 고정 룰로 검사한다.

스캐너는 다음 두 산출물만 외부 JSON 계약으로 생산한다.

- `normalized_api_graph.json`
- `scan_result.json`

취약점의 확정은 LLM이 아니라 스캐너 Executor의 고정 룰이 수행한다.

## 2. 범위

### 포함

- Target Profile 검증과 환경변수 기반 A/B 자격증명 로드
- A/B 로그인과 런타임 세션 관리
- OpenAPI 우선, 인증 세션을 주입한 Katana 보완 수집
- API 입력·출력 구조 정규화
- 사용자별 객체 ID 런타임 수집
- LLM이 생성한 관계 분석과 검사 계획의 참조 검증
- 요청별 안전 정책 적용
- BOLA, Auth, Transaction, Data Exposure 모듈 실행
- 실행 직후 고정 룰 판정
- 민감정보가 마스킹된 내부 evidence artifact 저장
- verified finding만 포함하는 `scan_result.json` 생성
- 구조화된 감사 이벤트 제공

### 제외

- 백엔드 REST API와 작업 큐
- 데이터베이스와 백엔드 Artifact Storage
- LLM 호출, 프롬프트, 관계 분석, 계획 생성, AI 보고서
- 프론트엔드
- HTML·PDF 보고서
- 별도 `verifier.py`
- 외부 계약인 `execution_evidence.json`
- 새 스캐너 명세에 없는 Input Validation 모듈

## 3. 문서 우선순위와 호환성

문서 간 충돌에는 가장 최근의 구체적인 `docs/스캐너 명세서.md`를 우선한다.

- Target Profile의 `schema_version`은 기존 계약과의 연동을 위해 `1.1`, `1.2`를
  입력으로 허용한다.
- Target Profile의 승인 모듈은 `bola`, `auth`, `transaction`,
  `data_exposure`를 정본으로 사용한다.
- 기존 LLM 계획의 `BOLA-001`, `AUTHN-001`, `DATA-001`은 Executor 경계에서
  각각 `bola`, `auth`, `data_exposure`로 변환한다.
- 새 명세에 없는 `INPUT-001`은 실행하지 않고 실행 불가 감사 이벤트를 남긴다.
- Transaction은 `transaction`이 Profile과 계획에서 모두 승인되고 상태 변경
  정책과 HTTP 메서드가 허용될 때만 실행한다.
- `scan_result.json`은 `docs/최종 JSON 데이터 계약.md`의 1.2 구조를 따른다.

## 4. 구성

명세에 정의된 핵심 구조를 유지하고, 정책·계약·마스킹을 위한 내부 지원 파일만
추가한다.

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
│  ├─ auth.py
│  ├─ transaction.py
│  └─ data_exposure.py
├─ artifacts.py
├─ audit.py
├─ contracts.py
├─ http_client.py
├─ policy.py
├─ executor.py
└─ scanner.py
```

### 책임

- `session_manager.py`: 환경변수 자격증명 해석, A/B 로그인, 토큰·쿠키·객체 ID를
  포함하는 Runtime Context 관리
- `katana_runner.py`: A/B 세션별 Katana 실행, 출력 수집, 명령·오류 마스킹
- `normalizer.py`: OpenAPI와 Katana 결과를 중복 제거하고 구조 계약으로 변환
- `modules/*.py`: 기준·변형 요청을 선언하고 모듈별 고정 판정 수행
- `policy.py`: 대상 origin, 경로, 메서드, 모듈, 요청 예산, 속도, 상태 변경 검증
- `http_client.py`: 정책 검사 뒤 HTTP 요청 실행, 리다이렉트 재검증, 요청 수 집계
- `artifacts.py`: 마스킹한 evidence를 저장하고 불투명한 참조 생성
- `audit.py`: `not_found`, `inconclusive`, 경고, 실패 이벤트를 구조화하여 전달
- `contracts.py`: 외부 JSON과 내부 실행 객체의 엄격한 Pydantic 모델
- `executor.py`: 계획 검증, 모듈 실행, evidence 저장, 고정 룰 판정, 결과 조립
- `scanner.py`: Discovery와 Execution 전체 흐름 조정

### 공개 Python 인터페이스

스캐너는 서버 API나 작업 큐를 만들지 않고 다음 Python 인터페이스만 제공한다.

```python
discovery = scanner.discover(target_profile)

result = scanner.execute(
    target_profile=target_profile,
    normalized_api_graph=discovery.graph,
    relationship_analysis=relationship_analysis,
    scan_plan=scan_plan,
    requests_already_used=discovery.requests_used,
)
```

`DiscoveryResult`는 외부 JSON 계약이 아닌 내부 객체다. LLM에 전달 가능한
`graph`, `available_object_types`와 비민감 카운터 `requests_used`만 노출한다.
토큰, 쿠키, 자격증명, 객체 ID는 Scanner 인스턴스의 Runtime Context에만 남는다.

`Scanner`는 `ArtifactStore`와 `AuditSink` 인터페이스를 생성자에서 주입받는다.
기본 구현은 로컬 파일 artifact와 메모리 감사 이벤트이며, 백엔드 저장 구현은
스캐너 범위에 포함하지 않는다.

## 5. 처리 흐름

### 5.1 Discovery

1. Target Profile의 스키마와 안전 정책을 검증한다.
2. A/B 자격증명을 환경변수에서 읽고 로그인한다. 로그인 요청은
   `allowed_methods`의 능동 검사 제한에서만 예외이며 대상 origin 제한은 지킨다.
3. 알려진 OpenAPI 경로를 허용 범위 안에서 우선 조회한다.
4. A/B 인증 세션을 각각 주입하여 Katana를 실행하고 누락 후보를 수집한다.
5. 허용 범위에 포함된 operation만 병합하고 중복 제거한다.
6. OpenAPI 응답 스키마와 안전한 인증 GET 응답의 형태에서 입력·출력 필드 구조를
   추출한다. 원시 값은 그래프에 넣지 않는다.
7. 인증 GET 응답에서 계좌·거래·카드 등 객체 유형과 ID를 찾아 actor별 Runtime
   Object Context에만 저장한다.
8. 구조만 포함하는 `normalized_api_graph.json`을 반환한다.

정규화 그래프의 operation은 다음 필드만 가진다.

- `operation_id`
- `method`
- `path_template`
- `inputs`
- `outputs`

그래프에는 인증 방식, 수집 출처, edge, confidence, 민감도, 실제 요청·응답값,
토큰, 객체 ID를 넣지 않는다.

### 5.2 LLM 경계

스캐너는 LLM을 호출하지 않는다. 백엔드 또는 상위 오케스트레이터가 그래프와
사용 가능한 객체 유형만 LLM에 전달하고 `relationship_analysis.json`,
`scan_plan.json`을 스캐너로 돌려준다.

Scanner 인스턴스가 유지되면 Runtime Context와 요청 카운터를 계속 사용한다.
인스턴스가 유실된 경우 Execution은 `requests_already_used`를 시작 카운터로
적용한 뒤 다시 로그인하고 객체를 수집한다. Runtime Context가 없는데 유효한
요청 카운터도 전달되지 않으면 요청 상한을 새로 초기화하지 않고 실행을 거부한다.

### 5.3 Execution

1. 분석과 계획의 `scan_id`가 Profile 및 그래프와 일치하는지 확인한다.
2. plan의 operation, candidate, binding이 입력 문서에 실제로 존재하는지 확인한다.
3. 모듈 ID를 스캐너 정본 이름으로 변환하고 Profile 승인 목록과 대조한다.
4. 각 기준·변형·전후 확인 요청 직전에 전체 안전 정책을 다시 적용한다.
5. 요청을 실행하고 모듈의 고정 룰을 즉시 적용한다.
6. 요청·응답·상태 비교에서 민감값을 마스킹한 뒤 내부 artifact로 저장한다.
7. artifact 저장에 성공하고 룰이 `verified`를 반환한 결과만 finding으로 만든다.
8. verified finding만 포함하는 `scan_result.json`을 반환한다.

## 6. 안전 정책

모든 요청은 다음 검사를 통과해야 한다.

- Target Profile의 `base_url`과 동일한 scheme, host, port
- `allowed_paths`에 포함되는 정규화된 경로
- 로그인 외에는 `allowed_methods`에 포함되는 메서드
- `approved_modules`에 포함되는 모듈
- `max_requests` 미초과
- `requests_per_second` 제한 준수
- 상태 변경 요청은 `state_change_policy`가 명시적으로 허용

리다이렉트는 자동 추적하지 않는다. Location을 해석한 뒤 같은 정책을 다시
적용하고 통과한 경우에만 제한된 횟수로 따른다.

`scan_plan.json`은 제안이며 안전 정책을 확대하거나 우회할 수 없다.

## 7. 모듈 판정

### BOLA

- 기준: A 세션과 A 소유 객체 ID
- 변형: A 세션과 B 소유 객체 ID
- verified: 기준 요청이 성공하고 변형 응답이 B 객체의 런타임 식별 정보와
  일치하는 보호 데이터를 반환한 경우
- rule: `SCN-BOLA-001`
- condition: `BOLA_CROSS_OWNER_OBJECT_RETURNED`

### Auth

- 기준: 유효한 A 세션으로 보호 API 요청
- 변형: 인증 제거 요청, 무효 Bearer 토큰 요청
- verified: 기준 요청이 성공하고 변형 요청 중 하나가 동일 보호 데이터 구조를
  성공 응답으로 반환한 경우
- rule: `SCN-AUTH-001`
- conditions:
  - `AUTH_MISSING_TOKEN_ACCEPTED`
  - `AUTH_INVALID_TOKEN_ACCEPTED`

### Transaction

- 기준: 정상 입력 또는 상태 조회
- 변형: 음수, 0, 한도 초과 등 비정상 거래 입력
- 확인: 관련 계좌·거래 조회를 이용한 전후 상태 비교
- verified: 비정상 입력 뒤 실제 잔액 또는 거래 상태가 변경된 경우
- rule: `SCN-TRANSACTION-001`
- condition: `TRANSACTION_INVALID_INPUT_CHANGED_STATE`

관계 분석이나 계획에 전후 상태 확인에 필요한 binding이 없으면 요청을 추측하지
않고 `inconclusive`로 처리한다.

### Data Exposure

- 기준: 성공 응답 검사
- 변형 없음
- verified: 고정 금지 필드 또는 형식에 해당하는 값이 마스킹 없이 반환된 경우
- rule: `SCN-DATA-001`
- condition: `DATA_UNMASKED_SENSITIVE_VALUE_RETURNED`

초기 금지 범주는 비밀번호, 인증 토큰·비밀키, PIN, CVV, 주민식별정보,
마스킹되지 않은 전체 카드번호와 계좌번호다. 필드명과 값 형식을 함께 확인하여
일반적인 ID 필드를 민감정보로 오판하지 않는다.

## 8. 결과와 evidence

모듈 결과는 내부적으로 `verified`, `not_found`, `inconclusive` 중 하나다.

- `verified`: artifact 저장 후 `scan_result.json.findings[]`에 추가
- `not_found`: finding을 만들지 않고 감사 이벤트만 전달
- `inconclusive`: 사유 코드와 함께 감사 이벤트만 전달

finding은 다음을 포함한다.

- 결정적으로 생성한 `finding_id`
- 그래프와 정확히 일치하는 `operation_id`
- 고정 `vulnerability_type`
- `verification.rule_id`
- 충족한 고정 condition 코드
- 실제 영향이 확인된 `affected_fields`
- 마스킹된 artifact의 `evidence_refs`

evidence는 외부 JSON 계약이 아니다. 저장 전 Authorization, Cookie, 비밀번호,
토큰형 필드, 세션 값, 실제 객체 ID와 민감 응답값을 마스킹한다. 마스킹된 내용의
SHA-256을 사용하여 `evidence:sha256:<hash>` 참조를 만든다.

artifact 저장에 실패하면 증거 없는 finding을 생성하지 않는다.

## 9. 오류 처리

- 잘못된 Profile, A/B 인증 실패, 모든 Discovery 소스 실패: 스캔 실패
- OpenAPI 성공 후 Katana만 실패: 경고 후 계속
- 개별 요청 타임아웃·네트워크 오류: 해당 검사 `inconclusive`
- binding 또는 객체 부족: 해당 검사 `inconclusive`
- 정책 거부: 요청을 보내지 않고 `inconclusive`
- 요청 예산 소진: 남은 요청을 보내지 않고 실행 중단 이벤트 전달
- 예상하지 못한 artifact 오류: finding 생성 금지, 검사 `inconclusive`

예외, 감사 이벤트, Katana 명령 로그에는 공통 마스킹을 적용한다.

## 10. 검증 전략

### 단위 테스트

- JSON 계약의 필수 필드, enum, extra field 거부
- URL origin, 경로, 메서드, 모듈, 상태 변경 정책
- 요청 상한과 초당 제한
- 리다이렉트 재검증
- OpenAPI·Katana 병합과 operation 중복 제거
- 응답 구조 추론 시 실제 값 제거
- 자격증명·토큰·객체 ID 마스킹
- 네 모듈의 verified/not_found/inconclusive 경계
- 기존 LLM 모듈 ID 호환 변환

### 통합 테스트

`httpx.MockTransport` 기반의 로컬 전용 vuln-bank 대역과 가짜 Katana 실행기를
사용한다.

- 독립 A/B 로그인과 객체 분리
- 안전한 API에서는 finding이 생성되지 않음
- 취약한 API에서는 해당 고정 룰 finding만 생성됨
- 기본 `state_change_policy=deny`에서 Transaction 요청이 전송되지 않음
- 허용 정책에서 Transaction의 전후 상태 변경을 확인함
- 범위 밖 URL과 리다이렉트가 실제로 호출되지 않음
- 요청 예산 초과 요청이 실제로 호출되지 않음
- 외부 JSON 및 artifact에 원본 비밀번호·토큰·객체 ID가 없음

## 11. 완료 조건

- 승인된 네 스캐너 모듈과 Discovery/Execution 흐름이 동작한다.
- Executor가 실행과 고정 룰 판정을 함께 담당한다.
- `verifier.py`와 `execution_evidence.json`을 만들지 않는다.
- 스캐너의 모든 HTTP 요청이 공통 안전 정책을 통과한다.
- JSON 결과에 verified finding만 포함된다.
- 민감 Runtime 값이 외부 JSON, 로그, 예외, artifact에 남지 않는다.
- 테스트 전체가 통과한다.
- 백엔드, LLM, 프론트엔드, DB, 보고서 기능이 추가되지 않는다.
