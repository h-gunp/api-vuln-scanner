# Deterministic BOLA Relationship Recovery Design

## Goal

LLM 관계 분석이 식별자 흐름을 누락하더라도 실제 정규화 API 그래프에 근거해
감사 가능한 `id_flow` 관계와 `BOLA-001` 후보를 생성하고, Scanner가 해당 후보를
사용자별 실제 객체 식별자로 실행할 수 있게 한다.

## Scope

- 수정 대상은 LLM 관계 분석 후처리와 Scanner의 런타임 객체 식별자 수집 및
  기존 BOLA 고정 규칙의 식별자 경로 판정이다.
- 실행 가능한 모듈은 기존 `BOLA-001|INPUT-001|DATA-001`만 유지한다.
- `docs/최종 JSON 데이터 계약.md`와 외부 JSON 스키마는 변경하지 않는다.
- 상태 변경 요청, 새로운 취약점 모듈, 인증 우회, SQL Injection, XSS 검사는
  추가하지 않는다.
- HTTP 성공 상태만으로 finding을 만들지 않는다.

## Root Cause

현재 `LLMService._select_candidates()`는 LLM이 반환한 `id_flow|ownership`
관계만 BOLA 후보로 변환한다. 실제 VulnBank 스캔에서는 정규화된 GET operation
43개와 식별자 입력이 있었지만 관계가 0개여서 `BOLA-001` 후보도 0개였다.

LLM 후보 생성만 보완해도 Scanner의 `SessionManager`가 `account_id`,
`transaction_id`, `card_id`만 사용자별 객체로 수집하므로 `account_number`와
`cards[].id`, `payments[].id`는 BOLA 바인딩에 사용할 수 없다. 또한 기존 BOLA
검증기는 응답의 `account_number`를 선택된 account 식별자로 인정하지 않는다.
따라서 세 지점을 함께 맞춰야 실제 BOLA 실행이 가능하다.

## Design

### 1. Deterministic relationship recovery

`LLMService._build_relationship_analysis()`는 검증된 LLM 관계를 먼저 보존한 뒤,
정규화 그래프에서 안전하게 증명되는 식별자 흐름을 추가한다.

관계는 다음 조건을 모두 만족할 때만 추가한다.

1. target operation이 현재 target profile의 method/path 범위 안에 있다.
2. target input 위치가 `path|query`이고 식별자 이름으로 인식된다.
3. source output과 target input의 계약 type이 동일하다.
4. source output과 target input에서 계산한 객체 종류가 동일하다.
5. source/target operation, source field, target parameter와 location이 모두 실제
   그래프에 존재한다.
6. path 식별자를 소비하는 target operation은 자기 자신의 출력을 source로
   사용하지 않는다. 해당 출력은 식별자 없이 target을 호출하기 전에 얻을 수
   없기 때문이다.

지원하는 식별자 형태는 다음과 같다.

- 명시적 ID: `id`, `*_id`
- 계좌 식별자: `account_number`
- collection의 일반 ID: `cards[].id`, `payments[].id`처럼 부모 collection
  이름으로 객체 종류를 판별할 수 있는 출력

추론 관계는 `relationship_type="id_flow"`, `confidence=1.0`으로 기록한다.
이는 이름과 type이 일치하는 결정적 후처리 결과이며 실제 값이나 LLM 추측을
사용하지 않는다. 이미 동일한 관계가 있으면 추가하지 않고, 기존 LLM 관계의
순서를 유지한 뒤 추론 관계를 operation/field 기준으로 정렬하여 추가한다.
최종 `relationship_id`는 전체 순서에 맞춰 다시 부여한다.

관계가 없는 `merchant_id`, pagination 값 또는 type이 다른 필드는 후보로 만들지
않는다. `category_id`처럼 형식상 관계가 있지만 두 사용자에게 공통인 객체는
후보가 될 수 있으나, Scanner의 사용자별 소유 값 교차 검증에서 finding으로
확정되지 않는다.

### 2. Owner-scoped runtime identifier collection

`SessionManager.collect_response()`의 사용자별 저장 구조는 유지한다. 명시적
`account_number`는 object type `account`로 수집한다. 일반 `id` 필드는 부모
collection이 허용된 객체 collection일 때만 수집한다.

초기 허용 collection 매핑은 현재 승인된 BOLA 흐름에 필요한 다음 값으로
제한한다.

- `accounts -> account`
- `transactions -> transaction`
- `cards -> card`
- `payments -> payment`

`items[].id`, `data[].id`처럼 객체 종류가 불명확한 값은 수집하지 않는다.
수집된 실제 값은 기존 `_RuntimeSecret`에만 보관하며 artifact, 로그 또는 오류
메시지에 기록하지 않는다.

### 3. Fixed-rule BOLA verification

기존 BOLA 실행 순서와 판정 조건은 유지한다.

1. user A와 user B에 공통인 식별자를 제외한다.
2. user A 소유 객체로 baseline 요청을 보낸다.
3. 동일한 user A 세션으로 user B 전용 객체를 variant 요청에 바인딩한다.
4. variant가 `401|403|404`이면 `NOT_FOUND`로 처리한다.
5. variant가 성공하고 응답의 식별자 경로에 선택한 user B 값이 있을 때만
   `BOLA_FOREIGN_OBJECT_RETURNED`를 검증한다.

account object의 식별자 경로에는 기존 `account_id`와 부모 `account` 아래의
`id`뿐 아니라 `account_number`도 포함한다. `reference_number`, `phone_number`
등 다른 `*_number`는 추가하지 않는다.

`account_number`는 `SafeHttpClient`의 공개 응답 snapshot에서 항상 redacted된다.
따라서 값 비교는 직렬화되지 않는 `runtime_json_body`를 메모리 안에서만 사용하고,
evidence에는 기존 redacted `json_body`만 유지한다.

## Data Flow

1. LLM이 관계 초안을 반환한다.
2. LLM service가 초안 참조를 그래프에 대조한다.
3. 결정적 관계 복구기가 누락된 식별자 흐름을 추가한다.
4. 기존 candidate selector가 복구 관계를 `BOLA-001` 후보로 변환한다.
5. 기존 plan builder가 object binding owner를 `user_b`로 설정한다.
6. Scanner discovery가 actor별 list response에서 지원 식별자를 런타임에만
   수집한다.
7. BOLA module이 user B 전용 값을 선택해 user A 세션으로 검증한다.

## Error and Safety Behavior

- 그래프에 존재하지 않는 참조는 기존 `LLM_HALLUCINATED_REFERENCE` 처리와
  재시도를 유지한다.
- 결정적 관계를 만들 조건이 불충분하면 관계를 만들지 않는다.
- 사용자별 객체 값이 없거나 모두 공통이면 `BOLA_BINDING_UNAVAILABLE`로
  `INCONCLUSIVE` 처리한다.
- 응답에서 user B 객체를 식별할 수 없으면
  `BOLA_FOREIGN_OBJECT_NOT_IDENTIFIED`로 `NOT_FOUND` 처리한다.
- 원문 응답, 계정 번호, 객체 ID, 토큰은 artifact에 저장하지 않는다.

## Test Design

### LLM service

- 빈 LLM 관계와 VulnBank 형태의 그래프에서 `account_number`, `card_id`,
  `payment_id` 관계 및 BOLA 후보가 생성된다.
- 기존 LLM 관계와 동일한 결정적 관계가 중복되지 않는다.
- source output이 없거나 객체 종류/type이 다르면 BOLA 후보가 생성되지 않는다.
- 생성된 relationship analysis와 scan plan이 기존 Scanner 계약 모델을 통과한다.

### Session manager

- 두 actor의 `account_number`를 각각 `account` object로 수집한다.
- `cards[].id`, `payments[].id`를 부모 collection의 객체 종류로 수집한다.
- 불명확한 `items[].id`와 실제 값은 직렬화 가능한 출력에 노출하지 않는다.

### BOLA module

- user A 세션으로 user B의 `account_number`를 요청하고 응답의
  `account_number`가 일치하면 기존 고정 규칙으로 `VERIFIED` 판정한다.
- 공통 계좌 번호, 거부 응답, 다른 number 필드 또는 응답에 식별자가 없는
  경우 finding을 만들지 않는다.

### Verification

- 관련 LLM, session manager, BOLA 테스트
- 전체 `python -m pytest -q`
- `python -m compileall -q scanner llm tests`
- `git diff --check`

실제 VulnBank E2E는 자격 증명과 외부 네트워크가 준비된 사용자 환경에서 Docker
이미지를 재빌드한 뒤 수행한다. 완료 기준은 관계와 계획에 `BOLA-001`이 포함되고,
실행 결과가 `BOLA_BINDING_UNAVAILABLE` 없이 고정 규칙의 `VERIFIED|NOT_FOUND`
판정까지 도달하는 것이다. 취약점 finding 자체는 대상의 실제 응답이 검증 조건을
만족할 때만 요구한다.
