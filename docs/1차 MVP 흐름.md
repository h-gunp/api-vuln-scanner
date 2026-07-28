# 전체 흐름

# 전체 데이터 흐름

```
Frontend
   │
   │ 스캔 요청
   ▼
Backend
   │
   │ target_profile.json
   ▼
Scanner
   │
   ├─ User A/B 로그인 및 토큰 확보
   ├─ OpenAPI·Katana 기반 API 수집
   └─ normalized_api_graph.json 생성
   │
   ▼
Backend
   │
   │ normalized_api_graph.json
   ▼
LLM Module
   │
   ├─ relationship_analysis.json
   └─ scan_plan.json
   │
   ▼
Backend
   │
   ▼
Module Executor & Verifier
   │
   ├─ 공격 모듈 실행
   ├─ 응답 검증
   └─ scan_result.json 생성
   │
   ▼
Backend
   │
   │ scan_result.json
   ▼
LLM Module
   │
   └─ 최종 보안 보고서 생성
   │
   ▼
Backend
   │
   ▼
Frontend
   ├─ 스캔 진행 상황 표시
   ├─ 크롤링 정보 표시
   ├─ 취약점 결과 표시
   └─ 보고서 다운로드
```

## 1. 스캔 요청 및 설정 전달

1. 사용자가 프론트엔드에서 스캔을 요청한다.
2. 프론트엔드는 스캔 요청 정보를 백엔드로 전달한다.
3. 백엔드는 스캔 대상과 설정이 포함된 `target_profile.json`을 생성하고 스캐너에 전달한다.

**흐름**

```
Frontend → Backend → Scanner
```

## 2. 인증 정보 확보

1. 스캐너는 `target_profile.json`에 정의된 사용자 A와 사용자 B 계정으로 각각 로그인한다.
2. 로그인 결과로 발급된 토큰 또는 세션 정보를 확보한다.

```
Scanner
├─ User A 로그인 → Token/Session A 확보
└─ User B 로그인 → Token/Session B 확보
```

## 3. API 수집 및 정규화

1. 스캐너는 OpenAPI 명세와 Katana 크롤링 결과를 이용해 API 정보를 수집한다.
2. 수집한 API 정보를 공통 구조로 정규화하여 `normalized_api_graph.json`을 생성한다.
3. 스캐너는 생성된 `normalized_api_graph.json`을 백엔드로 전송하고, 백엔드는 이를 저장한다.

```
OpenAPI + Katana
        ↓
API 정보 수집
        ↓
정규화
        ↓
normalized_api_graph.json
        ↓
Backend 저장
```

## 4. LLM 기반 관계 분석 및 스캔 계획 생성

1. 백엔드는 저장된 `normalized_api_graph.json`을 LLM 모듈에 전달한다.
2. LLM 모듈은 API 간 관계와 공격 가능성을 분석하여 다음 파일을 생성한다.
- `relationship_analysis.json`: API 간 데이터 및 권한 관계 분석 결과
- `scan_plan.json`: 실행할 취약점 검사 모듈과 검사 순서
1. LLM 모듈은 두 JSON 파일을 백엔드로 전달하고, 백엔드는 이를 저장한다.

```
normalized_api_graph.json
        ↓
LLM 분석
        ↓
relationship_analysis.json
scan_plan.json
        ↓
Backend 저장
```

## 5. 공격 모듈 실행 및 결과 검증

1. 백엔드는 `relationship_analysis.json`과 `scan_plan.json`을 모듈 실행기 및 검증기에 전달한다.
2. 모듈 실행기는 스캔 계획에 따라 BOLA, 권한 검증, 데이터 노출 등의 공격 모듈을 실행한다.
3. 검증기는 공격 요청과 응답을 규칙 기반으로 검증하여 실제 취약점 여부를 판정한다.
4. 실행 및 검증 결과를 통합하여 `scan_result.json`을 생성한다.
5. 생성된 `scan_result.json`을 백엔드로 전달하고 저장한다.

```
relationship_analysis.json + scan_plan.json
                    ↓
             공격 모듈 실행
                    ↓
               결과 검증
                    ↓
             scan_result.json
                    ↓
              Backend 저장
```

## 6. AI 보고서 생성

1. 백엔드는 `scan_result.json`을 LLM 모듈에 전달한다.
2. LLM 모듈은 확정된 취약점과 증거를 바탕으로 최종 보안 보고서를 생성한다.
3. 생성된 보고서는 백엔드에 저장된다.

```
scan_result.json
        ↓
LLM 보고서 생성
        ↓
최종 보안 보고서
        ↓
Backend 저장
```

## 7. 프론트엔드 결과 제공

1. 프론트엔드는 백엔드에서 다음 정보를 조회해 사용자에게 제공한다.
- 스캔 진행 상태
- API 크롤링 및 수집 현황
- 발견된 취약점 목록
- 취약점별 판정 결과
- 최종 AI 보안 보고서
- 보고서 다운로드 기능