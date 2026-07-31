# API Vulnerability Scanner 1차 MVP 프론트엔드 UI 설계

## 1. 설계 기준

- 데이터 구조의 정본은 `docs` 브랜치의 `최종 JSON 데이터 계약.md`다.
- 확정되지 않은 백엔드 API 요청·응답과 실제 스캔 동작은 프론트에서 추측하지 않는다.
- 첫 구현은 확정 JSON 타입과 mock 서비스로 전체 사용자 흐름을 완성한다.
- 실제 API 연동 시 화면 컴포넌트를 수정하지 않고 서비스 구현만 교체할 수 있도록 분리한다.

## 2. 기술 스택

- React
- TypeScript
- Vite
- Tailwind CSS
- React Router
- TanStack Query

React Router는 화면 이동을 담당하고 TanStack Query는 mock 서비스 호출의 로딩, 성공, 실패 상태를 관리한다. 실제 API가 확정되면 동일한 Query 인터페이스에 실제 서비스 구현을 연결한다.

## 3. 시각 방향

전체 UI는 세 운영 도구의 장점을 조합한다.

- Vercel: 중립적인 색상, 넓은 여백, 간결한 현재 경로 표시
- Cloudflare: 스캔 상태, 수치 카드, 원형 차트, 운영 현황 요약
- Sentry: Finding 목록, 유형 표시, 상세 Evidence 탐색 구조

메인 색상은 중립적인 흰색·회색 계열을 사용하고 강조색은 보라색으로 통일한다. 취약점 유형은 동일한 색상 체계로 일관되게 표시한다. 색상만으로 상태를 전달하지 않고 텍스트와 아이콘을 함께 사용한다.

## 4. 공통 레이아웃

왼쪽 사이드바를 모든 주요 화면에서 유지한다.

- 제품명
- 현재 Workspace와 Scan
- Overview
- APIs
- Findings
- AI Report
- 요청 예산 요약

콘텐츠 상단 헤더에는 현재 화면 경로와 `New scan` 버튼만 표시한다.

데스크톱에서는 사이드바의 아이콘과 메뉴명을 모두 표시한다. 좁은 화면에서는 사이드바를 아이콘 중심으로 축소하고 핵심 콘텐츠를 한 열로 배치한다.

## 5. 화면 구조

### 5.1 스캔 설정

사용자가 다음 정보를 입력한다.

- 검사 URL
- User A 아이디와 비밀번호
- User B 아이디와 비밀번호

자격증명은 React 컴포넌트 메모리에만 유지한다. mock 데이터, URL, 로그, 브라우저 저장소에는 넣지 않는다. mock 스캔 생성이 완료되거나 화면을 벗어나면 입력값을 제거한다.

실제 스캔 API 계약은 확정되지 않았으므로 첫 구현에서는 mock 서비스가 `scan_id`를 반환하고 진행 화면으로 이동한다.

### 5.2 메인 대시보드

메인 대시보드는 상세 데이터를 나열하지 않고 전체 상태와 상세 화면 진입점을 제공한다.

상단 지표:

- 스캔 진행률
- 발견 API 수
- 확정 Finding 수
- AI Report 상태

요약 영역:

- API Discovery 원형 차트
  - 전체 API 수
  - HTTP Method별 API 수
- Scan Pipeline
  - 인증
  - API 탐색
  - 관계 분석
  - 모듈 검증
  - AI Report
- Finding Breakdown 원형 차트
  - 취약점 유형별 확정 Finding 수
- 최근 Finding 세 건
- AI Report 준비 상태

각 지표 카드, 차트 영역, 패널, Finding 행은 해당 상세 화면으로 이동한다. 스캔 진행률 카드와 Scan Pipeline은 스캔 진행 상세로, API 요약은 API 목록으로, Finding 요약은 Finding 목록으로, AI Report 요약은 AI Report 상세로 연결한다. 빈 클릭 핸들러나 `href="#"`는 두지 않는다. 메인 화면에는 원시 Evidence나 긴 AI 분석을 표시하지 않는다.

### 5.3 스캔 진행 상세

메인 대시보드의 스캔 진행률 카드와 Scan Pipeline 영역에서 진입한다.

다음 다섯 단계를 순서대로 표시한다.

- 인증
- API 탐색
- 관계 분석
- 모듈 검증
- AI Report

각 단계는 이름, 설명, 텍스트 상태를 제공한다. 전체 진행률과 현재 단계를 상단에 표시하며, 색상만으로 상태를 전달하지 않는다. 이 상태 구조는 실제 백엔드 계약이 아니라 첫 구현의 mock 화면 모델이다.

### 5.4 API 목록과 상세

목록 화면은 Method, Path, 입력·출력 구조를 요약하고 검색을 제공한다.

상세 화면은 `normalized_api_graph.json.operations[]`의 다음 정보만 사용한다.

- `operation_id`
- `method`
- `path_template`
- `inputs`
- `outputs`

확정 JSON에 없는 인증 정보나 실제 요청·응답은 표시하지 않는다.

### 5.5 Finding 목록과 상세

목록 화면은 다음 기능을 제공한다.

- 전체 Finding 수
- `vulnerability_type`별 원형 차트
- 유형 필터
- 검색
- Finding 행을 통한 상세 이동

상세 화면은 `scan_result.json.findings[]`의 다음 정보만 사용한다.

- `finding_id`
- `operation_id`
- `vulnerability_type`
- `verification`
- `affected_fields`
- `evidence_refs`

`evidence_refs`가 가리키는 실제 artifact 조회 API는 확정되지 않았으므로 첫 구현에서는 마스킹된 mock Evidence를 별도 서비스로 제공한다.

### 5.6 AI Report

`ai_report.json`을 기반으로 다음 내용을 표시한다.

- 전체 위험 요약
- Finding별 원인
- 공격 흐름
- 영향
- 개선 권고
- Evidence 참조

보고서 미리보기와 다운로드는 mock 서비스로 제공한다. 실제 HTML/PDF API가 확정되면 서비스 구현을 교체한다.

## 6. 데이터 구조

프론트 데이터 계층은 세 부분으로 분리한다.

1. 계약 타입
   - 확정된 6개 JSON 구조를 TypeScript 타입으로 정의한다.
2. 서비스 인터페이스
   - 스캔, API 탐색, Finding, AI Report 조회 동작을 정의한다.
3. mock 서비스
   - 계약 타입을 만족하는 안전한 예제 데이터를 반환한다.

UI 컴포넌트는 mock 데이터 파일을 직접 import하지 않고 TanStack Query를 통해 서비스 인터페이스만 사용한다.

## 7. 상태 처리

모든 주요 화면은 다음 상태를 갖는다.

- Loading: Skeleton 또는 진행 표시
- Empty: 데이터가 없다는 의미와 다음 행동 안내
- Error: 재시도 가능한 오류 메시지
- Success: 요약 또는 상세 데이터 표시

`scan_result.json.findings`가 비어 있으면 “확정된 Finding이 없습니다”라고 표시한다. 전체 API가 안전하다고 단정하지 않는다.

## 8. 보안 처리

- 실제 계정값, 비밀번호, 토큰, 객체 ID를 mock 데이터에 포함하지 않는다.
- 비밀번호 입력값을 로그로 출력하지 않는다.
- 비밀번호 입력 필드는 브라우저 저장 기능을 사용하지 않는다.
- Evidence와 식별자는 마스킹된 예제만 사용한다.
- AI Report가 Finding의 판정 결과를 변경하는 UI를 제공하지 않는다.

## 9. 검증

- TypeScript 타입 검사
- ESLint
- 프로덕션 빌드
- 주요 서비스 및 필터 동작 테스트
- 주요 화면의 Loading, Empty, Error, Success 상태 테스트
- 자격증명이 브라우저 저장소나 mock 데이터에 남지 않는지 확인
- 데스크톱과 좁은 화면 레이아웃 확인

## 10. 첫 구현에서 제외하는 범위

- 실제 백엔드 로그인 및 스캔 실행
- 실제 상태 polling
- 실제 Evidence artifact 조회
- 실제 HTML/PDF 보고서 생성과 다운로드
- 확정되지 않은 API 오류 코드별 처리
- PM 문서와 API 명세 변경
