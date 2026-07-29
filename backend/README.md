# API Vulnerability Scanner Backend

FastAPI 기반 보안 스캔 오케스트레이터다. 프론트엔드의 스캔 요청을 받고 Scanner와 LLM 사이의 작업 상태와 버전이 지정된 JSON 산출물을 검증·저장한다. Scanner가 discovery와 module execution/verification을 모두 소유한다.

## 데이터 흐름

```text
Frontend
  → Backend (target_profile.json)
  → Scanner (normalized_api_graph.json)
  → Backend → LLM (relationship_analysis.json, scan_plan.json)
  → Backend → Scanner Executor/Verifier (scan_result.json)
  → Backend → LLM (ai_report.json)
  → Backend → Frontend (상태, Finding, AI/PDF 보고서)
```

각 callback은 Pydantic 계약 검증, 경로 `scan_id` 일치, 선행 Operation/Finding 참조, 안전 정책을 확인한다. JSON은 UTF-8로 원자 저장하며 체크섬이 동일한 재전송은 멱등 처리한다. 다른 내용으로 이미 저장된 동일 유형의 원본을 덮어쓰지 않는다.

## 책임과 계층

```text
API Router → Service → Repository → PostgreSQL
                  ├→ Scanner / LLM Client
                  └→ Artifact Service → Local/Object Storage
```

`app/api`에는 HTTP 변환만, `app/services`에는 비즈니스 규칙, `app/repositories`에는 SQLAlchemy 접근만 둔다. 외부 HTTP 계약이 확정되지 않은 Client는 명시적으로 실패하며 개발 기본값은 Mock Client다.

## 주요 디렉터리

```text
app/
├── api/                 # 프론트엔드 API와 internal callback
├── core/                # 설정, DB, enum, 오류, 로깅
├── models/              # SQLAlchemy 비동기 모델
├── schemas/contracts/   # 버전별 JSON 계약
├── repositories/        # DB 접근
├── services/            # 오케스트레이션과 검증
├── integrations/        # Scanner/LLM 인터페이스와 실제 HTTP client
├── storage/             # 로컬/Object Storage 인터페이스
├── tasks/               # Background/ARQ 작업 경계
└── utils/
migrations/              # Alembic 초기 마이그레이션
tests/unit/              # DB 없는 단위 테스트
tests/integration/       # 별도 PostgreSQL 통합 테스트
artifacts/scans/         # 로컬 산출물
```

## 로컬 개발

Python 3.12와 PostgreSQL 16+, Redis 7+가 필요하다.

```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
python -m pip install -e ".[dev]"
copy .env.example .env
alembic upgrade head
uvicorn app.main:app --reload
```

PowerShell에서는 `Copy-Item .env.example .env`를 사용할 수 있다. 로컬 PostgreSQL 주소를 쓰는 경우 `.env`의 `DATABASE_URL` host를 `localhost`로 바꾼다.

Swagger는 `http://localhost:8000/docs`, OpenAPI JSON은 `http://localhost:8000/openapi.json`에서 확인한다.

## Docker

`.env`가 없어도 Compose 기본값으로 실행된다.

```bash
cd backend
docker compose up --build
```

Backend 시작 전에 `alembic upgrade head`가 실행된다. Compose는 `backend`, `scanner`, `llm`, `postgres`, `redis` 서비스를 포함하며 실제 HTTP 연동이 기본값이다. 공개 Backend 포트는 `8000`, Scanner는 `8001`, LLM은 `8002`다. Vite 개발 origin `http://127.0.0.1:4173`과 `http://localhost:4173`만 credential CORS allowlist에 포함된다.

## Alembic

```bash
alembic upgrade head
alembic downgrade -1
alembic revision --autogenerate -m "describe change"
```

## 테스트

DB 없는 테스트:

```bash
pytest tests/unit
```

통합 테스트는 SQLite가 아닌 별도 PostgreSQL을 사용한다.

```bash
docker compose -f docker-compose.test.yml up -d
set TEST_DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:55432/security_scanner_test
pytest
```

PowerShell에서는 `$env:TEST_DATABASE_URL='postgresql+asyncpg://postgres:postgres@localhost:55432/security_scanner_test'`를 사용한다. `TEST_DATABASE_URL`이 없으면 통합 테스트만 skip되며 `pytest` 자체는 성공한다.

## API

프론트엔드:

- `POST /api/scans`
- `GET /api/scans/{scan_id}`
- `GET /api/scans/{scan_id}/summary`
- `GET /api/scans/{scan_id}/endpoints`
- `GET /api/scans/{scan_id}/findings`
- `GET /api/findings/{finding_id}`
- `GET /api/scans/{scan_id}/ai-report`
- `GET /api/reports/{report_id}/download`

내부 callback:

- `POST /internal/scans/{scan_id}/progress`
- `POST /internal/scans/{scan_id}/normalized-api-graph`
- `POST /internal/scans/{scan_id}/relationship-analysis`
- `POST /internal/scans/{scan_id}/scan-plan`
- `POST /internal/scans/{scan_id}/execution-progress`
- `POST /internal/scans/{scan_id}/scan-result`
- `POST /internal/scans/{scan_id}/ai-report`
- `POST /internal/scans/{scan_id}/failed`

`TASK_MODE=background`는 프로세스 내부 작업으로 URL 헬스체크와 Scanner 제출을 시작한다. `TASK_MODE=arq`는 Redis에 `execute_scan`을 넣고, worker는 `arq app.tasks.worker.WorkerSettings`로 실행한다. Task 함수는 Service만 호출하므로 큐 구현을 교체해도 비즈니스 계층은 유지된다.

## Artifact

```text
artifacts/scans/{scan_id}/
├── input/target_profile.json
├── discovery/normalized_api_graph.json
├── planning/relationship_analysis.json
├── planning/scan_plan.json
├── results/scan_result.json
└── reports/
    ├── ai_report.json
    └── security-report-{scan_id}.pdf
```

## 보안 설정

기본값은 사설·loopback·link-local·reserved 주소를 차단한다. 로컬 취약 서버가 필요한 개발 환경에서만 `ALLOW_PRIVATE_TARGETS=true`를 사용한다. 인증정보는 Target Profile에 값이 아닌 환경변수 이름만 기록하며, 마스킹 서비스는 중첩 JSON/배열/Header의 토큰, 쿠키, 비밀번호, 개인식별 패턴을 처리한다.

## 현재 TBD

- Endpoint 검색/페이지네이션/정렬 및 `summary`/`description`
- 최종 Module ID와 취약점 유형/Target Profile category 매핑
- Finding의 `detected_at`
- AI 보고서의 Finding별 분석을 목록 `summary`로 매핑하는 최종 규칙
- Evidence 저장 단위, 참조, 상세 응답 및 별도 API
- 프론트엔드/Internal/PDF 다운로드 인증과 권한
- 운영용 secret manager와 서비스별 internal token 분리
- Finding이 0개일 때의 규칙 기반 `overall_risk` 의미
- Object Storage provider

관련 구현 지점에는 `TODO` 또는 `TBD`가 남아 있다.
