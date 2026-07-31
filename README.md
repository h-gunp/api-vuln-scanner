# vuln-bank LLM 모듈

고정 JSON 계약을 유지하면서 다음 세 산출물을 생성하는 Python 모듈임.

- `relationship_analysis.json`
- `scan_plan.json`
- `ai_report.json`

LLM 생성 로직과 백엔드가 호출하는 비동기 내부 Job API를 포함함. 백엔드의
DB·Artifact 저장과 Executor의 HTTP 실행·판정 기능은 포함하지 않음.

현재 MVP의 로그인 정보는 프론트엔드가 보내지 않음. 백엔드가
`target_profile.json`에 환경변수 이름만 기록하고, Scanner Worker가 런타임
환경에서 실제 값을 해석해 A/B 로그인을 수행함. 실제 자격증명·토큰은 LLM 입력과
JSON Artifact에 포함하지 않음.

## 설치

```bash
python -m venv .venv

# Windows PowerShell
.\.venv\Scripts\Activate.ps1

# macOS/Linux
source .venv/bin/activate

pip install -e .
```

`OPENAI_API_KEY` 환경변수를 설정해야 실제 모델 호출이 가능함. 기본 모델은 고정
계약 예시와 같은 `gpt-4o-mini-2024-07-18`임.

## 실행

```bash
export OPENAI_API_KEY="<openai-api-key>"
export BACKEND_BASE_URL="http://backend:8000"
export INTERNAL_AUTH_ENABLED="true"
export INTERNAL_SERVICE_TOKEN="<service-token>"

uvicorn llm.api:app --host 0.0.0.0 --port 8002
```

`BACKEND_BASE_URL`은 LLM 서비스 설정으로만 고정하며 Job 요청에서 callback URL을
받지 않음. 내부 인증을 켜면 모든 callback에
`Authorization: Bearer <INTERNAL_SERVICE_TOKEN>`을 보냄.

## 백엔드 Job API

| Endpoint | 입력 | 성공 callback |
| --- | --- | --- |
| `POST /jobs/relationship-analysis` | `job_id`, Target Profile, API Graph | `/internal/scans/{scan_id}/relationship-analysis` |
| `POST /jobs/scan-plan` | `job_id`, Target Profile, API Graph, 관계 분석, 현재 요청 사용량 | `/internal/scans/{scan_id}/scan-plan` |
| `POST /jobs/ai-report` | `job_id`, Scan Result | `/internal/scans/{scan_id}/ai-report` |

요청은 즉시 HTTP 202를 반환하고 Background Task에서 실행됨. 같은 `job_id`는
프로세스 수명 동안 한 번만 실행함. 생성 또는 성공 callback에 실패하면
`/internal/scans/{scan_id}/failed`에 LLM source, 백엔드 ScanStage와 고정
오류 코드·메시지만 전송함.

## 생성 서비스

```python
from llm import LLMService

service = LLMService()

relationship_analysis = service.analyze_relationships(
    target_profile,
    normalized_api_graph,
)

scan_plan = service.create_scan_plan(
    target_profile,
    normalized_api_graph,
    relationship_analysis,
    requests_already_used=12,
)

ai_report = service.create_ai_report(scan_result)

payload = ai_report.model_dump(mode="json")
```

`requests_already_used`는 JSON Artifact를 새로 만들지 않고 백엔드 Scanner Job
메타데이터에서 전달함. FastAPI Job wrapper는 위 생성 서비스를 그대로 호출함.

## 동작 원칙

- JSON 버전은 입력 `1.1`, 출력 `1.2` 계약을 그대로 사용함.
- 현재 승인 범주는 `BOLA-001`, `INPUT-001`, `DATA-001`로만 매핑함.
- `AUTHN-001`은 현재 `approved_modules`에 매핑이 없어 생성하지 않음.
- 관계와 실행 순서만 모델이 생성함. 후보, endpoint, binding owner, 예산,
  UUID, Evidence 참조와 전체 위험도는 코드가 확정함.
- `scan_result.findings[]`는 이미 확정된 Finding으로 취급함.
- `severity`는 `scan_result`가 아니라 보고서 단계에서 생성함.
- 원본 토큰·객체 ID·응답값은 모델 입력으로 받지 않음.
- 모든 외부 모델 출력은 Pydantic과 원본 참조 검증을 통과해야 함.

## 테스트

OpenAI API 호출 없이 계약·참조·재시도·예산·Evidence 연결을 검사함.

```bash
python -m unittest discover -s tests -v
```

Ponytail의 최소 구현 원칙에 따라 별도 에이전트 프레임워크, 데이터베이스 계층과
중복 재시도 라이브러리를 추가하지 않음. 얇은 FastAPI wrapper, 신뢰 경계 검증,
보안, 오류 처리와 실행 가능한 테스트만 유지함.
