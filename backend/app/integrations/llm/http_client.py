from app.core.error_codes import ErrorCode
from app.core.exceptions import AppError
from app.integrations.common import ExternalSubmission
from app.integrations.llm.base import LLMClient
from app.schemas.contracts.normalized_api_graph import NormalizedAPIGraph
from app.schemas.contracts.relationship_analysis import RelationshipAnalysis


class HTTPLLMClient(LLMClient):
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url

    async def request_relationship_analysis(
        self,
        graph: NormalizedAPIGraph,
    ) -> ExternalSubmission:
        return self._not_configured()

    async def request_scan_plan(
        self,
        analysis: RelationshipAnalysis,
    ) -> ExternalSubmission:
        return self._not_configured()

    async def request_report(self, scan_id: str) -> ExternalSubmission:
        return self._not_configured()

    @staticmethod
    def _not_configured() -> ExternalSubmission:
        # TODO: LLM HTTP endpoints, payload envelopes, and authentication contract pending.
        raise AppError(
            ErrorCode.LLM_REQUEST_FAILED,
            "LLM HTTP 연동 계약이 아직 설정되지 않았습니다.",
            status_code=502,
        )

