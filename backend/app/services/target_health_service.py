import asyncio
import socket
from dataclasses import dataclass
from time import perf_counter
from urllib.parse import urljoin, urlsplit

import httpx

from app.core.config import Settings
from app.core.error_codes import ErrorCode
from app.core.exceptions import AppError
from app.utils.url_utils import is_blocked_ip, normalized_http_url


@dataclass(frozen=True)
class TargetHealth:
    final_url: str
    status_code: int
    response_time_ms: int
    redirects: tuple[str, ...]


class TargetHealthService:
    MAX_REDIRECTS = 5

    def __init__(self, settings: Settings, client: httpx.AsyncClient | None = None) -> None:
        self.settings = settings
        self._client = client

    async def validate_destination(self, target_url: str) -> list[str]:
        try:
            normalized_http_url(target_url)
        except ValueError as exc:
            raise AppError(
                ErrorCode.INVALID_REQUEST,
                str(exc),
                status_code=422,
                field_errors=[{"field": "target_url", "reason": str(exc)}],
            ) from exc

        hostname = urlsplit(target_url).hostname
        assert hostname is not None
        if hostname.lower() == "localhost" and not self.settings.allow_private_targets:
            self._raise_blocked()

        try:
            addresses = await self._resolve(hostname)
        except OSError as exc:
            raise AppError(
                ErrorCode.TARGET_CONNECTION_FAILED,
                "대상 호스트의 DNS 주소를 확인할 수 없습니다.",
                status_code=422,
            ) from exc
        if not addresses:
            raise AppError(
                ErrorCode.TARGET_CONNECTION_FAILED,
                "대상 호스트의 DNS 주소를 확인할 수 없습니다.",
                status_code=422,
            )
        if not self.settings.allow_private_targets and any(is_blocked_ip(ip) for ip in addresses):
            self._raise_blocked()
        return addresses

    async def check(self, target_url: str) -> TargetHealth:
        current_url = target_url
        redirects: list[str] = []
        started = perf_counter()
        owns_client = self._client is None
        client = self._client or httpx.AsyncClient(
            timeout=self.settings.target_connect_timeout_seconds,
            follow_redirects=False,
        )
        try:
            for _ in range(self.MAX_REDIRECTS + 1):
                await self.validate_destination(current_url)
                response = await client.get(current_url)
                if response.is_redirect:
                    location = response.headers.get("location")
                    if not location:
                        break
                    if len(redirects) >= self.MAX_REDIRECTS:
                        raise AppError(
                            ErrorCode.TARGET_CONNECTION_FAILED,
                            "대상 서버의 리다이렉트 횟수가 제한을 초과했습니다.",
                            status_code=422,
                        )
                    current_url = urljoin(current_url, location)
                    redirects.append(current_url)
                    continue
                return TargetHealth(
                    final_url=str(response.url),
                    status_code=response.status_code,
                    response_time_ms=round((perf_counter() - started) * 1000),
                    redirects=tuple(redirects),
                )
            raise AppError(
                ErrorCode.TARGET_CONNECTION_FAILED,
                "대상 서버의 응답을 확인할 수 없습니다.",
                status_code=422,
            )
        except (httpx.HTTPError, asyncio.TimeoutError) as exc:
            raise AppError(
                ErrorCode.TARGET_CONNECTION_FAILED,
                "대상 서버에 연결할 수 없습니다.",
                status_code=422,
            ) from exc
        finally:
            if owns_client:
                await client.aclose()

    @staticmethod
    async def _resolve(hostname: str) -> list[str]:
        loop = asyncio.get_running_loop()
        records = await loop.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        return sorted({record[4][0] for record in records})

    @staticmethod
    def _raise_blocked() -> None:
        raise AppError(
            ErrorCode.SCAN_POLICY_VIOLATION,
            "보안 정책상 허용되지 않는 대상 주소입니다.",
            status_code=422,
        )

