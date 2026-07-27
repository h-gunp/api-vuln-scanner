import hmac
from typing import Annotated

from fastapi import Depends, Header

from app.core.config import Settings, get_settings
from app.core.error_codes import ErrorCode
from app.core.exceptions import AppError


async def verify_internal_service(
    settings: Annotated[Settings, Depends(get_settings)],
    authorization: Annotated[str | None, Header()] = None,
) -> None:
    # TODO: Frontend and internal service authentication contract pending.
    if not settings.internal_auth_enabled:
        return
    expected = settings.internal_service_token
    supplied = authorization.removeprefix("Bearer ").strip() if authorization else ""
    if not expected or not hmac.compare_digest(supplied, expected):
        raise AppError(
            ErrorCode.ACCESS_DENIED,
            "내부 서비스 접근 권한이 없습니다.",
            status_code=403,
        )


InternalAuth = Annotated[None, Depends(verify_internal_service)]

