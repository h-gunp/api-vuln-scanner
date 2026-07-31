from typing import Annotated

from fastapi import Depends


async def verify_frontend_request() -> None:
    # TODO: Frontend authentication and authorization contract pending.
    return None


FrontendAuth = Annotated[None, Depends(verify_frontend_request)]

