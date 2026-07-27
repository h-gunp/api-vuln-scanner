from fastapi import APIRouter

from app.api.endpoints import router as endpoints_router
from app.api.findings import router as findings_router
from app.api.internal.executor_callbacks import router as executor_callbacks_router
from app.api.internal.llm_callbacks import router as llm_callbacks_router
from app.api.internal.scanner_callbacks import router as scanner_callbacks_router
from app.api.reports import router as reports_router
from app.api.scans import router as scans_router

api_router = APIRouter()
api_router.include_router(scans_router)
api_router.include_router(endpoints_router)
api_router.include_router(findings_router)
api_router.include_router(reports_router)
api_router.include_router(scanner_callbacks_router)
api_router.include_router(llm_callbacks_router)
api_router.include_router(executor_callbacks_router)
