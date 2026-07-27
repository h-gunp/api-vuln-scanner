from arq.connections import RedisSettings

from app.core.config import get_settings
from app.tasks.report_tasks import generate_report_task
from app.tasks.scan_tasks import run_scan_task


async def execute_scan(_: dict, scan_id: str) -> None:
    await run_scan_task(scan_id)


async def execute_report(_: dict, scan_id: str) -> None:
    await generate_report_task(scan_id)


class WorkerSettings:
    functions = [execute_scan, execute_report]
    redis_settings = RedisSettings.from_dsn(get_settings().redis_url)
    max_tries = 3
    job_timeout = 300
