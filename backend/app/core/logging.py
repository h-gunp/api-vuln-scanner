import logging
from typing import Any

SENSITIVE_LOG_KEYS = {
    "authorization",
    "access_token",
    "refresh_token",
    "cookie",
    "session_id",
    "password",
    "api_key",
}


class SensitiveDataFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, dict):
            record.args = {
                key: "[MASKED]" if key.lower() in SENSITIVE_LOG_KEYS else value
                for key, value in record.args.items()
            }
        return True


def configure_logging(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler()
    handler.addFilter(SensitiveDataFilter())
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=[handler],
        force=True,
    )


def sanitized_extra(**values: Any) -> dict[str, Any]:
    return {
        key: "[MASKED]" if key.lower() in SENSITIVE_LOG_KEYS else value
        for key, value in values.items()
    }

