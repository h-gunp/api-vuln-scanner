from typing import Any

from .errors import LLMError
from .service import LLMService


def __getattr__(name: str) -> Any:
    if name in {"JobRegistry", "app", "create_app"}:
        from . import api

        return getattr(api, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["JobRegistry", "LLMError", "LLMService", "app", "create_app"]
